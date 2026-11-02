package auth

import (
	"sync"
	"testing"
	"time"
)

func TestReplayFirstThenDuplicate(t *testing.T) {
	g := NewReplayGuard(100, time.Minute)
	defer g.Close()

	now := time.Now()
	if !g.Check("10.0.0.1:53", "nonce-a", now) {
		t.Fatal("first use of a nonce should be accepted")
	}
	if g.Check("10.0.0.1:53", "nonce-a", now) {
		t.Fatal("replay of the same (caller, nonce) should be rejected")
	}
}

func TestReplayDifferentCallerSameNonce(t *testing.T) {
	g := NewReplayGuard(100, time.Minute)
	defer g.Close()

	now := time.Now()
	if !g.Check("10.0.0.1:53", "shared", now) {
		t.Fatal("first caller should be accepted")
	}
	// A different caller reusing the same nonce is a distinct identity.
	if !g.Check("10.0.0.2:53", "shared", now) {
		t.Fatal("a different caller with the same nonce should be accepted")
	}
}

func TestReplayDifferentNonce(t *testing.T) {
	g := NewReplayGuard(100, time.Minute)
	defer g.Close()

	now := time.Now()
	if !g.Check("10.0.0.1:53", "nonce-a", now) || !g.Check("10.0.0.1:53", "nonce-b", now) {
		t.Fatal("distinct nonces should both be accepted")
	}
}

func TestReplayEviction(t *testing.T) {
	g := NewReplayGuard(4, time.Minute)
	defer g.Close()

	now := time.Now()
	// Fill past capacity with distinct nonces.
	for i := 0; i < 5; i++ {
		if !g.Check("10.0.0.1:53", "n"+string(rune('a'+i)), now) {
			t.Fatalf("nonce %d should be accepted on first use", i)
		}
	}
	if g.Len() != 4 {
		t.Fatalf("Len = %d, want 4 (oldest should have been evicted)", g.Len())
	}
	// The oldest nonce (a) was evicted, so re-using it is now accepted.
	if !g.Check("10.0.0.1:53", "na", now) {
		t.Fatal("evicted nonce should be reusable after capacity pressure")
	}
}

func TestReplayTTLExpiry(t *testing.T) {
	g := NewReplayGuard(100, 50*time.Millisecond)
	defer g.Close()

	if !g.Check("10.0.0.1:53", "nonce-a", time.Now()) {
		t.Fatal("first use should be accepted")
	}
	if g.Check("10.0.0.1:53", "nonce-a", time.Now()) {
		t.Fatal("nonce should still be fresh before TTL elapses")
	}

	time.Sleep(120 * time.Millisecond)
	if !g.Check("10.0.0.1:53", "nonce-a", time.Now()) {
		t.Fatal("nonce should be reusable after its TTL expires")
	}
}

func TestReplayConcurrent(t *testing.T) {
	g := NewReplayGuard(1000, time.Minute)
	defer g.Close()

	const workers = 50
	var syncWg sync.WaitGroup
	start := make(chan struct{})
	var wins int64
	var mu sync.Mutex

	for i := 0; i < workers; i++ {
		syncWg.Add(1)
		go func() {
			defer syncWg.Done()
			<-start
			if g.Check("10.0.0.1:53", "same-nonce", time.Now()) {
				mu.Lock()
				wins++
				mu.Unlock()
			}
		}()
	}
	close(start)
	syncWg.Wait()

	if wins != 1 {
		t.Fatalf("%d workers won the (caller, nonce) race; exactly one should", wins)
	}
}
