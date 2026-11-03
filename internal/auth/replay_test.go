package auth

import (
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"
)

// TestReplayGuardDefaults checks that non-positive max/ttl fall back to the
// package defaults.
func TestReplayGuardDefaults(t *testing.T) {
	g := NewReplayGuard(0, 0)
	defer g.Close()
	if g.max != DefaultReplayMaxEntries {
		t.Errorf("max = %d, want default %d", g.max, DefaultReplayMaxEntries)
	}
	if g.ttl != DefaultReplayTTL {
		t.Errorf("ttl = %v, want default %v", g.ttl, DefaultReplayTTL)
	}
	if err := g.Check("nonce-a", time.Now()); err != nil {
		t.Fatalf("guard with defaults should accept a fresh nonce: %v", err)
	}
}

func TestReplayFirstThenDuplicate(t *testing.T) {
	g := NewReplayGuard(100, time.Minute)
	defer g.Close()

	now := time.Now()
	if err := g.Check("nonce-a", now); err != nil {
		t.Fatalf("first use of a nonce should be accepted: %v", err)
	}
	if err := g.Check("nonce-a", now); !errors.Is(err, ErrReplay) {
		t.Fatalf("replay of the same nonce: err = %v, want ErrReplay", err)
	}
}

func TestReplayDifferentNonce(t *testing.T) {
	g := NewReplayGuard(100, time.Minute)
	defer g.Close()

	now := time.Now()
	if g.Check("nonce-a", now) != nil || g.Check("nonce-b", now) != nil {
		t.Fatal("distinct nonces should both be accepted")
	}
}

// TestReplayFullRejectsInsteadOfEvicting checks that a guard at capacity with
// live nonces refuses new ones rather than forgetting an old one; forgetting
// would re-open that nonce for replay.
func TestReplayFullRejectsInsteadOfEvicting(t *testing.T) {
	g := NewReplayGuard(4, time.Minute)
	defer g.Close()

	now := time.Now()
	for i := 0; i < 4; i++ {
		if err := g.Check(fmt.Sprintf("n%d", i), now); err != nil {
			t.Fatalf("nonce %d should be accepted on first use: %v", i, err)
		}
	}
	if err := g.Check("n4", now); !errors.Is(err, ErrGuardFull) {
		t.Fatalf("fifth nonce: err = %v, want ErrGuardFull", err)
	}
	if g.Len() != 4 {
		t.Fatalf("Len = %d, want 4", g.Len())
	}
	// The oldest nonce is still remembered, so replaying it is still caught.
	if err := g.Check("n0", now); !errors.Is(err, ErrReplay) {
		t.Fatalf("oldest nonce after capacity pressure: err = %v, want ErrReplay", err)
	}
}

// TestReplayFullReclaimsExpired checks that a full guard makes room by
// dropping expired entries (and only those).
func TestReplayFullReclaimsExpired(t *testing.T) {
	g := NewReplayGuard(3, time.Minute)
	defer g.Close()

	t0 := time.Now()
	_ = g.Check("old-1", t0)
	_ = g.Check("old-2", t0)
	_ = g.Check("live", t0.Add(50*time.Second))

	later := t0.Add(61 * time.Second) // old-* expired, live has 49s left
	if err := g.Check("new", later); err != nil {
		t.Fatalf("full guard with expired entries should accept: %v", err)
	}
	if g.Len() != 2 {
		t.Fatalf("Len = %d, want 2 (live + new)", g.Len())
	}
	if err := g.Check("live", later); !errors.Is(err, ErrReplay) {
		t.Fatalf("live nonce: err = %v, want ErrReplay", err)
	}
}

func TestReplayTTLExpiry(t *testing.T) {
	g := NewReplayGuard(100, time.Minute)
	defer g.Close()

	t0 := time.Now()
	if err := g.Check("nonce-a", t0); err != nil {
		t.Fatalf("first use should be accepted: %v", err)
	}
	if err := g.Check("nonce-a", t0.Add(time.Minute)); !errors.Is(err, ErrReplay) {
		t.Fatalf("at exactly the TTL the nonce is still remembered: err = %v", err)
	}
	if err := g.Check("nonce-a", t0.Add(time.Minute+time.Nanosecond)); err != nil {
		t.Fatalf("nonce should be reusable after its TTL expires: %v", err)
	}
}

// TestReplayReaperRemovesExpired checks the background reaper with a real
// clock and a short TTL.
func TestReplayReaperRemovesExpired(t *testing.T) {
	g := NewReplayGuard(100, 40*time.Millisecond)
	defer g.Close()
	_ = g.Check("nonce-a", time.Now())
	deadline := time.Now().Add(2 * time.Second)
	for g.Len() != 0 {
		if time.Now().After(deadline) {
			t.Fatalf("reaper did not remove expired entry (Len=%d)", g.Len())
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func TestReplayCloseIdempotent(t *testing.T) {
	g := NewReplayGuard(100, time.Minute)
	// Closing twice must not panic (the second close hits the non-blocking
	// default branch once stop is already closed).
	g.Close()
	g.Close()
}

func TestReplayConcurrent(t *testing.T) {
	g := NewReplayGuard(1000, time.Minute)
	defer g.Close()

	const workers = 50
	var wg sync.WaitGroup
	start := make(chan struct{})
	var wins int64
	var mu sync.Mutex

	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			if g.Check("same-nonce", time.Now()) == nil {
				mu.Lock()
				wins++
				mu.Unlock()
			}
		}()
	}
	close(start)
	wg.Wait()

	if wins != 1 {
		t.Fatalf("%d workers won the nonce race; exactly one should", wins)
	}
}
