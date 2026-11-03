package mcp

import (
	"bytes"
	"context"
	"fmt"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Crank-Git/mcport53/internal/codec"
	"github.com/Crank-Git/mcport53/internal/dns"
)

// clockedStore returns a store with limits l whose clock the test controls.
func clockedStore(l ResultLimits) (*ResultStore, *time.Time) {
	s := NewResultStoreWithLimits(l)
	now := time.Unix(1_800_000_000, 0)
	s.now = func() time.Time { return now }
	return s, &now
}

func mustPut(t *testing.T, s *ResultStore, data []byte) string {
	t.Helper()
	id, err := s.Put(data)
	if err != nil {
		t.Fatalf("Put(%d bytes): %v", len(data), err)
	}
	return id
}

func TestStorePutGetSingle(t *testing.T) {
	s := NewResultStore()
	data := []byte("hello world")
	session := mustPut(t, s, data)
	got, total, more, ok := s.Get(session, 0)
	if !ok || total != 1 || more || !bytes.Equal(got, data) {
		t.Fatalf("Get = %q total=%d more=%v ok=%v", got, total, more, ok)
	}
	if s.Len() != 1 || s.Bytes() != len(data) {
		t.Errorf("Len=%d Bytes=%d, want 1/%d", s.Len(), s.Bytes(), len(data))
	}
}

func TestStorePutGetMulti(t *testing.T) {
	s := NewResultStore()
	data := bytes.Repeat([]byte("x"), 2*codec.ChunkSize+10) // 3 chunks
	session := mustPut(t, s, data)

	var assembled bytes.Buffer
	for i := 0; ; i++ {
		got, total, more, ok := s.Get(session, i)
		if !ok || total != 3 {
			t.Fatalf("Get(chunk %d) ok=%v total=%d", i, ok, total)
		}
		assembled.Write(got)
		if !more {
			break
		}
	}
	if !bytes.Equal(assembled.Bytes(), data) {
		t.Error("reassembled data does not match original")
	}
}

func TestStoreGetUnknown(t *testing.T) {
	s := NewResultStore()
	if _, _, _, ok := s.Get("missing", 0); ok {
		t.Error("Get(missing session) ok=true")
	}
	session := mustPut(t, s, []byte("data"))
	for _, idx := range []int{99, 1, -1} {
		if _, _, _, ok := s.Get(session, idx); ok {
			t.Errorf("Get(chunk %d) ok=true", idx)
		}
	}
}

func TestStoreDefaults(t *testing.T) {
	s := NewResultStore()
	if s.limits.TTL != DefaultResultTTL || s.limits.MaxSessions != DefaultResultMaxSessions || s.limits.MaxBytes != DefaultResultMaxBytes {
		t.Fatalf("limits = %+v", s.limits)
	}
}

// TestStoreTTLExpiry pins the TTL boundary: a session is served up to its
// expiry and gone after it, both on read and on the next Put.
func TestStoreTTLExpiry(t *testing.T) {
	s, now := clockedStore(ResultLimits{TTL: time.Minute})
	a := mustPut(t, s, []byte("a"))
	t0 := *now

	*now = t0.Add(time.Minute)
	if _, _, _, ok := s.Get(a, 0); !ok {
		t.Fatal("session should be served at exactly its TTL")
	}
	*now = t0.Add(time.Minute + time.Nanosecond)
	if _, _, _, ok := s.Get(a, 0); ok {
		t.Fatal("session served after its TTL")
	}
	if s.Len() != 0 || s.Bytes() != 0 {
		t.Fatalf("expired session not dropped on read: Len=%d Bytes=%d", s.Len(), s.Bytes())
	}

	// Expired sessions that are never read are dropped by the next Put.
	_ = mustPut(t, s, []byte("b"))
	*now = now.Add(2 * time.Minute)
	_ = mustPut(t, s, []byte("c"))
	if s.Len() != 1 {
		t.Fatalf("Len = %d, want 1 (only c live)", s.Len())
	}
}

// TestStoreMaxSessionsEvictsOldest checks the count bound and eviction order.
func TestStoreMaxSessionsEvictsOldest(t *testing.T) {
	s, _ := clockedStore(ResultLimits{MaxSessions: 3})
	var ids []string
	for i := 0; i < 5; i++ {
		ids = append(ids, mustPut(t, s, []byte{byte(i)}))
	}
	if s.Len() != 3 {
		t.Fatalf("Len = %d, want 3", s.Len())
	}
	for i, id := range ids {
		_, _, _, ok := s.Get(id, 0)
		if want := i >= 2; ok != want {
			t.Errorf("session %d present=%v, want %v", i, ok, want)
		}
	}
}

// TestStoreMaxBytesEvictsOldest checks the byte bound: older sessions are
// dropped until the new one fits, and the byte count stays exact.
func TestStoreMaxBytesEvictsOldest(t *testing.T) {
	s, _ := clockedStore(ResultLimits{MaxBytes: 1000})
	a := mustPut(t, s, make([]byte, 400))
	b := mustPut(t, s, make([]byte, 400))
	c := mustPut(t, s, make([]byte, 300)) // 1100 > 1000: a must go
	if _, _, _, ok := s.Get(a, 0); ok {
		t.Error("oldest session survived byte pressure")
	}
	for _, id := range []string{b, c} {
		if _, _, _, ok := s.Get(id, 0); !ok {
			t.Error("newer session evicted")
		}
	}
	if s.Bytes() != 700 {
		t.Errorf("Bytes = %d, want 700", s.Bytes())
	}
	if _, err := s.Put(make([]byte, 1001)); err != errResultTooLarge {
		t.Errorf("Put over the byte budget: err = %v, want errResultTooLarge", err)
	}
	if s.Bytes() != 700 {
		t.Errorf("a rejected Put changed Bytes to %d", s.Bytes())
	}
}

// TestStoreCursorNonceExpiresWithSession checks cursor nonces live and die with
// their session (the old server-level map grew forever).
func TestStoreCursorNonceExpiresWithSession(t *testing.T) {
	s, now := clockedStore(ResultLimits{TTL: time.Minute})
	id := mustPut(t, s, []byte("x"))
	gen := func() (string, error) { return "nonce1", nil }
	if ns, ok := s.cursorNonce(id, nil); ok || ns != "" {
		t.Fatal("cursor nonce exists before first use")
	}
	if ns, ok := s.cursorNonce(id, gen); !ok || ns != "nonce1" {
		t.Fatalf("create: %q %v", ns, ok)
	}
	if ns, _ := s.cursorNonce(id, func() (string, error) { return "other", nil }); ns != "nonce1" {
		t.Fatalf("nonce changed on second use: %q", ns)
	}
	*now = now.Add(2 * time.Minute)
	if _, ok := s.cursorNonce(id, gen); ok {
		t.Fatal("cursor nonce outlived its session")
	}
	if _, ok := s.cursorNonce("unknown", gen); ok {
		t.Fatal("cursor nonce for unknown session")
	}
	if _, ok := s.cursorNonce(mustPut(t, s, []byte("y")), func() (string, error) { return "", fmt.Errorf("rng") }); ok {
		t.Fatal("cursor nonce despite generator error")
	}
}

func TestStoreConcurrent(t *testing.T) {
	s := NewResultStoreWithLimits(ResultLimits{MaxSessions: 64})
	data := bytes.Repeat([]byte("z"), 350)
	var wg sync.WaitGroup
	for w := 0; w < 16; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < 200; i++ {
				id, err := s.Put(data)
				if err != nil {
					t.Error(err)
					return
				}
				// The session may already be evicted by other writers; when
				// present, every chunk must be intact.
				for c := 0; ; c++ {
					got, _, more, ok := s.Get(id, c)
					if !ok {
						break
					}
					if !bytes.Equal(got, data[c*codec.ChunkSize:c*codec.ChunkSize+len(got)]) {
						t.Error("corrupt chunk")
					}
					if !more {
						break
					}
				}
				_, _ = s.cursorNonce(id, func() (string, error) { return "n", nil })
			}
		}()
	}
	wg.Wait()
	if s.Len() > 64 || s.Bytes() != s.Len()*len(data) {
		t.Fatalf("Len=%d Bytes=%d after concurrent use", s.Len(), s.Bytes())
	}
}

// TestServerStoreStaysBounded is the scenario from the issue: many large calls
// used to leave one stored session each, forever.
func TestServerStoreStaysBounded(t *testing.T) {
	r := NewRegistry()
	_ = r.Register(&Tool{Name: "big", Call: func(ctx context.Context, a []byte) (*codec.Envelope, error) {
		return codec.OK("big", strings.Repeat("x", codec.MaxEnvelopeTXT+100), 0), nil
	}})
	store := NewResultStoreWithLimits(ResultLimits{MaxSessions: 128})
	h := NewServer(r).WithResultStore(store).Handlers()
	for i := 0; i < 10000; i++ {
		if e := h.OnCall(&dns.CallRequest{Tool: "big"}); e.Status != codec.StatusChunked {
			t.Fatalf("call %d: %+v", i, e)
		}
	}
	if store.Len() != 128 {
		t.Fatalf("sessions after 10000 calls = %d, want 128", store.Len())
	}

	// The default store is bounded the same way.
	srv := NewServer(r)
	h = srv.Handlers()
	for i := 0; i < DefaultResultMaxSessions+500; i++ {
		h.OnCall(&dns.CallRequest{Tool: "big"})
	}
	if srv.results.Len() != DefaultResultMaxSessions {
		t.Fatalf("default store Len = %d, want %d", srv.results.Len(), DefaultResultMaxSessions)
	}
}

// TestServerResultTooLargeIsError checks a result over the byte budget becomes
// an error envelope rather than being stored.
func TestServerResultTooLargeIsError(t *testing.T) {
	r := NewRegistry()
	_ = r.Register(&Tool{Name: "huge", Call: func(ctx context.Context, a []byte) (*codec.Envelope, error) {
		return codec.OK("huge", strings.Repeat("x", 5000), 0), nil
	}})
	h := NewServer(r).WithResultStore(NewResultStoreWithLimits(ResultLimits{MaxBytes: 1000})).Handlers()
	e := h.OnCall(&dns.CallRequest{Tool: "huge"})
	if e.Status != codec.StatusError || !strings.Contains(e.Error, "too large") {
		t.Fatalf("envelope = %+v, want too-large error", e)
	}
}

// TestChunkFetchAfterExpiryOverDNS drives the chunk protocol over a real
// socket: chunk 1 is served within the TTL and refused with a clean error once
// the session has expired.
func TestChunkFetchAfterExpiryOverDNS(t *testing.T) {
	r := NewRegistry()
	_ = r.Register(&Tool{Name: "big", Call: func(ctx context.Context, a []byte) (*codec.Envelope, error) {
		re, _ := codec.JSONResult(strings.Repeat("y", 600))
		return codec.OK("big", re, 0), nil
	}})
	store := NewResultStoreWithLimits(ResultLimits{TTL: time.Minute})
	base := time.Now()
	var offset atomic.Int64 // read by the server goroutine; no store lock
	store.now = func() time.Time { return base.Add(time.Duration(offset.Load())) }
	agent := startAgentServerConfig(t, r, func(s *Server) *Server { return s.WithResultStore(store) })

	first, err := agent.client.Call(agentZone, "big", []byte(`{}`), "")
	if err != nil || first.Status != codec.StatusChunked || first.Total < 2 {
		t.Fatalf("first envelope = %+v err=%v", first, err)
	}
	if e, err := agent.client.Chunk(agentZone, first.Session, 1); err != nil || e.Status != codec.StatusChunked {
		t.Fatalf("chunk 1 within TTL: %+v err=%v", e, err)
	}
	offset.Store(int64(2 * time.Minute))
	e, err := agent.client.Chunk(agentZone, first.Session, 1)
	if err != nil || e.Status != codec.StatusError || !strings.Contains(e.Error, "unknown session") {
		t.Fatalf("chunk 1 after TTL: %+v err=%v, want unknown-session error", e, err)
	}
	if store.Len() != 0 {
		t.Fatalf("expired session still stored: Len=%d", store.Len())
	}
}
