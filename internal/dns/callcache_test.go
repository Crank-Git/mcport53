package dns

import (
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Crank-Git/mcport53/internal/codec"
	"github.com/miekg/dns"
)

// gatedServer runs a server whose call handler blocks until release is
// closed (when gate is true) and counts runs per tool.
func gatedServer(t *testing.T, gate bool, configure func(*Server) *Server) (*Server, string, chan struct{}, *sync.Map) {
	t.Helper()
	release := make(chan struct{})
	var runs sync.Map // tool -> *atomic.Int64
	srv := NewServer(testZone, &Handlers{
		OnCall: func(req *CallRequest) *codec.Envelope {
			n, _ := runs.LoadOrStore(req.Tool, new(atomic.Int64))
			n.(*atomic.Int64).Add(1)
			if req.Tool == "panic" {
				panic("tool bug")
			}
			if gate && req.Tool != "free" {
				<-release
			}
			return codec.OK(req.Tool, req.Nonce, 0)
		},
	})
	if configure != nil {
		srv = configure(srv)
	}
	_, addr := startServerWithAddr(t, srv)
	return srv, addr, release, &runs
}

func runsOf(m *sync.Map, tool string) int64 {
	if n, ok := m.Load(tool); ok {
		return n.(*atomic.Int64).Load()
	}
	return 0
}

func sendTXT(t *testing.T, addr, name string) (*codec.Envelope, error) {
	t.Helper()
	c := NewClient(addr)
	c.SetTimeout(5 * time.Second)
	resp, err := c.Query(name, dns.TypeTXT)
	if err != nil {
		return nil, err
	}
	txt, err := extractTXT(resp)
	if err != nil {
		return nil, err
	}
	return codec.ParseEnvelope([]byte(txt))
}

// TestConcurrentCopiesRunOnce: 20 copies of one call name in flight at once
// run the handler once, and every copy gets the same answer.
func TestConcurrentCopiesRunOnce(t *testing.T) {
	_, addr, release, runs := gatedServer(t, true, nil)
	name := callName("echo")
	var wg sync.WaitGroup
	results := make([]string, 20)
	for i := range results {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			e, err := sendTXT(t, addr, name)
			if err != nil {
				t.Errorf("copy %d: %v", i, err)
				return
			}
			results[i] = e.Result
		}(i)
	}
	time.Sleep(200 * time.Millisecond) // let every copy arrive while the first is running
	close(release)
	wg.Wait()
	if got := runsOf(runs, "echo"); got != 1 {
		t.Fatalf("handler ran %d times for 20 copies, want 1", got)
	}
	for i, r := range results {
		if r != results[0] || r == "" {
			t.Fatalf("copy %d answered %q, copy 0 %q", i, r, results[0])
		}
	}
}

// TestLaterCopyAndCaseShareEntry: a copy after completion, and copies in
// other cases, are answered from the cache.
func TestLaterCopyAndCaseShareEntry(t *testing.T) {
	_, addr, _, runs := gatedServer(t, false, nil)
	name := callName("echo")
	first, err := sendTXT(t, addr, name)
	if err != nil {
		t.Fatal(err)
	}
	for _, variant := range []string{name, strings.ToUpper(name), randomCaseFixed(name)} {
		e, err := sendTXT(t, addr, variant)
		if err != nil || e.Result != first.Result {
			t.Fatalf("copy %q: %+v %v", variant, e, err)
		}
	}
	if got := runsOf(runs, "echo"); got != 1 {
		t.Fatalf("handler ran %d times, want 1", got)
	}
	// A different nonce is a different call.
	if _, err := sendTXT(t, addr, callName("echo")); err != nil {
		t.Fatal(err)
	}
	if got := runsOf(runs, "echo"); got != 2 {
		t.Fatalf("distinct call: handler ran %d times total, want 2", got)
	}
}

func randomCaseFixed(s string) string {
	b := []byte(s)
	for i := 0; i < len(b); i += 2 {
		if b[i] >= 'a' && b[i] <= 'z' {
			b[i] -= 32
		}
	}
	return string(b)
}

// TestCallCacheExpiry: after the TTL, a copy runs the call again.
func TestCallCacheExpiry(t *testing.T) {
	var offset atomic.Int64
	base := time.Now()
	_, addr, _, runs := gatedServer(t, false, func(s *Server) *Server {
		s = s.WithCallCache(10, time.Minute)
		s.calls.now = func() time.Time { return base.Add(time.Duration(offset.Load())) }
		return s
	})
	name := callName("echo")
	_, _ = sendTXT(t, addr, name)
	offset.Store(int64(59 * time.Second))
	_, _ = sendTXT(t, addr, name)
	if got := runsOf(runs, "echo"); got != 1 {
		t.Fatalf("within TTL: %d runs, want 1", got)
	}
	offset.Store(int64(61 * time.Second))
	_, _ = sendTXT(t, addr, name)
	if got := runsOf(runs, "echo"); got != 2 {
		t.Fatalf("after TTL: %d runs, want 2", got)
	}
}

// TestCallCacheBounded: the cache holds at most its limit and evicts the
// oldest finished entry.
func TestCallCacheBounded(t *testing.T) {
	srv, addr, _, runs := gatedServer(t, false, func(s *Server) *Server { return s.WithCallCache(3, time.Minute) })
	var names []string
	for i := 0; i < 5; i++ {
		names = append(names, callName("echo"))
		_, _ = sendTXT(t, addr, names[i])
	}
	if n := srv.calls.len(); n != 3 {
		t.Fatalf("cache len = %d, want 3", n)
	}
	_, _ = sendTXT(t, addr, names[4]) // newest: cached
	if got := runsOf(runs, "echo"); got != 5 {
		t.Fatalf("after re-sending newest: %d runs, want 5", got)
	}
	_, _ = sendTXT(t, addr, names[0]) // oldest: evicted, runs again
	if got := runsOf(runs, "echo"); got != 6 {
		t.Fatalf("after re-sending oldest: %d runs, want 6", got)
	}
}

// TestCallCacheFullOfInFlightRunsUncached: when every entry is in flight, a
// new call still runs (uncached) instead of blocking.
func TestCallCacheFullOfInFlightRunsUncached(t *testing.T) {
	_, addr, release, runs := gatedServer(t, true, func(s *Server) *Server { return s.WithCallCache(1, time.Minute) })
	defer close(release)
	go func() { _, _ = sendTXT(t, addr, callName("blocked")) }()
	deadline := time.Now().Add(2 * time.Second)
	for runsOf(runs, "blocked") == 0 && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	start := time.Now()
	e, err := sendTXT(t, addr, callName("free"))
	if err != nil || e.Status != codec.StatusOK || time.Since(start) > time.Second {
		t.Fatalf("call while the cache is full of in-flight calls: %+v %v after %v", e, err, time.Since(start))
	}
}

// TestCallCacheLeaderPanic: a panicking first copy releases waiters with an
// error instead of hanging them, and a later copy runs the call again.
func TestCallCacheLeaderPanic(t *testing.T) {
	_, addr, _, runs := gatedServer(t, false, nil)
	name := callName("panic")
	c := NewClient(addr)
	if resp, err := c.Query(name, dns.TypeTXT); err != nil || resp.Rcode != dns.RcodeServerFailure {
		t.Fatalf("panicking call: %v %v, want SERVFAIL", resp, err)
	}
	if resp, _ := c.Query(name, dns.TypeTXT); resp.Rcode != dns.RcodeServerFailure {
		t.Fatalf("copy after a panic: rcode %s", dns.RcodeToString[resp.Rcode])
	}
	if got := runsOf(runs, "panic"); got != 2 {
		t.Fatalf("panicking call ran %d times, want 2 (no cached answer after a panic)", got)
	}
}

// TestCallCacheWaitLimit: a copy stops waiting for a stuck first copy.
func TestCallCacheWaitLimit(t *testing.T) {
	prev := callWaitLimit
	callWaitLimit = 100 * time.Millisecond
	t.Cleanup(func() { callWaitLimit = prev })
	_, addr, release, _ := gatedServer(t, true, nil)
	defer close(release)
	name := callName("stuck")
	go func() { _, _ = sendTXT(t, addr, name) }()
	time.Sleep(50 * time.Millisecond)
	e, err := sendTXT(t, addr, name)
	if err != nil || e.Status != codec.StatusError || !strings.Contains(e.Error, "did not complete") {
		t.Fatalf("waiting copy: %+v %v", e, err)
	}
}
