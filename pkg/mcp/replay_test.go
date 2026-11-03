package mcp

import (
	"context"
	"errors"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Crank-Git/mcport53/internal/auth"
	"github.com/Crank-Git/mcport53/internal/codec"
	"github.com/Crank-Git/mcport53/internal/dns"
	miedns "github.com/miekg/dns"
)

// fakeClock replaces timeNow for the duration of a test.
func fakeClock(t *testing.T, start time.Time) *time.Time {
	t.Helper()
	now := start
	var mu sync.Mutex
	prev := timeNow
	timeNow = func() time.Time { mu.Lock(); defer mu.Unlock(); return now }
	t.Cleanup(func() { timeNow = prev })
	return &now
}

func signedReq(secret []byte, tool string, args []byte, ts int64, caller string) *dns.CallRequest {
	nonce, _ := codec.RandomNonce()
	return &dns.CallRequest{
		Tool: tool, Args: args, Nonce: nonce, Caller: caller,
		Sig: auth.Sign(secret, tool, nonce, args, ts),
	}
}

// TestReplayFromAnotherCallerRejected is the bypass from the issue: before the
// fix the guard keyed on (caller, nonce), so the same signed call replayed from
// a different source address verified.
func TestReplayFromAnotherCallerRejected(t *testing.T) {
	secret := []byte("s")
	reg := auth.NewKeyRegistry(secret)
	verifiers := map[string]func(*dns.CallRequest) error{
		"HMACVerify":     HMACVerify(secret, time.Minute, 0),
		"HMACVerifyKeys": HMACVerifyKeys(reg),
	}
	for name, verify := range verifiers {
		req := signedReq(secret, "echo", []byte(`{}`), time.Now().Unix(), "10.0.0.1")
		if err := verify(req); err != nil {
			t.Fatalf("%s: original call: %v", name, err)
		}
		for _, caller := range []string{"10.0.0.1", "10.0.0.2", "::1", ""} {
			replay := *req
			replay.Caller = caller
			if err := verify(&replay); !errors.Is(err, errReplay) {
				t.Errorf("%s: replay from %q: err = %v, want errReplay", name, caller, err)
			}
		}
	}
}

// TestReplayAfterWindowWithFutureTimestamp covers the TTL gap: a call signed at
// the far edge of the window (ts = now+window) is valid until now+2*window. The
// old guard forgot its nonce after one window, so it could be replayed.
func TestReplayAfterWindowWithFutureTimestamp(t *testing.T) {
	secret := []byte("s")
	window := time.Minute
	t0 := time.Unix(1_800_000_000, 0)
	clock := fakeClock(t, t0)
	verify := HMACVerify(secret, window, 0)

	req := signedReq(secret, "echo", []byte(`{}`), t0.Add(window).Unix(), "a")
	if err := verify(req); err != nil {
		t.Fatalf("call signed at the window edge: %v", err)
	}
	for _, after := range []time.Duration{window + time.Second, window + 30*time.Second, 2 * window} {
		*clock = t0.Add(after)
		if err := verify(req); !errors.Is(err, errReplay) {
			t.Errorf("replay %v later: err = %v, want errReplay", after, err)
		}
	}
	// Past 2*window the timestamp itself is stale, so the call is refused on
	// the signature check regardless of the guard.
	*clock = t0.Add(2*window + 2*time.Second)
	if err := verify(req); !errors.Is(err, auth.ErrStale) {
		t.Errorf("replay past 2*window: err = %v, want ErrStale", err)
	}
}

// TestReplayGuardFullSurfaces checks that a full guard refuses new calls
// (with a distinct error) instead of evicting a live nonce.
func TestReplayGuardFullSurfaces(t *testing.T) {
	secret := []byte("s")
	verify := HMACVerify(secret, time.Minute, 2)
	now := time.Now().Unix()
	first := signedReq(secret, "echo", nil, now, "a")
	for _, r := range []*dns.CallRequest{first, signedReq(secret, "echo", nil, now, "a")} {
		if err := verify(r); err != nil {
			t.Fatalf("fill: %v", err)
		}
	}
	if err := verify(signedReq(secret, "echo", nil, now, "a")); !errors.Is(err, auth.ErrGuardFull) {
		t.Fatalf("third call: err = %v, want ErrGuardFull", err)
	}
	if err := verify(first); !errors.Is(err, errReplay) {
		t.Fatalf("first nonce must still be remembered: err = %v", err)
	}
}

// TestForgedCallDoesNotConsumeNonce checks the guard only records nonces of
// calls whose signature verified.
func TestForgedCallDoesNotConsumeNonce(t *testing.T) {
	secret := []byte("s")
	verify := HMACVerify(secret, time.Minute, 0)
	req := signedReq(secret, "echo", []byte(`{}`), time.Now().Unix(), "a")
	forged := *req
	forged.Sig = auth.Sign([]byte("wrong"), req.Tool, req.Nonce, req.Args, time.Now().Unix())
	if err := verify(&forged); err == nil {
		t.Fatal("forged call verified")
	}
	if err := verify(req); err != nil {
		t.Fatalf("genuine call after a forgery with its nonce: %v", err)
	}
}

// TestHandlersShareOneReplayGuard checks that calling Handlers() more than
// once does not create independent guards (each would accept the same nonce).
func TestHandlersShareOneReplayGuard(t *testing.T) {
	reg := auth.NewKeyRegistry([]byte("k"))
	srv := NewServer(echoRegistry(t)).WithKeys(reg)
	h1, h2 := srv.Handlers(), srv.Handlers()

	req := signedReq([]byte("k"), "echo", []byte(`{}`), time.Now().Unix(), "a")
	if err := h1.OnVerify(req); err != nil {
		t.Fatalf("first: %v", err)
	}
	if err := h2.OnVerify(req); !errors.Is(err, errReplay) {
		t.Fatalf("same nonce through a second Handlers(): err = %v, want errReplay", err)
	}
}

// TestReplayEndToEndAcrossAddresses captures a signed query on the wire and
// replays the identical bytes to the same server from another address family
// (127.0.0.1 then ::1), so the server sees different callers. The call must
// never run twice: while the call cache holds it, replays get the original
// answer; once the entry is evicted, replay protection refuses them.
func TestReplayEndToEndAcrossAddresses(t *testing.T) {
	key := []byte("e2e-key")
	var runs atomic.Int64
	reg := NewRegistry()
	_ = reg.Register(&Tool{Name: "pay", Call: func(_ context.Context, args []byte) (*codec.Envelope, error) {
		runs.Add(1)
		return codec.OK("pay", `{"kind":"text","value":"cGFpZA=="}`, 0), nil
	}})
	srv := NewServer(reg).WithKeys(auth.NewKeyRegistry(key))
	handlers := srv.Handlers()
	ds := dns.NewServer(agentZone, &handlers).WithCallCache(1, time.Minute)
	handler := ds.Handler()

	v4 := listenFor(t, "udp4", "127.0.0.1:0", handler)
	v6 := listenFor(t, "udp6", "[::1]:0", handler)
	if v6 == "" {
		t.Skip("IPv6 loopback unavailable")
	}

	query := func(args string) *miedns.Msg {
		nonce, _ := codec.RandomNonce()
		sig := auth.Sign(key, "pay", nonce, []byte(args), time.Now().Unix())
		q := new(miedns.Msg)
		q.SetQuestion(dns.LabelsToName(codec.BuildCallName(dns.NameToLabels(agentZone), "pay", []byte(args), nonce, sig)), miedns.TypeTXT)
		return q
	}
	send := func(q *miedns.Msg, addr string) *codec.Envelope {
		t.Helper()
		c := &miedns.Client{Net: "udp", UDPSize: 4096, Timeout: 2 * time.Second}
		resp, _, err := c.Exchange(q.Copy(), addr)
		if err != nil {
			t.Fatalf("exchange %s: %v", addr, err)
		}
		raw, err := dns.ExtractTXT(resp)
		if err != nil {
			t.Fatalf("TXT answer: %v", err)
		}
		e, err := codec.ParseEnvelope([]byte(raw))
		if err != nil {
			t.Fatalf("envelope from %s: %v", addr, err)
		}
		return e
	}

	captured := query(`{"amount":100}`)
	first := send(captured, v4)
	if first.Status != codec.StatusOK {
		t.Fatalf("original call: %+v", first)
	}
	for _, addr := range []string{v4, v6} {
		if e := send(captured, addr); e.Status != codec.StatusOK || e.Result != first.Result {
			t.Errorf("cached replay via %s: %+v, want the original answer", addr, e)
		}
	}
	if runs.Load() != 1 {
		t.Fatalf("tool ran %d times after replays, want 1", runs.Load())
	}

	// A different call evicts the captured one from the one-entry cache.
	if e := send(query(`{"amount":1}`), v4); e.Status != codec.StatusOK {
		t.Fatalf("second call: %+v", e)
	}
	for _, addr := range []string{v4, v6} {
		e := send(captured, addr)
		if e.Status != codec.StatusError || !strings.Contains(e.Error, "replay") {
			t.Errorf("uncached replay via %s: %+v, want replay error", addr, e)
		}
	}
	if runs.Load() != 2 {
		t.Fatalf("tool ran %d times, want 2 (one per distinct call)", runs.Load())
	}
}

// listenFor serves handler on a fresh UDP socket and returns its address, or
// "" if the address family is unavailable.
func listenFor(t *testing.T, network, addr string, h miedns.Handler) string {
	t.Helper()
	ua, err := net.ResolveUDPAddr(network, addr)
	if err != nil {
		return ""
	}
	conn, err := net.ListenUDP(network, ua)
	if err != nil {
		return ""
	}
	s := &miedns.Server{PacketConn: conn, Handler: h}
	ready, done := make(chan struct{}), make(chan struct{})
	s.NotifyStartedFunc = func() { close(ready) }
	go func() { _ = s.ActivateAndServe(); close(done) }()
	<-ready
	t.Cleanup(func() { _ = s.Shutdown(); <-done })
	return conn.LocalAddr().String()
}
