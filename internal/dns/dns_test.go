package dns

import (
	"encoding/base64"
	"encoding/json"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Crank-Git/mcport53/internal/auth"
	"github.com/Crank-Git/mcport53/internal/codec"
	"github.com/miekg/dns"
	miedns "github.com/miekg/dns"
)

const testZone = "example."

// testHandlers builds a Handlers that simulates echo/boom/slow/big tools plus
// chunk and job protocols, capturing the last call request.
type testHarness struct {
	mu       sync.Mutex
	lastCall *CallRequest
}

// last returns the most recent call request seen by the server. The server
// handler runs on its own goroutine, so access is guarded by mu.
func (h *testHarness) last() *CallRequest {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.lastCall
}

func newTestServer(t *testing.T) (*Client, *testHarness) {
	t.Helper()
	h := &testHarness{}
	handlers := &Handlers{
		OnDiscovery: func() *DiscoveryResponse {
			return &DiscoveryResponse{
				Version: 1,
				Tools: []Tool{
					{Name: "echo", Description: "echo text", InputSchema: json.RawMessage(`{"type":"object"}`)},
					{Name: "boom", Description: "always fails"},
				},
			}
		},
		OnCall: func(req *CallRequest) *codec.Envelope {
			h.mu.Lock()
			h.lastCall = req
			h.mu.Unlock()
			switch req.Tool {
			case "boom":
				return codec.Error("boom", "kaboom")
			case "slow":
				return codec.Queued("slow", "job-1")
			case "big":
				return codec.Chunked("big", "sess-1", 0, 2, true, b64("hello-"))
			default:
				return codec.OK(req.Tool, codec.TextResult("text/plain", string(req.Args)), 0)
			}
		},
		OnSchema: func(tool string) *codec.Envelope {
			return codec.OK(tool, `{"type":"object"}`, 0)
		},
		OnChunk: func(req *ChunkRequest) *codec.Envelope {
			if req.Chunk == 0 {
				return codec.Chunked("big", "sess-1", 0, 2, true, b64("hello-"))
			}
			return codec.Chunked("big", "sess-1", 1, 2, false, b64("world"))
		},
		OnJob: func(job string) *codec.Envelope {
			return codec.Done("slow", job, "sess-1")
		},
	}

	return startTestServer(t, handlers), h
}

// startTestServer launches an authoritative test server for testZone over an
// anonymous in-process UDP listener and returns a client for it.
func startTestServer(t *testing.T, h *Handlers) *Client {
	t.Helper()
	c, _ := startTestServerWithAddr(t, h)
	return c
}

// startTestServerWithAddr is like startTestServer but also returns the server's
// listen address, which is needed by tests that must send raw messages the
// Client helper cannot express.
func startTestServerWithAddr(t *testing.T, h *Handlers) (*Client, string) {
	t.Helper()
	return startServerWithAddr(t, NewServer(testZone, h).WithDiscovery("127.0.0.1.", 53))
}

// startServerWithAddr starts an in-process UDP test server for the given
// preconfigured Server and returns a client plus the listen address. It lets
// tests configure server options such as TSIG (protocol §8) that the default
// startTestServer helpers do not expose.
func startServerWithAddr(t *testing.T, srv *Server) (*Client, string) {
	t.Helper()
	udpConn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
	if err != nil {
		t.Fatalf("bind udp: %v", err)
	}
	dnsSrv := &dns.Server{PacketConn: udpConn, Handler: srv.Handler(), TsigProvider: srv.tsig.provider()}
	done := make(chan struct{})
	go func() {
		_ = dnsSrv.ActivateAndServe()
		close(done)
	}()
	t.Cleanup(func() {
		_ = dnsSrv.Shutdown()
		<-done
	})
	return NewClient(udpConn.LocalAddr().String()), udpConn.LocalAddr().String()
}

func b64(s string) string { return base64.StdEncoding.EncodeToString([]byte(s)) }

// startRawServer launches an in-process UDP server whose replies are produced
// by fn, letting tests exercise malformed-response handling that the normal
// Handlers cannot express.
func startRawServer(t *testing.T, fn func(req *dns.Msg) *dns.Msg) *Client {
	t.Helper()
	udpConn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
	if err != nil {
		t.Fatalf("bind udp: %v", err)
	}
	srv := &miedns.Server{PacketConn: udpConn, Handler: miedns.HandlerFunc(func(w miedns.ResponseWriter, r *miedns.Msg) {
		resp := fn(r)
		if resp == nil {
			resp = reply(r)
		}
		_ = w.WriteMsg(resp)
	})}
	done := make(chan struct{})
	go func() {
		_ = srv.ActivateAndServe()
		close(done)
	}()
	t.Cleanup(func() {
		_ = srv.Shutdown()
		<-done
	})
	return NewClient(udpConn.LocalAddr().String())
}

// Discovery: a TXT answer that is not a discovery document is an error.
func TestDiscoveryMalformedTXT(t *testing.T) {
	c := startRawServer(t, func(req *dns.Msg) *dns.Msg {
		resp := reply(req)
		resp.Rcode = dns.RcodeSuccess
		resp.Answer = []dns.RR{&dns.TXT{
			Hdr: dns.RR_Header{Name: req.Question[0].Name, Rrtype: dns.TypeTXT, Class: dns.ClassINET, Ttl: 0},
			Txt: TXTStrings("!not a document!"),
		}}
		return resp
	})
	if _, err := c.Discovery(testZone); err == nil {
		t.Fatal("expected an error for a TXT answer that is not a discovery document")
	}
}

// Discovery: a TXT answer that is not a JSON document is a parse error.
func TestDiscoveryNonJSON(t *testing.T) {
	c := startRawServer(t, func(req *dns.Msg) *dns.Msg {
		resp := reply(req)
		resp.Rcode = dns.RcodeSuccess
		resp.Answer = []dns.RR{&dns.TXT{
			Hdr: dns.RR_Header{Name: req.Question[0].Name, Rrtype: dns.TypeTXT, Class: dns.ClassINET, Ttl: 0},
			Txt: TXTStrings("not json"),
		}}
		return resp
	})
	if _, err := c.Discovery(testZone); err == nil {
		t.Fatal("expected a JSON parse error for a non-JSON TXT answer")
	}
}

// Discovery: an exchange that fails is surfaced as an error.
func TestDiscoveryExchangeError(t *testing.T) {
	c := NewClient("127.0.0.1:1")
	if _, err := c.Discovery(testZone); err == nil {
		t.Fatal("expected an exchange error when the server is unreachable")
	}
}

// queryTXT: a query whose exchange fails is surfaced as an error.
func TestQueryExchangeError(t *testing.T) {
	c := NewClient("127.0.0.1:1")
	if _, err := c.queryTXT(dns.Fqdn("a.example."), dns.TypeTXT); err == nil {
		t.Fatal("expected an exchange error when the server is unreachable")
	}
}

func TestDiscovery(t *testing.T) {
	c, _ := newTestServer(t)
	doc, err := c.Discovery(testZone)
	if err != nil {
		t.Fatalf("discovery: %v", err)
	}
	if doc.Version != 1 {
		t.Errorf("version = %d, want 1", doc.Version)
	}
	if len(doc.Tools) != 2 {
		t.Fatalf("tools = %d, want 2", len(doc.Tools))
	}
	if doc.Tools[0].Name != "echo" {
		t.Errorf("tool[0].name = %q, want echo", doc.Tools[0].Name)
	}
}

// TestDiscoverySRVTarget verifies the advertised SRV target and port flow through
// to the discovery response (protocol §2.1), so operators can point clients at
// the reachable resolver rather than a hard-wired address.
func TestDiscoverySRVTarget(t *testing.T) {
	handlers := &Handlers{
		OnDiscovery: func() *DiscoveryResponse { return &DiscoveryResponse{} },
	}
	srv := NewServer(testZone, handlers).WithDiscovery("resolver.example.", 8053)

	udpConn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
	if err != nil {
		t.Fatalf("bind udp: %v", err)
	}
	dnsSrv := &dns.Server{PacketConn: udpConn, Handler: srv.Handler()}
	done := make(chan struct{})
	go func() {
		_ = dnsSrv.ActivateAndServe()
		close(done)
	}()
	t.Cleanup(func() {
		_ = dnsSrv.Shutdown()
		<-done
	})

	c := NewClient(udpConn.LocalAddr().String())
	resp, err := c.Query(dns.Fqdn("_mcp._udp."+strings.TrimSuffix(testZone, ".")), dns.TypeSRV)
	if err != nil {
		t.Fatalf("discovery query: %v", err)
	}
	var srvRec *dns.SRV
	for _, rr := range resp.Answer {
		if s, ok := rr.(*dns.SRV); ok {
			srvRec = s
			break
		}
	}
	if srvRec == nil {
		t.Fatal("no SRV answer in discovery response")
	}
	if srvRec.Target != "resolver.example." || srvRec.Port != 8053 {
		t.Errorf("SRV = %q:%d, want resolver.example.:8053", srvRec.Target, srvRec.Port)
	}
}

func TestCallOK(t *testing.T) {
	c, _ := newTestServer(t)
	e, err := c.Call(testZone, "echo", []byte(`{"text":"hi"}`), "")
	if err != nil {
		t.Fatalf("call: %v", err)
	}
	if e.Status != codec.StatusOK {
		t.Fatalf("status = %q, want ok (%+v)", e.Status, e)
	}
	if e.Tool != "echo" {
		t.Errorf("tool = %q, want echo", e.Tool)
	}
}

func TestCallError(t *testing.T) {
	c, _ := newTestServer(t)
	e, err := c.Call(testZone, "boom", nil, "")
	if err != nil {
		t.Fatalf("call: %v", err)
	}
	if e.Status != codec.StatusError || e.Error != "kaboom" {
		t.Fatalf("envelope = %+v, want error kaboom", e)
	}
}

// A call whose handler returns a nil envelope surfaces a generic error.
func TestCallNilHandler(t *testing.T) {
	c := startTestServer(t, &Handlers{
		OnCall: func(*CallRequest) *codec.Envelope { return nil },
	})
	e, err := c.Call(testZone, "echo", []byte(`{}`), "")
	if err != nil {
		t.Fatalf("call: %v", err)
	}
	if e.Status != codec.StatusError || !strings.Contains(e.Error, "call handler returned nil") {
		t.Fatalf("envelope = %+v, want error mentioning a nil handler", e)
	}
}

func TestCallSignatureRoundTrip(t *testing.T) {
	c, h := newTestServer(t)
	if _, err := c.Call(testZone, "echo", []byte(`{}`), "deadbeef"); err != nil {
		t.Fatalf("call: %v", err)
	}
	if got := h.last(); got == nil || got.Sig != "deadbeef" {
		t.Fatalf("server saw call %+v, want sig deadbeef", got)
	}
}

func TestSchema(t *testing.T) {
	c, _ := newTestServer(t)
	e, err := c.Schema(testZone, "echo")
	if err != nil {
		t.Fatalf("schema: %v", err)
	}
	if e.Status != codec.StatusOK {
		t.Fatalf("status = %q, want ok", e.Status)
	}
}

func TestChunkProtocol(t *testing.T) {
	c, _ := newTestServer(t)
	e, err := c.Call(testZone, "big", nil, "")
	if err != nil {
		t.Fatalf("call big: %v", err)
	}
	if e.Status != codec.StatusChunked || e.Chunk != 0 || e.Total != 2 || !e.More {
		t.Fatalf("big envelope = %+v, want chunked 0/2 more", e)
	}
	last, err := c.Chunk(testZone, e.Session, e.Total-1)
	if err != nil {
		t.Fatalf("chunk: %v", err)
	}
	if last.More {
		t.Fatalf("final chunk still has more=true: %+v", last)
	}
}

func TestChunkCursorProtocol(t *testing.T) {
	c := startTestServer(t, &Handlers{
		OnCall: func(req *CallRequest) *codec.Envelope {
			e := codec.Chunked("big", "sess-c", 0, 2, true, b64("hello-"))
			e.Cursor = "done"
			return e
		},
		OnChunk: func(req *ChunkRequest) *codec.Envelope {
			if req.Cursor == "" {
				t.Fatalf("cursor fetch missing its cursor")
			}
			if req.Chunk != 0 {
				t.Fatalf("cursor fetch should not carry a fixed index, got %d", req.Chunk)
			}
			return codec.Chunked("big", "sess-c", 1, 2, false, b64("world"))
		},
	})
	e, err := c.Call(testZone, "big", nil, "")
	if err != nil {
		t.Fatalf("call big: %v", err)
	}
	if e.Cursor == "" {
		t.Fatal("chunk-0 envelope should carry a cursor")
	}
	last, err := c.ChunkByCursor(testZone, e.Session, e.Cursor)
	if err != nil {
		t.Fatalf("chunk by cursor: %v", err)
	}
	if last.More {
		t.Fatalf("final cursor chunk still has more=true: %+v", last)
	}
	// A malformed cursor name is rejected by the name parser.
	if _, _, _, err := codec.ParseCursorName([]string{"chunk", "example"}); err == nil {
		t.Fatal("expected an error for a malformed cursor chunk name")
	}
}

func TestJobProtocol(t *testing.T) {
	c, _ := newTestServer(t)
	e, err := c.Call(testZone, "slow", nil, "")
	if err != nil {
		t.Fatalf("call slow: %v", err)
	}
	if e.Status != codec.StatusQueued || e.Job != "job-1" {
		t.Fatalf("slow envelope = %+v, want queued job-1", e)
	}
	j, err := c.Job(testZone, e.Job)
	if err != nil {
		t.Fatalf("job: %v", err)
	}
	if j.Status != codec.StatusDone || j.Session != "sess-1" {
		t.Fatalf("job envelope = %+v, want done sess-1", j)
	}
}

// An unknown shape under the zone is an empty non-terminal: NODATA with the
// SOA, never NXDOMAIN (see authoritative_test.go).
func TestUnknownNameIsNODATA(t *testing.T) {
	c, _ := newTestServer(t)
	resp, err := c.Query(dns.Fqdn("definitely-a-tool.example."), dns.TypeTXT)
	if err != nil {
		t.Fatalf("query: %v", err)
	}
	if resp.Rcode != dns.RcodeSuccess || len(resp.Answer) != 0 || len(resp.Ns) != 1 {
		t.Fatalf("rcode=%s answer=%d ns=%d, want NODATA with SOA", dns.RcodeToString[resp.Rcode], len(resp.Answer), len(resp.Ns))
	}
}

func TestForeignZoneRefused(t *testing.T) {
	c, _ := newTestServer(t)
	resp, err := c.Query(dns.Fqdn("echo.call.abc123.notexample."), dns.TypeTXT)
	if err != nil {
		t.Fatalf("query: %v", err)
	}
	if resp.Rcode != dns.RcodeRefused || resp.Authoritative {
		t.Fatalf("rcode = %s aa=%v, want non-authoritative REFUSED for a foreign zone", dns.RcodeToString[resp.Rcode], resp.Authoritative)
	}
}

func TestQueryTimeout(t *testing.T) {
	c := NewClient("127.0.0.1:1") // port 1: no listener, connection refused
	c.SetTimeout(500 * time.Millisecond)
	if _, err := c.Query(dns.Fqdn("echo.example."), dns.TypeTXT); err == nil {
		t.Fatal("expected error querying an unreachable server")
	}
}

// authServer starts a test server whose OnVerify enforces HMAC signatures and
// one-time nonces via an auth.ReplayGuard, returning the client and the guard.
func authServer(t *testing.T, secret []byte) *Client {
	t.Helper()
	guard := auth.NewReplayGuard(auth.DefaultReplayMaxEntries, time.Minute)
	t.Cleanup(guard.Close)
	handlers := &Handlers{
		OnCall: func(req *CallRequest) *codec.Envelope {
			return codec.OK(req.Tool, codec.TextResult("text/plain", string(req.Args)), 0)
		},
		OnVerify: func(req *CallRequest) error {
			if err := auth.Check(secret, req.Sig, req.Tool, req.Nonce, req.Args, time.Now(), time.Minute); err != nil {
				return err
			}
			return guard.Check(req.Nonce, time.Now())
		},
	}
	c := startTestServer(t, handlers)
	return c
}

// signedCallName builds a fully-qualified signed call name for the given nonce
// and signature, mirroring what a signing client would send.
func signedCallName(t *testing.T, zone, tool string, args []byte, nonce, sig string) string {
	t.Helper()
	labels := codec.BuildCallName(NameToLabels(zone), tool, args, nonce, sig)
	return LabelsToName(labels)
}

func callEnvelope(t *testing.T, c *Client, name string) *codec.Envelope {
	t.Helper()
	resp, err := c.Query(name, dns.TypeTXT)
	if err != nil {
		t.Fatalf("query %s: %v", name, err)
	}
	if resp.Rcode != dns.RcodeSuccess {
		t.Fatalf("query %s: rcode %s, want NOERROR", name, dns.RcodeToString[resp.Rcode])
	}
	txt, err := extractTXT(resp)
	if err != nil {
		t.Fatalf("query %s: extract TXT: %v", name, err)
	}
	e, err := codec.ParseEnvelope([]byte(txt))
	if err != nil {
		t.Fatalf("query %s: parse envelope: %v", name, err)
	}
	return e
}

func TestAuthSignedCallOK(t *testing.T) {
	secret := []byte("shared-top-secret")
	c := authServer(t, secret)

	nonce, err := codec.RandomNonce()
	if err != nil {
		t.Fatalf("nonce: %v", err)
	}
	args := []byte(`{"text":"hi"}`)
	sig := auth.Sign(secret, "echo", nonce, args, time.Now().Unix())
	name := signedCallName(t, testZone, "echo", args, nonce, sig)

	e := callEnvelope(t, c, name)
	if e.Status != codec.StatusOK {
		t.Fatalf("signed call status = %q, want ok (%+v)", e.Status, e)
	}
}

func TestAuthUnsignedRejected(t *testing.T) {
	secret := []byte("shared-top-secret")
	c := authServer(t, secret)

	nonce, _ := codec.RandomNonce()
	args := []byte(`{"text":"hi"}`)
	// Unsigned call: empty signature label.
	name := signedCallName(t, testZone, "echo", args, nonce, "")

	e := callEnvelope(t, c, name)
	if e.Status != codec.StatusError || !strings.Contains(e.Error, "not signed") {
		t.Fatalf("unsigned call envelope = %+v, want error mentioning 'not signed'", e)
	}
}

func TestAuthTamperedRejected(t *testing.T) {
	secret := []byte("shared-top-secret")
	c := authServer(t, secret)

	nonce, _ := codec.RandomNonce()
	args := []byte(`{"text":"hi"}`)
	// Sign the real args, but send tampered args on the wire. The tampered
	// arguments cannot match the signature for any timestamp in the window, so
	// the call is rejected (ErrStale).
	sig := auth.Sign(secret, "echo", nonce, args, time.Now().Unix())
	tampered := signedCallName(t, testZone, "echo", []byte(`{"text":"evil"}`), nonce, sig)

	e := callEnvelope(t, c, tampered)
	if e.Status != codec.StatusError || e.Error == "" {
		t.Fatalf("tampered call envelope = %+v, want a non-empty error", e)
	}
}

// TestMultiQuestionFormErr covers ServeDNS's != 1 question guard. The miekg
// server rejects multi-question messages before reaching the handler by
// default, so we install an accept func that admits them.
func TestMultiQuestionFormErr(t *testing.T) {
	srv := NewServer(testZone, &Handlers{}).WithDiscovery("127.0.0.1.", 53)
	udpConn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
	if err != nil {
		t.Fatalf("bind udp: %v", err)
	}
	dnsSrv := &dns.Server{PacketConn: udpConn, Handler: srv.Handler(), MsgAcceptFunc: func(dns.Header) miedns.MsgAcceptAction { return miedns.MsgAccept }}
	done := make(chan struct{})
	go func() {
		_ = dnsSrv.ActivateAndServe()
		close(done)
	}()
	defer func() {
		_ = dnsSrv.Shutdown()
		<-done
	}()
	addr := udpConn.LocalAddr().String()

	client := &miedns.Client{Net: "udp", Timeout: 2 * time.Second}
	m := new(miedns.Msg)
	m.SetQuestion(dns.Fqdn("echo.example."), dns.TypeTXT)
	// Append a second question: SetQuestion replaces, so add the extra one
	// directly to exercise the != 1 question guard in ServeDNS.
	m.Question = append(m.Question, miedns.Question{Name: dns.Fqdn("boom.example."), Qtype: dns.TypeTXT})
	resp, _, err := client.Exchange(m, addr)
	if err != nil {
		t.Fatalf("query: %v", err)
	}
	if resp.Rcode != dns.RcodeFormatError {
		t.Fatalf("rcode = %d, want FORMERR for multi-question", resp.Rcode)
	}
}

// A signed discovery document verifies when the client holds the matching key.
func TestDiscoveryVerifiedOK(t *testing.T) {
	key := []byte("discovery-root-key")
	doc := &DiscoveryResponse{Version: 1, Tools: []Tool{{Name: "echo"}}}
	b, _ := json.Marshal(doc)
	sig := auth.Sign(key, "discovery", "", b, 0)
	doc.Sig = sig
	out, _ := json.Marshal(doc)

	c := startRawServer(t, func(req *dns.Msg) *dns.Msg {
		resp := reply(req)
		resp.Rcode = dns.RcodeSuccess
		resp.Answer = []dns.RR{&dns.TXT{
			Hdr: dns.RR_Header{Name: req.Question[0].Name, Rrtype: dns.TypeTXT, Class: dns.ClassINET, Ttl: 0},
			Txt: TXTStrings(string(out)),
		}}
		return resp
	})
	if _, err := c.WithDiscoveryKey(key).Discovery(testZone); err != nil {
		t.Fatalf("verified discovery: %v", err)
	}
}

// A tampered discovery document fails verification.
func TestDiscoveryTamperedRejected(t *testing.T) {
	key := []byte("discovery-root-key")
	doc := &DiscoveryResponse{Version: 1, Tools: []Tool{{Name: "echo"}}}
	b, _ := json.Marshal(doc)
	sig := auth.Sign(key, "discovery", "", b, 0)
	doc.Sig = sig

	c := startRawServer(t, func(req *dns.Msg) *dns.Msg {
		resp := reply(req)
		resp.Rcode = dns.RcodeSuccess
		// Tamper: advertise an extra tool. The signature no longer matches.
		tampered := &DiscoveryResponse{Version: 1, Tools: []Tool{{Name: "echo"}, {Name: "boom"}}}
		tampered.Sig = sig
		tamperedOut, _ := json.Marshal(tampered)
		resp.Answer = []dns.RR{&dns.TXT{
			Hdr: dns.RR_Header{Name: req.Question[0].Name, Rrtype: dns.TypeTXT, Class: dns.ClassINET, Ttl: 0},
			Txt: TXTStrings(string(tamperedOut)),
		}}
		return resp
	})
	if _, err := c.WithDiscoveryKey(key).Discovery(testZone); err == nil {
		t.Fatal("expected a verification failure for a tampered discovery document")
	}
}

// An unsigned discovery document fails verification when a key is configured.
func TestDiscoveryUnsignedRejected(t *testing.T) {
	key := []byte("discovery-root-key")
	doc := &DiscoveryResponse{Version: 1}
	out, _ := json.Marshal(doc) // no Sig field

	c := startRawServer(t, func(req *dns.Msg) *dns.Msg {
		resp := reply(req)
		resp.Rcode = dns.RcodeSuccess
		resp.Answer = []dns.RR{&dns.TXT{
			Hdr: dns.RR_Header{Name: req.Question[0].Name, Rrtype: dns.TypeTXT, Class: dns.ClassINET, Ttl: 0},
			Txt: TXTStrings(string(out)),
		}}
		return resp
	})
	if _, err := c.WithDiscoveryKey(key).Discovery(testZone); err == nil {
		t.Fatal("expected a failure for an unsigned discovery document")
	}
}

// WithSigner signs calls automatically; the server sees a valid signature.
func TestCallSignerRoundTrip(t *testing.T) {
	secret := []byte("shared-top-secret")
	c := startTestServer(t, &Handlers{
		OnCall: func(req *CallRequest) *codec.Envelope {
			return codec.OK(req.Tool, codec.TextResult("text/plain", string(req.Args)), 0)
		},
		OnVerify: func(req *CallRequest) error {
			return auth.Check(secret, req.Sig, req.Tool, req.Nonce, req.Args, time.Now(), time.Minute)
		},
	})
	c.WithSigner(func(tool, nonce string, args []byte, ts int64) string {
		return auth.Sign(secret, tool, nonce, args, ts)
	})
	e, err := c.Call(testZone, "echo", []byte(`{"text":"hi"}`), "")
	if err != nil {
		t.Fatalf("auto-signed call: %v", err)
	}
	if e.Status != codec.StatusOK {
		t.Fatalf("status = %q, want ok", e.Status)
	}
}

// TestAuthReplayRejected: a replayed copy of a signed call never runs the
// call again. While the call cache holds the call, the copy gets the original
// answer; once the entry is gone, replay protection rejects it.
func TestAuthReplayRejected(t *testing.T) {
	secret := []byte("shared-top-secret")
	guard := auth.NewReplayGuard(auth.DefaultReplayMaxEntries, time.Minute)
	t.Cleanup(guard.Close)
	var runs atomic.Int64
	srv := NewServer(testZone, &Handlers{
		OnCall: func(req *CallRequest) *codec.Envelope {
			runs.Add(1)
			return codec.OK(req.Tool, "ran", 0)
		},
		OnVerify: func(req *CallRequest) error {
			if err := auth.Check(secret, req.Sig, req.Tool, req.Nonce, req.Args, time.Now(), time.Minute); err != nil {
				return err
			}
			return guard.Check(req.Nonce, time.Now())
		},
	}).WithCallCache(1, time.Minute)
	c, _ := startServerWithAddr(t, srv)

	signed := func(args string) string {
		nonce, _ := codec.RandomNonce()
		sig := auth.Sign(secret, "echo", nonce, []byte(args), time.Now().Unix())
		return signedCallName(t, testZone, "echo", []byte(args), nonce, sig)
	}
	name := signed(`{"text":"hi"}`)
	if e := callEnvelope(t, c, name); e.Status != codec.StatusOK {
		t.Fatalf("first call status = %q, want ok", e.Status)
	}
	if e := callEnvelope(t, c, name); e.Status != codec.StatusOK || runs.Load() != 1 {
		t.Fatalf("cached replay = %+v after %d runs, want the original answer and 1 run", e, runs.Load())
	}
	// Another call evicts the entry from the one-entry cache.
	if e := callEnvelope(t, c, signed(`{"text":"other"}`)); e.Status != codec.StatusOK {
		t.Fatalf("second call: %+v", e)
	}
	e := callEnvelope(t, c, name)
	if e.Status != codec.StatusError || !strings.Contains(e.Error, "replay") {
		t.Fatalf("uncached replay = %+v, want error mentioning 'replay'", e)
	}
	if runs.Load() != 2 {
		t.Fatalf("handler ran %d times, want 2 (one per distinct call)", runs.Load())
	}
}
