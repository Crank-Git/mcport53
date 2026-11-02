package dns

import (
	"encoding/base64"
	"encoding/json"
	"net"
	"testing"
	"time"

	"github.com/Crank-Git/mcport53/internal/codec"
	"github.com/miekg/dns"
)

const testZone = "example."

// testHandlers builds a Handlers that simulates echo/boom/slow/big tools plus
// chunk and job protocols, capturing the last call request.
type testHarness struct {
	lastCall *CallRequest
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
			h.lastCall = req
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

	srv := NewServer(testZone, handlers).WithDiscovery("127.0.0.1.", 53)
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

	return NewClient(udpConn.LocalAddr().String()), h
}

func b64(s string) string { return base64.StdEncoding.EncodeToString([]byte(s)) }

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

func TestCallSignatureRoundTrip(t *testing.T) {
	c, h := newTestServer(t)
	if _, err := c.Call(testZone, "echo", []byte(`{}`), "deadbeef"); err != nil {
		t.Fatalf("call: %v", err)
	}
	if h.lastCall.Sig != "deadbeef" {
		t.Fatalf("server saw sig = %q, want deadbeef", h.lastCall.Sig)
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

func TestUnknownNXDOMAIN(t *testing.T) {
	c, _ := newTestServer(t)
	resp, err := c.Query(dns.Fqdn("definitely-a-tool.example."), dns.TypeTXT)
	if err != nil {
		t.Fatalf("query: %v", err)
	}
	if resp.Rcode != dns.RcodeNameError {
		t.Fatalf("rcode = %d (%s), want NXDOMAIN", resp.Rcode, dns.RcodeToString[resp.Rcode])
	}
}

func TestBadZoneNXDOMAIN(t *testing.T) {
	c, _ := newTestServer(t)
	resp, err := c.Query(dns.Fqdn("echo.call.abc123.notexample."), dns.TypeTXT)
	if err != nil {
		t.Fatalf("query: %v", err)
	}
	if resp.Rcode != dns.RcodeNameError {
		t.Fatalf("rcode = %d, want NXDOMAIN for foreign zone", resp.Rcode)
	}
}

func TestQueryTimeout(t *testing.T) {
	c := NewClient("127.0.0.1:1") // port 1: no listener, connection refused
	c.SetTimeout(500 * time.Millisecond)
	if _, err := c.Query(dns.Fqdn("echo.example."), dns.TypeTXT); err == nil {
		t.Fatal("expected error querying an unreachable server")
	}
}
