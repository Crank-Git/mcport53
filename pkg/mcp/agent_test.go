package mcp

import (
	"context"
	"encoding/base64"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/Crank-Git/mcport53/internal/codec"
	"github.com/Crank-Git/mcport53/internal/dns"
	miedns "github.com/miekg/dns"
	sdkmcp "github.com/modelcontextprotocol/go-sdk/mcp"
)

// b64Chunk base64-encodes a chunk payload for use in synthetic chunk envelopes.
func b64Chunk(s string) string {
	return base64.StdEncoding.EncodeToString([]byte(s))
}

// textResult builds a text-only CallToolResult for tests.
func textResult(s string) *sdkmcp.CallToolResult {
	return &sdkmcp.CallToolResult{
		Content: []sdkmcp.Content{&sdkmcp.TextContent{Text: s}},
	}
}

const agentZone = "agent.example."

// startAgentServer starts an in-process authoritative server for agentZone
// backed by the given registry and returns an Agent for it.
func startAgentServer(t *testing.T, reg *Registry) *Agent {
	return startAgentServerConfig(t, reg, nil)
}

// startAgentServerConfig is like startAgentServer but applies an optional server
// modifier (for example WithKeys or WithDiscoveryKey) before wiring the handlers.
func startAgentServerConfig(t *testing.T, reg *Registry, configure func(*Server) *Server) *Agent {
	t.Helper()
	srv := NewServer(reg)
	if configure != nil {
		srv = configure(srv)
	}
	handlers := srv.Handlers()
	dnsSrv := dns.NewServer(agentZone, &handlers).WithDiscovery("127.0.0.1.", 53)
	udpConn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
	if err != nil {
		t.Fatalf("bind udp: %v", err)
	}
	srvMsg := &miedns.Server{PacketConn: udpConn, Handler: dnsSrv.Handler()}
	ready := make(chan struct{})
	done := make(chan struct{})
	srvMsg.NotifyStartedFunc = func() { close(ready) }
	go func() {
		_ = srvMsg.ActivateAndServe()
		close(done)
	}()
	<-ready // ensure started=true so a no-query test's Shutdown does not race
	t.Cleanup(func() {
		_ = srvMsg.Shutdown()
		<-done
	})
	return NewAgent(udpConn.LocalAddr().String(), agentZone)
}

func TestAgentDiscovery(t *testing.T) {
	reg := NewRegistry()
	_ = reg.AddMCPTool(&sdkmcp.Tool{Name: "echo", Description: "echo text"}, func(ctx context.Context, req *sdkmcp.CallToolRequest) (*sdkmcp.CallToolResult, error) {
		return textResult("hi"), nil
	})
	agent := startAgentServer(t, reg)
	doc, err := agent.Discovery()
	if err != nil {
		t.Fatalf("discovery: %v", err)
	}
	if doc.Version != 1 {
		t.Errorf("version = %d, want 1", doc.Version)
	}
	if len(doc.Tools) != 1 {
		t.Fatalf("tools = %d, want 1", len(doc.Tools))
	}
	if doc.Tools[0].Name != "echo" {
		t.Errorf("tool = %q, want echo", doc.Tools[0].Name)
	}
}

func TestAgentCallOK(t *testing.T) {
	reg := NewRegistry()
	_ = reg.AddMCPTool(&sdkmcp.Tool{Name: "echo"}, func(ctx context.Context, req *sdkmcp.CallToolRequest) (*sdkmcp.CallToolResult, error) {
		return textResult("hi"), nil
	})
	agent := startAgentServer(t, reg)
	re, err := agent.Call(context.Background(), "echo", []byte(`{}`))
	if err != nil {
		t.Fatalf("call: %v", err)
	}
	if re.Kind != codec.KindJSON {
		t.Errorf("kind = %q, want json", re.Kind)
	}
	// The value is the marshaled CallToolResult; it should contain the text.
	if !strings.Contains(re.Value, "hi") {
		t.Errorf("value = %q, want to contain 'hi'", re.Value)
	}
}

func TestAgentCallError(t *testing.T) {
	reg := NewRegistry()
	_ = reg.AddMCPTool(&sdkmcp.Tool{Name: "boom"}, func(ctx context.Context, req *sdkmcp.CallToolRequest) (*sdkmcp.CallToolResult, error) {
		return &sdkmcp.CallToolResult{
			Content: []sdkmcp.Content{&sdkmcp.TextContent{Text: "kaboom"}},
			IsError: true,
		}, nil
	})
	agent := startAgentServer(t, reg)
	if _, err := agent.Call(context.Background(), "boom", []byte(`{}`)); err == nil {
		t.Fatal("call error status: expected error, got nil")
	}
}

func TestAgentCallUnknownTool(t *testing.T) {
	agent := startAgentServer(t, NewRegistry())
	if _, err := agent.Call(context.Background(), "nope", []byte(`{}`)); err == nil {
		t.Fatal("call unknown tool: expected error, got nil")
	}
}

func TestAgentCallChunked(t *testing.T) {
	reg := NewRegistry()
	// A tool whose result is large enough to trigger chunking.
	long := strings.Repeat("x", codec.MaxEnvelopeTXT+200)
	_ = reg.AddMCPTool(&sdkmcp.Tool{Name: "big"}, func(ctx context.Context, req *sdkmcp.CallToolRequest) (*sdkmcp.CallToolResult, error) {
		return &sdkmcp.CallToolResult{
			Content: []sdkmcp.Content{&sdkmcp.TextContent{Text: long}},
		}, nil
	})
	agent := startAgentServer(t, reg)
	re, err := agent.Call(context.Background(), "big", []byte(`{}`))
	if err != nil {
		t.Fatalf("call big: %v", err)
	}
	if !strings.Contains(re.Value, long) {
		t.Errorf("assembled value missing the long payload (len %d)", len(re.Value))
	}
}

// startChunkServer starts an in-process server whose call and chunk handlers
// return caller-supplied envelopes, letting tests exercise the agent's
// chunked-result assembly paths (including error paths).
func startChunkServer(t *testing.T, onCall func(*dns.CallRequest) *codec.Envelope, onChunk func(*dns.ChunkRequest) *codec.Envelope) *Agent {
	t.Helper()
	h := &dns.Handlers{OnCall: onCall, OnChunk: onChunk}
	srv := dns.NewServer(agentZone, h)
	udpConn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
	if err != nil {
		t.Fatalf("bind udp: %v", err)
	}
	srvMsg := &miedns.Server{PacketConn: udpConn, Handler: srv.Handler()}
	ready := make(chan struct{})
	done := make(chan struct{})
	srvMsg.NotifyStartedFunc = func() { close(ready) }
	go func() {
		_ = srvMsg.ActivateAndServe()
		close(done)
	}()
	<-ready
	t.Cleanup(func() {
		_ = srvMsg.Shutdown()
		<-done
	})
	return NewAgent(udpConn.LocalAddr().String(), agentZone)
}

// startRawAgentServer starts an in-process server whose replies are produced by
// fn, letting tests exercise responses the typed handlers cannot express (for
// example a chunk query that NXDOMAINs).
func startRawAgentServer(t *testing.T, fn func(req *miedns.Msg) *miedns.Msg) *Agent {
	t.Helper()
	udpConn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
	if err != nil {
		t.Fatalf("bind udp: %v", err)
	}
	srvMsg := &miedns.Server{PacketConn: udpConn, Handler: miedns.HandlerFunc(func(w miedns.ResponseWriter, req *miedns.Msg) {
		resp := fn(req)
		if resp == nil {
			resp = &miedns.Msg{Id: req.Id, Question: req.Question}
		}
		_ = w.WriteMsg(resp)
	})}
	ready := make(chan struct{})
	done := make(chan struct{})
	srvMsg.NotifyStartedFunc = func() { close(ready) }
	go func() {
		_ = srvMsg.ActivateAndServe()
		close(done)
	}()
	<-ready
	t.Cleanup(func() {
		_ = srvMsg.Shutdown()
		<-done
	})
	return NewAgent(udpConn.LocalAddr().String(), agentZone)
}

// A chunk whose fetch NXDOMAINs surfaces a fetch error.
func TestAgentCallChunkedFetchError(t *testing.T) {
	agent := startRawAgentServer(t, func(req *miedns.Msg) *miedns.Msg {
		name := req.Question[0].Name
		if strings.Contains(name, ".chunk.") {
			resp := new(miedns.Msg)
			resp.Id = req.Id
			resp.Question = req.Question
			resp.Rcode = miedns.RcodeNameError
			return resp
		}
		e := codec.Chunked("echo", "sess", 0, 2, true, b64Chunk("a"))
		b, _ := e.Marshal()
		resp := new(miedns.Msg)
		resp.Id = req.Id
		resp.Question = req.Question
		resp.Authoritative = true
		b64 := base64.StdEncoding.EncodeToString(b)
		resp.Answer = []miedns.RR{&miedns.TXT{
			Hdr: miedns.RR_Header{Name: name, Rrtype: miedns.TypeTXT, Class: miedns.ClassINET, Ttl: 0},
			Txt: splitTxt(b64),
		}}
		return resp
	})
	if _, err := agent.Call(context.Background(), "echo", []byte(`{}`)); err == nil {
		t.Fatal("expected a chunk fetch error when the follow-up chunk NXDOMAINs")
	}
}

// splitTxt splits s into <=255-byte pieces so it fits a single TXT string.
func splitTxt(s string) []string {
	var out []string
	for len(s) > 0 {
		n := 252
		if n > len(s) {
			n = len(s)
		}
		out = append(out, s[:n])
		s = s[n:]
	}
	return out
}

// A chunked call whose envelope reports zero chunks is an error.
func TestAgentCallChunkedNoChunks(t *testing.T) {
	agent := startChunkServer(t,
		func(*dns.CallRequest) *codec.Envelope {
			return codec.Chunked("echo", "sess", 0, 0, false, "")
		},
		func(*dns.ChunkRequest) *codec.Envelope { return codec.Chunked("echo", "sess", 0, 1, false, "") },
	)
	if _, err := agent.Call(context.Background(), "echo", []byte(`{}`)); err == nil {
		t.Fatal("expected error for a chunked result with no chunks")
	}
}

// A chunk 0 payload that is not valid base64 is a decode error.
func TestAgentCallChunkedBadChunk0(t *testing.T) {
	agent := startChunkServer(t,
		func(*dns.CallRequest) *codec.Envelope {
			return codec.Chunked("echo", "sess", 0, 1, false, "!!not-base64!!")
		},
		func(*dns.ChunkRequest) *codec.Envelope { return codec.Chunked("echo", "sess", 0, 1, false, "") },
	)
	if _, err := agent.Call(context.Background(), "echo", []byte(`{}`)); err == nil {
		t.Fatal("expected a base64 decode error for chunk 0")
	}
}

// A subsequent chunk that does not come back as a chunked envelope is an error.
func TestAgentCallChunkedNonChunked(t *testing.T) {
	agent := startChunkServer(t,
		func(*dns.CallRequest) *codec.Envelope {
			return codec.Chunked("echo", "sess", 0, 2, true, b64Chunk("a"))
		},
		func(*dns.ChunkRequest) *codec.Envelope { return codec.OK("echo", "done", 0) },
	)
	if _, err := agent.Call(context.Background(), "echo", []byte(`{}`)); err == nil {
		t.Fatal("expected an error when a subsequent chunk is not chunked")
	}
}

// A subsequent chunk whose payload is not valid base64 is a decode error.
func TestAgentCallChunkedBadDecode(t *testing.T) {
	agent := startChunkServer(t,
		func(*dns.CallRequest) *codec.Envelope {
			return codec.Chunked("echo", "sess", 0, 2, true, b64Chunk("a"))
		},
		func(*dns.ChunkRequest) *codec.Envelope {
			return codec.Chunked("echo", "sess", 1, 2, false, "!!not-base64!!")
		},
	)
	if _, err := agent.Call(context.Background(), "echo", []byte(`{}`)); err == nil {
		t.Fatal("expected a base64 decode error for a subsequent chunk")
	}
}

// An assembled result that is not a valid ResultEnvelope is a parse error.
func TestAgentCallChunkedParseError(t *testing.T) {
	agent := startChunkServer(t,
		func(*dns.CallRequest) *codec.Envelope {
			return codec.Chunked("echo", "sess", 0, 1, false, b64Chunk("not json"))
		},
		func(*dns.ChunkRequest) *codec.Envelope { return codec.Chunked("echo", "sess", 0, 1, false, "") },
	)
	if _, err := agent.Call(context.Background(), "echo", []byte(`{}`)); err == nil {
		t.Fatal("expected a parse error for an invalid assembled result")
	}
}

// A call that returns an error envelope surfaces the error message.
func TestAgentCallStatusError(t *testing.T) {
	agent := startChunkServer(t,
		func(*dns.CallRequest) *codec.Envelope { return codec.Error("echo", "boom") },
		func(*dns.ChunkRequest) *codec.Envelope { return codec.Chunked("echo", "sess", 0, 1, false, "") },
	)
	if _, err := agent.Call(context.Background(), "echo", []byte(`{}`)); err == nil || !strings.Contains(err.Error(), "boom") {
		t.Fatalf("expected error mentioning boom, got %v", err)
	}
}

// A call that returns an unexpected status (queued/running/done) is an error.
func TestAgentCallUnexpectedStatus(t *testing.T) {
	agent := startChunkServer(t,
		func(*dns.CallRequest) *codec.Envelope { return codec.Queued("echo", "job-1") },
		func(*dns.ChunkRequest) *codec.Envelope { return codec.Chunked("echo", "sess", 0, 1, false, "") },
	)
	if _, err := agent.Call(context.Background(), "echo", []byte(`{}`)); err == nil {
		t.Fatal("expected an error for an unexpected call status")
	}
}

func TestAgentSetTimeout(t *testing.T) {
	reg := NewRegistry()
	agent := startAgentServer(t, reg)
	agent.SetTimeout(2 * time.Second) // should not panic
}

func TestAgentCallQueryTimeout(t *testing.T) {
	// Point the agent at an unreachable server and expect a timeout error.
	agent := NewAgent("127.0.0.1:1", agentZone)
	agent.SetTimeout(500 * time.Millisecond)
	if _, err := agent.Call(context.Background(), "echo", []byte(`{}`)); err == nil {
		t.Fatal("expected timeout error querying an unreachable server")
	}
}
