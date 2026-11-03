package mcp

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/Crank-Git/mcport53/internal/codec"
	"github.com/Crank-Git/mcport53/internal/dns"
)

func testRegistry(t *testing.T) *Registry {
	t.Helper()
	r := NewRegistry()
	if err := r.AddMCPTool(nil, nil); err == nil {
		t.Error("AddMCPTool(nil) = nil error, want error")
	}
	if err := r.Register(&Tool{
		Name: "echo",
		Call: func(ctx context.Context, args []byte) (*codec.Envelope, error) {
			return codec.OK("echo", codec.TextResult("text/plain", string(args)), 0), nil
		},
	}); err != nil {
		t.Fatalf("Register(echo): %v", err)
	}
	if err := r.Register(&Tool{
		Name:        "schema_tool",
		Description: "has a schema",
		InputSchema: json.RawMessage(`{"type":"object","properties":{"x":{"type":"integer"}}}`),
		Call: func(ctx context.Context, args []byte) (*codec.Envelope, error) {
			return codec.OK("schema_tool", "ok", 0), nil
		},
	}); err != nil {
		t.Fatalf("Register(schema_tool): %v", err)
	}
	return r
}

func TestHandlersWiring(t *testing.T) {
	srv := NewServer(testRegistry(t))
	h := srv.Handlers()
	if h.OnCall == nil || h.OnDiscovery == nil || h.OnSchema == nil || h.OnChunk == nil {
		t.Fatal("Handlers() has nil handlers")
	}
	if h.OnVerify != nil {
		t.Error("OnVerify should be nil before WithVerify")
	}
	srv.WithVerify(func(*dns.CallRequest) error { return nil })
	if srv.Handlers().OnVerify == nil {
		t.Error("OnVerify should be set after WithVerify")
	}
}

func TestOnCall(t *testing.T) {
	srv := NewServer(testRegistry(t))
	env := srv.onCall(&dns.CallRequest{Tool: "echo", Args: []byte("hi")})
	if env.Status != codec.StatusOK {
		t.Fatalf("status = %q, want ok (%+v)", env.Status, env)
	}
	if env.Tool != "echo" {
		t.Errorf("tool = %q, want echo", env.Tool)
	}
	// Unknown tool.
	env = srv.onCall(&dns.CallRequest{Tool: "nope"})
	if env.Status != codec.StatusError || !strings.Contains(env.Error, "unknown tool") {
		t.Errorf("unknown tool envelope = %+v, want error", env)
	}
}

func TestOnCallToolError(t *testing.T) {
	r := NewRegistry()
	_ = r.Register(&Tool{
		Name: "boom",
		Call: func(ctx context.Context, args []byte) (*codec.Envelope, error) {
			return codec.Error("boom", "kaboom"), nil
		},
	})
	srv := NewServer(r)
	env := srv.onCall(&dns.CallRequest{Tool: "boom"})
	if env.Status != codec.StatusError || env.Error != "kaboom" {
		t.Fatalf("envelope = %+v, want error kaboom", env)
	}
}

func TestOnCallToolGoError(t *testing.T) {
	r := NewRegistry()
	_ = r.Register(&Tool{
		Name: "boom",
		Call: func(ctx context.Context, args []byte) (*codec.Envelope, error) {
			return nil, context.DeadlineExceeded
		},
	})
	srv := NewServer(r)
	env := srv.onCall(&dns.CallRequest{Tool: "boom"})
	if env.Status != codec.StatusError {
		t.Fatalf("envelope = %+v, want error", env)
	}
}

func TestOnCallNilEnvelope(t *testing.T) {
	r := NewRegistry()
	_ = r.Register(&Tool{
		Name: "nil",
		Call: func(ctx context.Context, args []byte) (*codec.Envelope, error) {
			return nil, nil
		},
	})
	srv := NewServer(r)
	env := srv.onCall(&dns.CallRequest{Tool: "nil"})
	if env.Status != codec.StatusError || !strings.Contains(env.Error, "nil envelope") {
		t.Fatalf("nil envelope = %+v, want error mentioning nil envelope", env)
	}
}

func TestOnCallNonOKStatus(t *testing.T) {
	r := NewRegistry()
	// A queued envelope is returned as-is without chunking.
	_ = r.Register(&Tool{
		Name: "queued",
		Call: func(ctx context.Context, args []byte) (*codec.Envelope, error) {
			return codec.Queued("queued", "job-1"), nil
		},
	})
	srv := NewServer(r)
	env := srv.onCall(&dns.CallRequest{Tool: "queued"})
	if env.Status != codec.StatusQueued {
		t.Fatalf("status = %q, want queued", env.Status)
	}
}

func TestChunkIfNeededSmall(t *testing.T) {
	srv := NewServer(testRegistry(t))
	data := []byte(`{"result":"small"}`)
	env := srv.chunkIfNeeded("tool", data, 5)
	if env.Status != codec.StatusOK {
		t.Fatalf("status = %q, want ok", env.Status)
	}
	if env.Result != string(data) {
		t.Errorf("result = %q, want %q", env.Result, data)
	}
	if env.Ms != 5 {
		t.Errorf("ms = %d, want 5", env.Ms)
	}
}

func TestChunkIfNeededLarge(t *testing.T) {
	srv := NewServer(testRegistry(t))
	data := []byte(strings.Repeat("x", codec.MaxEnvelopeTXT+50))
	env := srv.chunkIfNeeded("tool", data, 0)
	if env.Status != codec.StatusChunked {
		t.Fatalf("status = %q, want chunked", env.Status)
	}
	if env.Total == 0 {
		t.Error("Total = 0, want > 0")
	}
	if !env.More {
		t.Error("More = false on first chunk")
	}
	if srv.results.Len() != 1 {
		t.Errorf("store Len = %d, want 1", srv.results.Len())
	}
}

func TestOnChunk(t *testing.T) {
	srv := NewServer(testRegistry(t))
	data := []byte(strings.Repeat("x", codec.MaxEnvelopeTXT+50))
	env := srv.chunkIfNeeded("tool", data, 0)
	session := env.Session

	// Fetch the final chunk.
	last := srv.onChunk(&dns.ChunkRequest{Session: session, Chunk: env.Total - 1})
	if last.Status != codec.StatusChunked {
		t.Fatalf("chunk status = %q, want chunked", last.Status)
	}
	if last.More {
		t.Error("final chunk More = true, want false")
	}
	// Unknown session.
	unknown := srv.onChunk(&dns.ChunkRequest{Session: "missing", Chunk: 0})
	if unknown.Status != codec.StatusError {
		t.Errorf("unknown chunk status = %q, want error", unknown.Status)
	}
}

func TestOnDiscovery(t *testing.T) {
	srv := NewServer(testRegistry(t))
	doc := srv.onDiscovery()
	if doc.Version != 1 {
		t.Errorf("version = %d, want 1", doc.Version)
	}
	if len(doc.Tools) != 2 {
		t.Fatalf("tools = %d, want 2", len(doc.Tools))
	}
	for _, tool := range doc.Tools {
		if tool.Name == "" {
			t.Error("discovery tool with empty name")
		}
	}
}

func TestOnSchema(t *testing.T) {
	srv := NewServer(testRegistry(t))
	env := srv.onSchema("schema_tool")
	if env.Status != codec.StatusOK {
		t.Fatalf("status = %q, want ok", env.Status)
	}
	if !strings.Contains(env.Result, "integer") {
		t.Errorf("schema result = %q, want to contain 'integer'", env.Result)
	}
	// Unknown tool.
	env = srv.onSchema("nope")
	if env.Status != codec.StatusError {
		t.Errorf("unknown schema status = %q, want error", env.Status)
	}
}

func TestOnSchemaMissingInputSchema(t *testing.T) {
	r := NewRegistry()
	_ = r.Register(&Tool{Name: "noschema"})
	srv := NewServer(r)
	env := srv.onSchema("noschema")
	if env.Result != `{"type":"object"}` {
		t.Errorf("schema = %q, want default object schema", env.Result)
	}
}
