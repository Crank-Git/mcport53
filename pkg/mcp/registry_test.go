package mcp

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/Crank-Git/mcport53/internal/codec"
	"github.com/Crank-Git/mcport53/internal/dns"
	sdkmcp "github.com/modelcontextprotocol/go-sdk/mcp"
)

func TestRegisterErrors(t *testing.T) {
	r := NewRegistry()
	if err := r.Register(nil); err == nil {
		t.Error("Register(nil) = nil error, want error")
	}
	if err := r.Register(&Tool{Name: "   "}); err == nil {
		t.Error("Register(whitespace name) = nil error, want error")
	}
	for _, name := range []string{"call", "signed", "schema", "chunk", "job", "CALL", "Chunk"} {
		if err := r.Register(&Tool{Name: name}); err == nil {
			t.Errorf("Register(%q) = nil error, want reserved-name error", name)
		}
	}
	if err := r.Register(&Tool{Name: "echo"}); err != nil {
		t.Fatalf("Register(echo): %v", err)
	}
	if err := r.Register(&Tool{Name: "echo"}); err == nil {
		t.Error("Register(duplicate echo) = nil error, want error")
	}
	if err := r.Register(&Tool{Name: "ECHO"}); err == nil {
		t.Error("Register(ECHO) = nil error, want duplicate error")
	}
}

func TestToolLookup(t *testing.T) {
	r := NewRegistry()
	if err := r.Register(&Tool{Name: "Echo"}); err != nil {
		t.Fatalf("Register: %v", err)
	}
	// Names are case-insensitive and trimmed.
	if _, ok := r.Tool("echo"); !ok {
		t.Error("Tool(echo) not found after registering Echo")
	}
	if _, ok := r.Tool("  ECHO  "); !ok {
		t.Error("Tool('  ECHO  ') not found")
	}
	if _, ok := r.Tool("missing"); ok {
		t.Error("Tool(missing) found, want not found")
	}
}

func TestToolsSorted(t *testing.T) {
	r := NewRegistry()
	for _, n := range []string{"zebra", "alpha", "mango"} {
		if err := r.Register(&Tool{Name: n, Description: n}); err != nil {
			t.Fatalf("Register(%s): %v", n, err)
		}
	}
	got := r.Tools()
	if len(got) != 3 {
		t.Fatalf("Tools() len = %d, want 3", len(got))
	}
	want := []string{"alpha", "mango", "zebra"}
	for i, w := range want {
		if got[i].Name != w {
			t.Errorf("Tools()[%d].Name = %q, want %q", i, got[i].Name, w)
		}
	}
}

func TestLen(t *testing.T) {
	r := NewRegistry()
	if r.Len() != 0 {
		t.Fatalf("empty registry Len = %d, want 0", r.Len())
	}
	_ = r.Register(&Tool{Name: "a"})
	_ = r.Register(&Tool{Name: "b"})
	if r.Len() != 2 {
		t.Fatalf("Len = %d, want 2", r.Len())
	}
}

func TestToolFromMCP(t *testing.T) {
	h := func(ctx context.Context, req *sdkmcp.CallToolRequest) (*sdkmcp.CallToolResult, error) {
		return textResult("hi"), nil
	}
	tool := ToolFromMCP(&sdkmcp.Tool{Name: "Echo", Description: "echo text"}, h)
	if tool.Name != "echo" {
		t.Fatalf("tool.Name = %q, want echo", tool.Name)
	}
	if tool.Description != "echo text" {
		t.Errorf("tool.Description = %q, want echo text", tool.Description)
	}
	if len(tool.InputSchema) == 0 {
		t.Error("tool.InputSchema is empty, want default object schema")
	}
	env, err := tool.Call(context.Background(), nil)
	if err != nil {
		t.Fatalf("tool.Call: %v", err)
	}
	if env.Status != codec.StatusOK {
		t.Fatalf("status = %q, want ok (%+v)", env.Status, env)
	}
}

func TestToolFromMCPDefaultName(t *testing.T) {
	tool := ToolFromMCP(&sdkmcp.Tool{Description: "no name"}, func(ctx context.Context, req *sdkmcp.CallToolRequest) (*sdkmcp.CallToolResult, error) {
		return textResult("ok"), nil
	})
	if tool.Name != "tool" {
		t.Fatalf("tool.Name = %q, want tool", tool.Name)
	}
}

func TestInputSchemaNormalization(t *testing.T) {
	// nil schema -> default object.
	if got := inputSchema(nil); string(got) != `{"type":"object"}` {
		t.Errorf("inputSchema(nil) = %q, want default", got)
	}
	// RawMessage passthrough.
	raw := json.RawMessage(`{"type":"object","properties":{}}`)
	if got := inputSchema(raw); string(got) != string(raw) {
		t.Errorf("inputSchema(RawMessage) = %q, want passthrough", got)
	}
	// Map marshaled.
	if got := inputSchema(map[string]any{"type": "object"}); len(got) == 0 {
		t.Error("inputSchema(map) = empty, want json")
	}
	// Empty RawMessage -> default.
	if got := inputSchema(json.RawMessage(``)); string(got) != `{"type":"object"}` {
		t.Errorf("inputSchema(empty) = %q, want default", got)
	}
	// []byte passthrough (non-empty).
	if got := inputSchema([]byte(`{"type":"object"}`)); string(got) != `{"type":"object"}` {
		t.Errorf("inputSchema([]byte) = %q, want passthrough", got)
	}
}

func TestCallMCPToolErrors(t *testing.T) {
	// Handler returns a Go error.
	errHandler := func(ctx context.Context, req *sdkmcp.CallToolRequest) (*sdkmcp.CallToolResult, error) {
		return nil, errors.New("boom")
	}
	if _, err := callMCPTool(context.Background(), "t", errHandler, nil); err == nil {
		t.Error("callMCPTool(boom) = nil error, want error")
	}
	// Handler returns nil result.
	nilHandler := func(ctx context.Context, req *sdkmcp.CallToolRequest) (*sdkmcp.CallToolResult, error) {
		return nil, nil
	}
	if _, err := callMCPTool(context.Background(), "t", nilHandler, nil); err == nil {
		t.Error("callMCPTool(nil) = nil error, want error")
	}
}

func TestCallMCPToolErrorResult(t *testing.T) {
	handler := func(ctx context.Context, req *sdkmcp.CallToolRequest) (*sdkmcp.CallToolResult, error) {
		return &sdkmcp.CallToolResult{
			Content: []sdkmcp.Content{&sdkmcp.TextContent{Text: "bad input"}},
			IsError: true,
		}, nil
	}
	env, err := callMCPTool(context.Background(), "t", handler, []byte(`{}`))
	if err != nil {
		t.Fatalf("callMCPTool: %v", err)
	}
	if env.Status != codec.StatusError {
		t.Fatalf("status = %q, want error", env.Status)
	}
	if env.Tool != "t" {
		t.Errorf("tool = %q, want t", env.Tool)
	}
	if env.Result == "" {
		t.Error("error envelope has empty result")
	}
}

func TestToolText(t *testing.T) {
	if got := toolText(&sdkmcp.CallToolResult{Content: []sdkmcp.Content{&sdkmcp.TextContent{Text: "a"}, &sdkmcp.TextContent{Text: "b"}}}); got != "a b" {
		t.Errorf("toolText = %q, want 'a b'", got)
	}
	if got := toolText(&sdkmcp.CallToolResult{}); got != "mcp: tool error" {
		t.Errorf("toolText(empty) = %q, want fallback", got)
	}
}

func TestCallHandler(t *testing.T) {
	r := NewRegistry()
	if err := r.AddMCPTool(&sdkmcp.Tool{Name: "echo"}, func(ctx context.Context, req *sdkmcp.CallToolRequest) (*sdkmcp.CallToolResult, error) {
		return textResult("hi"), nil
	}); err != nil {
		t.Fatalf("AddMCPTool: %v", err)
	}
	h := r.callHandler()
	env := h(&dns.CallRequest{Tool: "echo", Args: []byte(`{}`)})
	if env.Status != codec.StatusOK {
		t.Fatalf("status = %q, want ok (%+v)", env.Status, env)
	}
	// Unknown tool.
	env = h(&dns.CallRequest{Tool: "nope"})
	if env.Status != codec.StatusError {
		t.Fatalf("unknown tool status = %q, want error", env.Status)
	}
	// Tool that returns a nil envelope.
	r2 := NewRegistry()
	_ = r2.Register(&Tool{
		Name: "nil",
		Call: func(ctx context.Context, args []byte) (*codec.Envelope, error) {
			return nil, nil
		},
	})
	env = r2.callHandler()(&dns.CallRequest{Tool: "nil"})
	if env.Status != codec.StatusError {
		t.Fatalf("nil envelope status = %q, want error", env.Status)
	}
	// Tool whose Call returns a Go error is surfaced as an error envelope.
	r3 := NewRegistry()
	_ = r3.Register(&Tool{
		Name: "boom",
		Call: func(ctx context.Context, args []byte) (*codec.Envelope, error) {
			return nil, errors.New("kaboom")
		},
	})
	env = r3.callHandler()(&dns.CallRequest{Tool: "boom"})
	if env.Status != codec.StatusError || !strings.Contains(env.Error, "kaboom") {
		t.Fatalf("go-error envelope = %+v, want error mentioning kaboom", env)
	}
}
