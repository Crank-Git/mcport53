// Package mcp adapts Model Context Protocol (MCP) tools to the MCPort53 DNS
// transport (protocol §11). A Registry stores named tools and adapts them to the
// dns package's Handlers, while an Agent provides a high-level client that
// assembles chunked and long-running results.
package mcp

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/Crank-Git/mcport53/internal/codec"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// reservedToolNames are tool names that collide with the DNS structural labels
// (§2). A tool name must be a single label and must not equal one of these.
var reservedToolNames = map[string]bool{
	"call":   true,
	"signed": true,
	"schema": true,
	"chunk":  true,
	"job":    true,
}

// Tool is a registered callable tool. Call receives the raw JSON argument bytes
// decoded from the call name (§3) and returns the result envelope to place in
// the TXT response, or an error for a protocol-level failure.
type Tool struct {
	Name        string
	Description string
	InputSchema json.RawMessage
	Call        func(ctx context.Context, args []byte) (*codec.Envelope, error)
}

// Registry stores tools by name and adapts them to dns.Handlers. It is safe for
// concurrent use.
type Registry struct {
	mu    sync.RWMutex
	tools map[string]*Tool
}

// NewRegistry builds an empty Registry.
func NewRegistry() *Registry {
	return &Registry{tools: make(map[string]*Tool)}
}

// Register adds or replaces a tool. It rejects nil tools, empty names, names
// that collide with a reserved structural label, and duplicate registrations.
// Tool names are compared case-insensitively (DNS labels are case-insensitive).
func (r *Registry) Register(t *Tool) error {
	if t == nil {
		return errors.New("mcp: nil tool")
	}
	name := strings.TrimSpace(t.Name)
	if name == "" {
		return errors.New("mcp: tool name required")
	}
	lower := strings.ToLower(name)
	if reservedToolNames[lower] {
		return fmt.Errorf("mcp: tool name %q collides with a reserved structural label", name)
	}

	r.mu.Lock()
	defer r.mu.Unlock()
	if _, exists := r.tools[lower]; exists {
		return fmt.Errorf("mcp: tool %q already registered", name)
	}
	t.Name = lower
	r.tools[lower] = t
	return nil
}

// Tool returns the registered tool by name (case-insensitive).
func (r *Registry) Tool(name string) (*Tool, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	t, ok := r.tools[strings.ToLower(strings.TrimSpace(name))]
	return t, ok
}

// Tools returns every registered tool sorted by name.
func (r *Registry) Tools() []*Tool {
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := make([]*Tool, 0, len(r.tools))
	for _, t := range r.tools {
		out = append(out, t)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

// Len returns the number of registered tools.
func (r *Registry) Len() int {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return len(r.tools)
}

// AddMCPTool adapts an MCP SDK tool and handler into a registry Tool and
// registers it. It is the bridge between the MCP SDK tool model and the DNS
// transport.
func (r *Registry) AddMCPTool(t *mcp.Tool, h mcp.ToolHandler) error {
	if t == nil {
		return errors.New("mcp: nil tool")
	}
	return r.Register(ToolFromMCP(t, h))
}

// ToolFromMCP adapts an MCP SDK tool and handler into a registry Tool. The
// handler receives the raw JSON arguments decoded from the call name and returns
// the serialized MCP result.
func ToolFromMCP(t *mcp.Tool, h mcp.ToolHandler) *Tool {
	name := strings.ToLower(strings.TrimSpace(t.Name))
	if name == "" {
		name = "tool"
	}
	return &Tool{
		Name:        name,
		Description: t.Description,
		InputSchema: inputSchema(t.InputSchema),
		Call: func(ctx context.Context, args []byte) (*codec.Envelope, error) {
			return callMCPTool(ctx, strings.ToLower(name), h, args)
		},
	}
}

// inputSchema normalizes an MCP tool's input schema to a json.RawMessage,
// defaulting to an empty object schema when unset.
func inputSchema(schema any) json.RawMessage {
	switch v := schema.(type) {
	case json.RawMessage:
		if len(v) > 0 {
			return v
		}
	case []byte:
		if len(v) > 0 {
			return json.RawMessage(v)
		}
	}
	if schema != nil {
		if b, err := json.Marshal(schema); err == nil && len(b) > 0 {
			return json.RawMessage(b)
		}
	}
	return json.RawMessage(`{"type":"object"}`)
}

// callMCPTool invokes an MCP SDK handler and converts the result into a result
// envelope. A Go error from the handler is a protocol error; a result flagged
// isError is surfaced through the envelope's error status so the caller (and the
// originating LLM) can observe it.
func callMCPTool(ctx context.Context, name string, h mcp.ToolHandler, args []byte) (*codec.Envelope, error) {
	start := time.Now()
	req := &mcp.CallToolRequest{
		Params: &mcp.CallToolParamsRaw{Name: name, Arguments: args},
	}
	res, err := h(ctx, req)
	ms := time.Since(start).Milliseconds()
	if err != nil {
		return nil, fmt.Errorf("mcp: tool %s: %w", name, err)
	}
	if res == nil {
		return nil, fmt.Errorf("mcp: tool %s returned a nil result", name)
	}
	// The result is wrapped as a JSON result envelope so clients can parse it
	// with codec.ParseResultEnvelope (§5).
	if res.IsError {
		msg := toolText(res)
		e := codec.Error(name, msg)
		e.Result = msg
		return e, nil
	}
	re, err := codec.JSONResult(res)
	if err != nil {
		return nil, fmt.Errorf("mcp: marshaling result for %s: %w", name, err)
	}
	return codec.OK(name, re, int(ms)), nil
}

// toolText concatenates the textual content of a CallToolResult for use as an
// error message.
func toolText(res *mcp.CallToolResult) string {
	var parts []string
	for _, c := range res.Content {
		if tc, ok := c.(*mcp.TextContent); ok {
			parts = append(parts, tc.Text)
		}
	}
	if len(parts) == 0 {
		return "mcp: tool error"
	}
	return strings.Join(parts, " ")
}
