package mcp

import (
	"context"
	"encoding/base64"
	"encoding/json"

	"github.com/Crank-Git/mcport53/internal/codec"
	"github.com/Crank-Git/mcport53/internal/dns"
)

// Server adapts a tool Registry into the dns package's Handlers, wiring discovery,
// schema, call, and result-chunk delivery. It is the glue a dns.Server needs to
// expose MCP tools over DNS.
type Server struct {
	registry *Registry
	results  *ResultStore
	verify   func(*dns.CallRequest) error
}

// NewServer builds a Server for the given registry with a fresh result store.
func NewServer(registry *Registry) *Server {
	return &Server{registry: registry, results: NewResultStore()}
}

// WithVerify sets the optional call-verification hook (protocol §7). A non-nil
// hook is invoked for every call before it runs; returning an error rejects the
// call.
func (s *Server) WithVerify(fn func(*dns.CallRequest) error) *Server {
	s.verify = fn
	return s
}

// Handlers returns the dns.Handlers that expose the registry over DNS.
func (s *Server) Handlers() dns.Handlers {
	h := dns.Handlers{
		OnCall:      s.onCall,
		OnDiscovery: s.onDiscovery,
		OnSchema:    s.onSchema,
		OnChunk:     s.onChunk,
	}
	h.OnVerify = s.verify
	return h
}

// onCall dispatches a tool call, chunking the result when it exceeds the TXT
// target size (protocol §4.2).
func (s *Server) onCall(req *dns.CallRequest) *codec.Envelope {
	tool, ok := s.registry.Tool(req.Tool)
	if !ok {
		return codec.Error(req.Tool, "mcp: unknown tool")
	}
	env, err := tool.Call(context.Background(), req.Args)
	if err != nil {
		return codec.Error(req.Tool, err.Error())
	}
	if env == nil {
		return codec.Error(req.Tool, "mcp: tool returned a nil envelope")
	}
	if env.Status != codec.StatusOK {
		return env
	}
	return s.chunkIfNeeded(req.Tool, []byte(env.Result), env.Ms)
}

// chunkIfNeeded returns the envelope as-is when it fits in one TXT record,
// otherwise it stores the assembled result and returns a chunked envelope.
func (s *Server) chunkIfNeeded(tool string, data []byte, ms int) *codec.Envelope {
	if len(data) <= codec.MaxEnvelopeTXT {
		e := codec.NewEnvelope(codec.StatusOK)
		e.Tool = tool
		e.Result = string(data)
		e.Ms = ms
		return e
	}
	session := s.results.Put(data)
	pieces := codec.ChunkPayload(data, codec.ChunkSize)
	total := len(pieces)
	encoded := base64.StdEncoding.EncodeToString(pieces[0])
	e := codec.Chunked(tool, session, 0, total, true, encoded)
	e.Ms = ms
	return e
}

// onChunk serves a single result chunk from the store (protocol §2.4).
func (s *Server) onChunk(req *dns.ChunkRequest) *codec.Envelope {
	data, total, more, ok := s.results.Get(req.Session, req.Chunk)
	if !ok {
		return codec.Error("", "mcp: unknown session or chunk")
	}
	encoded := base64.StdEncoding.EncodeToString(data)
	return codec.Chunked("", req.Session, req.Chunk, total, more, encoded)
}

// onDiscovery builds the discovery document (§2.1).
func (s *Server) onDiscovery() *dns.DiscoveryResponse {
	doc := &dns.DiscoveryResponse{Version: 1}
	for _, t := range s.registry.Tools() {
		doc.Tools = append(doc.Tools, dns.Tool{
			Name:        t.Name,
			Description: t.Description,
			InputSchema: t.InputSchema,
		})
	}
	return doc
}

// onSchema serves a tool's input schema (§2.2).
func (s *Server) onSchema(tool string) *codec.Envelope {
	t, ok := s.registry.Tool(tool)
	if !ok {
		return codec.Error(tool, "mcp: unknown tool")
	}
	schema := t.InputSchema
	if len(schema) == 0 {
		schema = json.RawMessage(`{"type":"object"}`)
	}
	return codec.OK(tool, string(schema), 0)
}
