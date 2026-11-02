package mcp

import (
	"context"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"sync"

	"github.com/Crank-Git/mcport53/internal/auth"
	"github.com/Crank-Git/mcport53/internal/codec"
	"github.com/Crank-Git/mcport53/internal/dns"
)

// Server adapts a tool Registry into the dns package's Handlers, wiring discovery,
// schema, call, and result-chunk delivery. It is the glue a dns.Server needs to
// expose MCP tools over DNS.
type Server struct {
	registry     *Registry
	results      *ResultStore
	verify       func(*dns.CallRequest) error
	keys         *auth.KeyRegistry // optional per-tool HMAC keys (protocol §8)
	discoveryKey []byte            // optional key signing discovery documents (protocol §8)
	compress     bool              // gzip large results into a single envelope (protocol §4.4)
	useCursor    bool              // hand out opaque pagination cursors instead of fixed indices (protocol §4.4)
	cursorMu     sync.Mutex
	cursorNS     map[string]string // session -> opaque cursor nonce
}

// NewServer builds a Server for the given registry with a fresh result store.
func NewServer(registry *Registry) *Server {
	return &Server{registry: registry, results: NewResultStore()}
}

// WithVerify sets the optional call-verification hook (protocol §7). A non-nil
// hook is invoked for every call before it runs; returning an error rejects the
// call. It is ignored when WithKeys has installed per-tool verification.
func (s *Server) WithVerify(fn func(*dns.CallRequest) error) *Server {
	s.verify = fn
	return s
}

// WithKeys installs per-tool HMAC keys (protocol §8). Calls are verified with
// the key registered for the called tool, falling back to the registry's default
// key; unsigned calls and signatures made with the wrong key are rejected, and a
// replay guard rejects reused nonces.
func (s *Server) WithKeys(reg *auth.KeyRegistry) *Server {
	s.keys = reg
	return s
}

// WithDiscoveryKey makes the server sign every discovery document with key
// (protocol §8). Clients holding the same key can verify the document's
// authenticity, which is what makes delegated discovery trustworthy.
func (s *Server) WithDiscoveryKey(key []byte) *Server {
	s.discoveryKey = key
	return s
}

// WithCompression makes the server gzip large results into a single envelope
// (protocol §4.4) instead of splitting them into fixed chunks. The client
// decompresses transparently, so this is invisible apart from fewer queries.
func (s *Server) WithCompression() *Server {
	s.compress = true
	return s
}

// WithCursorPagination makes the server hand out opaque pagination cursors with
// each result chunk (protocol §4.4). The client follows the cursor instead of
// requesting fixed chunk indices, which suits streaming producers that decide
// chunk boundaries on the fly.
func (s *Server) WithCursorPagination() *Server {
	s.useCursor = true
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
	switch {
	case s.keys != nil:
		h.OnVerify = HMACVerifyKeys(s.keys)
	case s.verify != nil:
		h.OnVerify = s.verify
	}
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
//
// When compression is enabled and a large result gzip-shrinks into a single
// TXT-sized envelope (protocol §4.4), that compressed envelope is returned
// instead of fixed chunks.
func (s *Server) chunkIfNeeded(tool string, data []byte, ms int) *codec.Envelope {
	if len(data) <= codec.MaxEnvelopeTXT {
		e := codec.NewEnvelope(codec.StatusOK)
		e.Tool = tool
		e.Result = string(data)
		e.Ms = ms
		return e
	}
	if s.compress {
		if enc, err := codec.CompressResult(codec.CompressionGzip, data); err == nil {
			e := codec.NewEnvelope(codec.StatusOK)
			e.Tool = tool
			e.Result = enc
			e.Compression = string(codec.CompressionGzip)
			e.Ms = ms
			if b, err := e.Marshal(); err == nil && len(b) <= codec.MaxEnvelopeTXT {
				return e
			}
		}
	}
	session := s.results.Put(data)
	pieces := codec.ChunkPayload(data, codec.ChunkSize)
	total := len(pieces)
	encoded := base64.StdEncoding.EncodeToString(pieces[0])
	e := codec.Chunked(tool, session, 0, total, true, encoded)
	e.Ms = ms
	// Flag cursor mode on the chunk-0 envelope so the client follows cursors
	// rather than fixed indices (protocol §4.4).
	if s.useCursor {
		e.Cursor = s.nextCursor(session, 0, total)
	}
	return e
}

// onChunk serves a single result chunk from the store (protocol §2.4 / §4.4).
//
// When cursor pagination is enabled the response carries an opaque cursor that
// the client presents to fetch the next chunk; otherwise the client fetches by
// fixed index.
func (s *Server) onChunk(req *dns.ChunkRequest) *codec.Envelope {
	// When the caller fetches by cursor, decode the opaque token into a chunk
	// index before looking the chunk up (protocol §4.4).
	if s.useCursor && req.Cursor != "" {
		idx, ok := s.chunkFromCursor(req.Session, req.Cursor)
		if !ok {
			return codec.Error("", "mcp: invalid cursor")
		}
		req.Chunk = idx
	}
	data, total, more, ok := s.results.Get(req.Session, req.Chunk)
	if !ok {
		return codec.Error("", "mcp: unknown session or chunk")
	}
	encoded := base64.StdEncoding.EncodeToString(data)
	e := codec.Chunked("", req.Session, req.Chunk, total, more, encoded)
	if s.useCursor {
		e.Cursor = s.nextCursor(req.Session, req.Chunk, total)
	}
	return e
}

// nextCursor returns an opaque cursor pointing at the chunk following idx, or
// "" at the final chunk. The cursor mixes a per-session nonce with the next
// index so callers cannot guess it (protocol §4.4).
func (s *Server) nextCursor(session string, idx, total int) string {
	if idx+1 >= total {
		return ""
	}
	s.cursorMu.Lock()
	defer s.cursorMu.Unlock()
	if s.cursorNS == nil {
		s.cursorNS = make(map[string]string)
	}
	ns := s.cursorNS[session]
	if ns == "" {
		var err error
		if ns, err = codec.RandomHex(8); err != nil {
			return ""
		}
		s.cursorNS[session] = ns
	}
	return encodeCursor(ns, idx+1)
}

// chunkFromCursor decodes an opaque cursor into a chunk index, verifying that
// it was issued for session. It returns ok=false for a forged or malformed
// cursor.
func (s *Server) chunkFromCursor(session, cursor string) (int, bool) {
	s.cursorMu.Lock()
	defer s.cursorMu.Unlock()
	ns := s.cursorNS[session]
	if ns == "" {
		return 0, false
	}
	return decodeCursor(ns, cursor)
}

// decodeCursor returns the chunk index encoded in cursor, verifying it belongs
// to the session identified by its nonce ns. It returns ok=false for a forged
// or malformed cursor.
func decodeCursor(ns, cursor string) (int, bool) {
	b, err := codec.DecodeBase32(cursor)
	if err != nil || len(b) < len(ns)+4 {
		return 0, false
	}
	if string(b[:len(ns)]) != ns {
		return 0, false
	}
	return int(binary.BigEndian.Uint32(b[len(ns):])), true
}

// encodeCursor encodes (sessionNonce, index) into an opaque base32 cursor.
func encodeCursor(sessionNonce string, idx int) string {
	b := make([]byte, len(sessionNonce)+4)
	copy(b, sessionNonce)
	binary.BigEndian.PutUint32(b[len(sessionNonce):], uint32(idx))
	return codec.EncodeBase32(b)
}

// onDiscovery builds the discovery document (§2.1), signing it with the
// discovery key when one is configured so clients can verify its authenticity
// (protocol §8).
func (s *Server) onDiscovery() *dns.DiscoveryResponse {
	doc := &dns.DiscoveryResponse{Version: 1}
	for _, t := range s.registry.Tools() {
		doc.Tools = append(doc.Tools, dns.Tool{
			Name:        t.Name,
			Description: t.Description,
			InputSchema: t.InputSchema,
		})
	}
	if s.discoveryKey != nil {
		if b, err := json.Marshal(doc); err == nil {
			doc.Sig = auth.Sign(s.discoveryKey, "discovery", "", b, 0)
		}
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
