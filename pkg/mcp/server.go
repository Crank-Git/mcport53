package mcp

import (
	"context"
	"crypto/tls"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"time"

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
	keys         *auth.KeyRegistry            // optional per-tool HMAC keys (protocol §7.3)
	keyVerify    func(*dns.CallRequest) error // verifier for keys; built once so every Handlers() shares one replay guard
	discoveryKey []byte                       // optional key signing discovery documents (protocol §7.3)
	compress     bool                         // gzip large results into a single envelope (protocol §4.4)
	useCursor    bool                         // hand out opaque pagination cursors instead of fixed indices (protocol §4.4)
	tsigName     string                       // optional TSIG key name for transport integrity (protocol §8)
	tsigSecret   []byte                       // optional TSIG shared secret (protocol §8)
	tls          *tls.Config                  // optional DoT certificate config (protocol §8)
	callTimeout  time.Duration                // per-call tool deadline; DefaultCallTimeout when zero
	inlineBudget time.Duration                // time before a call is answered "queued"; DefaultInlineBudget when zero
	jobs         *jobStore                    // calls that outlived the inline budget (protocol §4.3)
}

// DefaultCallTimeout bounds how long a tool may run for one call.
const DefaultCallTimeout = 30 * time.Second

// NewServer builds a Server for the given registry with a fresh result store.
func NewServer(registry *Registry) *Server {
	return &Server{registry: registry, results: NewResultStore(), jobs: newJobStore(0, 0)}
}

// WithCallTimeout sets the deadline for each tool call (default
// DefaultCallTimeout). The tool's context is cancelled at the deadline and the
// call returns an error envelope.
func (s *Server) WithCallTimeout(d time.Duration) *Server {
	s.callTimeout = d
	return s
}

// WithResultStore replaces the store that holds large results while clients
// fetch their chunks, for example one built with NewResultStoreWithLimits.
func (s *Server) WithResultStore(store *ResultStore) *Server {
	s.results = store
	return s
}

// WithVerify sets the optional call-verification hook (protocol §7). A non-nil
// hook is invoked for every call before it runs; returning an error rejects the
// call. It is ignored when WithKeys has installed per-tool verification.
func (s *Server) WithVerify(fn func(*dns.CallRequest) error) *Server {
	s.verify = fn
	return s
}

// WithKeys installs per-tool HMAC keys (protocol §7.3). Calls are verified with
// the key registered for the called tool, falling back to the registry's default
// key; unsigned calls and signatures made with the wrong key are rejected, and a
// replay guard rejects reused nonces.
func (s *Server) WithKeys(reg *auth.KeyRegistry) *Server {
	s.keys = reg
	s.keyVerify = HMACVerifyKeys(reg)
	return s
}

// WithDiscoveryKey makes the server sign every discovery document with key
// (protocol §7.3). Clients holding the same key can verify the document's
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

// WithTSIG requires every query to carry a TSIG signature over secret (protocol
// §8). The server verifies each query and signs its responses with the same
// key, authenticating the exchange at the transport layer in addition to any
// application HMAC (protocol §7).
func (s *Server) WithTSIG(name string, secret []byte) *Server {
	s.tsigName = name
	s.tsigSecret = secret
	return s
}

// WithTLS serves the server over DNS-over-TLS (RFC 7858) with cfg (protocol §8).
// The *tls.Config must carry a certificate and private key.
func (s *Server) WithTLS(cfg *tls.Config) *Server {
	s.tls = cfg
	return s
}

// ApplyTransport installs the configured TLS and TSIG settings on the dns.Server
// (protocol §8). It must be called when building the server:
//
//	dnsSrv := dns.NewServer(zone, &server.Handlers())
//	dnsSrv = server.ApplyTransport(dnsSrv)
//
// It is a no-op for a setting that was not configured.
func (s *Server) ApplyTransport(dnsSrv *dns.Server) *dns.Server {
	if s.tls != nil {
		dnsSrv = dnsSrv.WithTLS(s.tls)
	}
	if s.tsigName != "" {
		dnsSrv = dnsSrv.WithTSIG(s.tsigName, s.tsigSecret)
	}
	return dnsSrv
}

// Handlers returns the dns.Handlers that expose the registry over DNS.
func (s *Server) Handlers() dns.Handlers {
	h := dns.Handlers{
		OnCall:      s.onCall,
		OnDiscovery: s.onDiscovery,
		OnSchema:    s.onSchema,
		OnChunk:     s.onChunk,
		OnJob:       s.onJob,
	}
	switch {
	case s.keys != nil:
		h.OnVerify = s.keyVerify
	case s.verify != nil:
		h.OnVerify = s.verify
	}
	return h
}

// onCall dispatches a tool call, chunking the result when it exceeds the TXT
// target size (protocol §4.2). A call still running after the inline budget
// is answered "queued" with a job id and continues in the background
// (protocol §4.3).
func (s *Server) onCall(req *dns.CallRequest) *codec.Envelope {
	tool, ok := s.registry.Tool(req.Tool)
	if !ok {
		return codec.Error(req.Tool, "mcp: unknown tool")
	}
	result := make(chan *codec.Envelope, 1)
	go func() { result <- s.completeCall(req.Tool, tool, req.Args) }()

	budget := s.inlineBudget
	if budget <= 0 {
		budget = DefaultInlineBudget
	}
	timer := time.NewTimer(budget)
	defer timer.Stop()
	select {
	case e := <-result:
		return e
	case <-timer.C:
	}
	id, err := s.jobs.start(req.Tool, result)
	if err != nil {
		// No room for another job: answer when the call finishes.
		return <-result
	}
	return codec.Queued(req.Tool, id)
}

// completeCall runs tool and turns its outcome into the call's answer.
func (s *Server) completeCall(name string, tool *Tool, args []byte) *codec.Envelope {
	env, err := s.runTool(tool, args)
	if err != nil {
		return codec.Error(name, err.Error())
	}
	if env == nil {
		return codec.Error(name, "mcp: tool returned a nil envelope")
	}
	if env.Status != codec.StatusOK {
		return env
	}
	return s.chunkIfNeeded(name, []byte(env.Result), env.Ms)
}

// errToolTimeout is returned when a tool exceeds the call timeout.
var errToolTimeout = errors.New("mcp: tool timed out")

// runTool runs tool under the call timeout. The tool runs on its own goroutine
// so the DNS handler can answer at the deadline even if the tool ignores its
// context; a panic in the tool is recovered there and reported as an error,
// since the DNS server's recover does not cover other goroutines.
func (s *Server) runTool(tool *Tool, args []byte) (*codec.Envelope, error) {
	d := s.callTimeout
	if d <= 0 {
		d = DefaultCallTimeout
	}
	ctx, cancel := context.WithTimeout(context.Background(), d)
	defer cancel()

	type outcome struct {
		env *codec.Envelope
		err error
	}
	done := make(chan outcome, 1) // buffered: a late tool must not block forever
	go func() {
		defer func() {
			if v := recover(); v != nil {
				done <- outcome{err: fmt.Errorf("mcp: tool %s panicked: %v", tool.Name, v)}
			}
		}()
		env, err := tool.Call(ctx, args)
		done <- outcome{env, err}
	}()

	select {
	case o := <-done:
		return o.env, o.err
	case <-ctx.Done():
		return nil, errToolTimeout
	}
}

// chunkIfNeeded returns the result in a single envelope when it fits
// (codec.MaxEnvelopeTXT, measured on the marshaled envelope), otherwise it
// stores the payload and returns the first chunked envelope.
//
// When compression is enabled the payload is gzipped first (if that makes it
// smaller), and it is the compressed bytes that are sent whole or chunked
// (protocol §4.4). A chunked result carries the compression marker on its
// first envelope; the client decompresses after assembly.
func (s *Server) chunkIfNeeded(tool string, data []byte, ms int) *codec.Envelope {
	single := func(result, compression string) *codec.Envelope {
		e := codec.OK(tool, result, ms)
		e.Compression = compression
		if b, err := e.Marshal(); err == nil && len(b) <= codec.MaxEnvelopeTXT {
			return e
		}
		return nil
	}
	if e := single(string(data), ""); e != nil {
		return e
	}

	payload, compression := data, ""
	if s.compress {
		if c, err := codec.CompressorFor(codec.CompressionGzip); err == nil {
			if z, err := c.Compress(data); err == nil && len(z) < len(data) {
				payload, compression = z, string(codec.CompressionGzip)
				if e := single(base64.StdEncoding.EncodeToString(z), compression); e != nil {
					return e
				}
			}
		}
	}

	session, err := s.results.Put(payload)
	if err != nil {
		return codec.Error(tool, err.Error())
	}
	pieces := codec.ChunkPayload(payload, codec.ChunkSize)
	total := len(pieces)
	e := codec.Chunked(tool, session, 0, total, total > 1, base64.StdEncoding.EncodeToString(pieces[0]))
	e.Ms = ms
	e.Compression = compression
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
	ns, ok := s.results.cursorNonce(session, func() (string, error) { return codec.RandomHex(8) })
	if !ok {
		return ""
	}
	return encodeCursor(ns, idx+1)
}

// chunkFromCursor decodes an opaque cursor into a chunk index, verifying that
// it was issued for session. It returns ok=false for a forged or malformed
// cursor.
func (s *Server) chunkFromCursor(session, cursor string) (int, bool) {
	ns, ok := s.results.cursorNonce(session, nil)
	if !ok {
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
// (protocol §7.3).
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
