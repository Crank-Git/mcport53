package dns

import (
	"crypto/tls"
	"encoding/json"
	"errors"
	"log"
	"net"
	"strings"

	"github.com/Crank-Git/mcport53/internal/codec"
	"github.com/miekg/dns"
)

// Tool is an MCP tool descriptor in the discovery document.
type Tool struct {
	Name        string          `json:"name"`
	Description string          `json:"description,omitempty"`
	InputSchema json.RawMessage `json:"inputSchema,omitempty"`
}

// DiscoveryResponse is the JSON document returned for the _mcp._udp discovery
// query (protocol §2.1).
type DiscoveryResponse struct {
	Version int    `json:"version"`
	Tools   []Tool `json:"tools"`
	// Sig is an optional application-layer signature over the document's content
	// (protocol §8). When present, clients that hold the matching key can verify
	// the document's authenticity and integrity. It is omitted from the signed
	// content itself.
	Sig string `json:"sig,omitempty"`
}

// CallRequest is a decoded tool call received on a DNS query (protocol §2.3).
type CallRequest struct {
	Tool  string
	Args  []byte
	Nonce string
	Sig   string
	Zone  string
	// Caller is the query's source address, for logging and policy. It is not
	// an identity: UDP sources can be spoofed and resolvers share one address,
	// so replay protection keys on the signed nonce, not the caller.
	Caller string
}

// ChunkRequest is a decoded result-chunk query (protocol §2.4 / §4.4).
type ChunkRequest struct {
	Chunk   int // fixed chunk index (protocol §2.4); set when Cursor is empty
	Session string
	Zone    string
	// Cursor is an opaque pagination token (protocol §4.4). When non-empty the
	// caller is fetching by cursor rather than by fixed index.
	Cursor string
}

// Handlers implements the application logic a Server dispatches to. Every field
// is required; a nil handler yields a generic error envelope.
type Handlers struct {
	OnCall      func(req *CallRequest) *codec.Envelope
	OnDiscovery func() *DiscoveryResponse
	OnSchema    func(tool string) *codec.Envelope
	OnChunk     func(req *ChunkRequest) *codec.Envelope
	OnJob       func(job string) *codec.Envelope

	// OnVerify optionally authenticates a call before it is executed (protocol
	// §7). When non-nil it is invoked for every call, including unsigned ones,
	// and must return nil to allow the call. A common implementation verifies
	// an HMAC signature and enforces one-time nonces via auth.ReplayGuard; it
	// should reject unsigned calls (req.Sig == "") unless signing is optional.
	OnVerify func(req *CallRequest) error
}

// Server is an authoritative DNS server for a tool zone.
type Server struct {
	zone       string
	zoneLabels []string
	handlers   Handlers
	srvTarget  string      // SRV target advertised in discovery; defaults to "localhost."
	srvPort    uint16      // SRV port advertised in discovery; defaults to 53
	tsig       *TsigKeys   // optional TSIG keys for transport-layer integrity (protocol §11)
	tls        *tls.Config // optional TLS config; when set, ListenAndServe serves over DoT (protocol §11)
}

// NewServer builds a Server authoritative for zone (e.g. "example." or
// "mcp.example.").
func NewServer(zone string, h *Handlers) *Server {
	z := strings.TrimSuffix(zone, ".")
	return &Server{
		zone:       z,
		zoneLabels: NameToLabels(z),
		handlers:   *h,
		srvTarget:  "localhost.",
		srvPort:    53,
	}
}

// WithDiscovery advertises an SRV record in discovery responses pointing clients
// at target (e.g. "127.0.0.1.") on port.
func (s *Server) WithDiscovery(target string, port uint16) *Server {
	s.srvTarget = strings.TrimSuffix(target, ".") + "."
	s.srvPort = port
	return s
}

// Handler returns a dns.Handler that dispatches requests to ServeDNS.
func (s *Server) Handler() dns.Handler { return s }

// ServeDNS implements dns.Handler. It dispatches a single question by the shape
// of its name under the server's zone (protocol §2).
func (s *Server) ServeDNS(w dns.ResponseWriter, r *dns.Msg) {
	// A handler panic must cost one query, not the process: miekg/dns does not
	// recover panics, so an unrecovered one exits the server.
	defer func() {
		if v := recover(); v != nil {
			log.Printf("dns: recovered panic serving %s: %v", questionName(r), v)
			fail := reply(r)
			fail.Rcode = dns.RcodeServerFailure
			_ = w.WriteMsg(fail)
		}
	}()

	m := new(dns.Msg)
	*m = *reply(r)
	m.Authoritative = true

	// Transport-layer integrity (protocol §11): when TSIG is configured every
	// query must carry a valid signature over the message. A missing or invalid
	// signature is rejected before any handler runs, so TSIG is a true gateway
	// filter rather than an application concern.
	if s.tsig != nil {
		if err := s.verifyTSIG(w, r); err != nil {
			buildTXTResponse(r, m, envelopeTXT(codec.Error("", "dns: "+err.Error())))
			_ = w.WriteMsg(m)
			return
		}
	}

	if len(r.Question) != 1 {
		m.Rcode = dns.RcodeNameError
		_ = w.WriteMsg(m)
		return
	}

	labels := NameToLabels(r.Question[0].Name)
	prefix, ok := s.splitZone(labels)
	if !ok {
		m.Rcode = dns.RcodeNameError
		_ = w.WriteMsg(m)
		return
	}
	caller := callerAddr(w.RemoteAddr())

	switch {
	case isDiscovery(prefix):
		s.serveDiscovery(r, m)
	case isSchema(prefix):
		s.serveSchema(r, m, prefix)
	case isCall(prefix):
		s.serveCall(r, m, labels, caller)
	case isChunk(prefix):
		s.serveChunk(r, m, labels)
	case isJob(prefix):
		s.serveJob(r, m, labels)
	default:
		m.Rcode = dns.RcodeNameError
	}
	// Sign the response with the same TSIG key that authenticated the query
	// (protocol §11), so the client can confirm the answer came from this server
	// and was not tampered with on the wire.
	if s.tsig != nil {
		if t := r.IsTsig(); t != nil {
			m.SetTsig(t.Hdr.Name, s.tsig.Algorithm(), s.tsig.Fudge(), 0)
		}
	}
	_ = w.WriteMsg(m)
}

// WithTSIG requires every query to carry a valid TSIG signature over secret
// (protocol §11). The server verifies each query's signature and signs its
// responses with the same key, so the exchange is authenticated and
// integrity-checked at the transport layer. Queries without a valid signature
// are rejected before any handler runs. TSIG complements (does not replace) the
// application HMAC of protocol §7.
func (s *Server) WithTSIG(name string, secret []byte) *Server {
	if s.tsig == nil {
		s.tsig = NewTsigKeys()
	}
	s.tsig.With(name, secret)
	return s
}

// WithTSIGKeys installs a pre-built set of TSIG keys (protocol §11). It allows a
// server to accept more than one key name.
func (s *Server) WithTSIGKeys(keys *TsigKeys) *Server {
	s.tsig = keys
	return s
}

// WithTLS configures TLS for ListenAndServe, which then serves over
// DNS-over-TLS (RFC 8483) instead of UDP (protocol §11). The supplied
// *tls.Config must carry a certificate and private key.
func (s *Server) WithTLS(cfg *tls.Config) *Server {
	s.tls = cfg
	return s
}

// ListenAndServe starts the server on addr (e.g. "127.0.0.1:53"). It serves over
// UDP by default, or over DNS-over-TLS when WithTLS has configured a TLS cert.
func (s *Server) ListenAndServe(addr string) error {
	dnsSrv := &dns.Server{
		Addr:         addr,
		Net:          "udp",
		Handler:      s,
		TsigProvider: s.tsig.provider(),
	}
	if s.tls != nil {
		dnsSrv.Net = "tcp-tls"
		dnsSrv.TLSConfig = s.tls
	}
	return dnsSrv.ListenAndServe()
}

// splitZone separates the labels under the server's zone from the zone labels
// themselves. It returns the prefix and false if the name is not under the zone.
func (s *Server) splitZone(labels []string) ([]string, bool) {
	zl := s.zoneLabels
	if len(labels) < len(zl) {
		return nil, false
	}
	off := len(labels) - len(zl)
	for i := 0; i < len(zl); i++ {
		if !strings.EqualFold(labels[off+i], zl[i]) {
			return nil, false
		}
	}
	return labels[:off], true
}

func isDiscovery(prefix []string) bool {
	return len(prefix) == 2 &&
		strings.EqualFold(prefix[0], "_mcp") &&
		strings.EqualFold(prefix[1], "_udp")
}

func isSchema(prefix []string) bool {
	return len(prefix) == 2 && strings.EqualFold(prefix[1], "schema")
}

func isCall(prefix []string) bool {
	return hasLabel(prefix, codec.LabelCall)
}

func isChunk(prefix []string) bool {
	return hasLabel(prefix, codec.LabelChunk)
}

func isJob(prefix []string) bool {
	return hasLabel(prefix, codec.LabelJob)
}

func hasLabel(labels []string, want string) bool {
	for _, l := range labels {
		if strings.EqualFold(l, want) {
			return true
		}
	}
	return false
}

// indexOf returns the position of the first label equal (case-insensitively) to
// want, or -1. It is used to locate structural labels such as "chunk".
func indexOf(labels []string, want string) int {
	for i, l := range labels {
		if strings.EqualFold(l, want) {
			return i
		}
	}
	return -1
}

// verifyTSIG enforces transport-layer integrity (protocol §11). It returns nil
// when TSIG is not configured, or when a valid TSIG signature is present. It
// returns an error when a signature is required but absent (badsig) or invalid
// (badsig), so a caller can reject the query.
func (s *Server) verifyTSIG(w dns.ResponseWriter, r *dns.Msg) error {
	if r.IsTsig() == nil {
		return errors.New("query is not signed with the required TSIG key")
	}
	if err := w.TsigStatus(); err != nil {
		return err
	}
	return nil
}

// questionName returns the first question's name for logging, or "" when the
// message has no question.
func questionName(r *dns.Msg) string {
	if r == nil || len(r.Question) == 0 {
		return ""
	}
	return r.Question[0].Name
}

// callerAddr returns the host portion of a remote address, used as the caller
// identity for per-caller replay protection. The ephemeral source port changes
// on every dial, so the identity is the IP alone.
func callerAddr(addr net.Addr) string {
	if addr == nil {
		return ""
	}
	if host, _, err := net.SplitHostPort(addr.String()); err == nil {
		return host
	}
	return addr.String()
}

func (s *Server) serveDiscovery(r, m *dns.Msg) {
	h := s.handlers
	if h.OnDiscovery == nil {
		buildTXTResponse(r, m, `{"version":0,"tools":[]}`)
		return
	}
	doc := h.OnDiscovery()
	b, err := json.Marshal(doc)
	if err != nil {
		buildTXTResponse(r, m, envelopeTXT(codec.Error("discovery", err.Error())))
		return
	}
	buildTXTResponse(r, m, string(b))
	if s.srvTarget != "" {
		name := m.Question[0].Name
		m.Answer = append(m.Answer, &dns.SRV{
			Hdr:    dns.RR_Header{Name: name, Rrtype: dns.TypeSRV, Class: dns.ClassINET, Ttl: 0},
			Target: dns.Fqdn(s.srvTarget),
			Port:   s.srvPort,
		})
	}
}

func (s *Server) serveSchema(r, m *dns.Msg, prefix []string) {
	tool := strings.ToLower(prefix[0])
	h := s.handlers
	if h.OnSchema == nil {
		s.errResp(r, m, tool, "server: no schema handler")
		return
	}
	e := h.OnSchema(tool)
	buildTXTResponse(r, m, envelopeTXT(e))
}

func (s *Server) serveCall(r, m *dns.Msg, labels []string, caller string) {
	cn, err := codec.ParseCallName(labels)
	if err != nil {
		s.errResp(r, m, "", err.Error())
		return
	}
	h := s.handlers
	if h.OnCall == nil {
		s.errResp(r, m, cn.Tool, "server: no call handler")
		return
	}
	req := &CallRequest{Tool: cn.Tool, Args: cn.Args, Nonce: cn.Nonce, Sig: cn.Sig, Zone: s.zone, Caller: caller}
	if h.OnVerify != nil {
		if err := h.OnVerify(req); err != nil {
			s.errResp(r, m, cn.Tool, err.Error())
			return
		}
	}
	e := h.OnCall(req)
	if e == nil {
		s.errResp(r, m, cn.Tool, "call handler returned nil")
		return
	}
	buildTXTResponse(r, m, envelopeTXT(e))
}

func (s *Server) serveChunk(r, m *dns.Msg, labels []string) {
	i := indexOf(labels, codec.LabelChunk)
	if i < 1 {
		s.errResp(r, m, "", "codec: malformed chunk name")
		return
	}
	h := s.handlers
	if h.OnChunk == nil {
		s.errResp(r, m, "", "server: no chunk handler")
		return
	}
	// A numeric label before "chunk" is a fixed index; anything else is an
	// opaque cursor (protocol §4.4). Cursors are base32 (alphabet a-z2-7), so
	// they are never purely numeric and never collide with an index.
	idx, session, _, err := codec.ParseChunkName(labels)
	if err == nil {
		req := &ChunkRequest{Chunk: idx, Session: session, Zone: s.zone}
		e := h.OnChunk(req)
		buildTXTResponse(r, m, envelopeTXT(e))
		return
	}
	cursor, session, _, err := codec.ParseCursorName(labels)
	if err != nil {
		s.errResp(r, m, "", err.Error())
		return
	}
	req := &ChunkRequest{Cursor: cursor, Session: session, Zone: s.zone}
	e := h.OnChunk(req)
	buildTXTResponse(r, m, envelopeTXT(e))
}

func (s *Server) serveJob(r, m *dns.Msg, labels []string) {
	job, _, err := codec.ParseJobName(labels)
	if err != nil {
		s.errResp(r, m, "", err.Error())
		return
	}
	h := s.handlers
	if h.OnJob == nil {
		s.errResp(r, m, "", "server: no job handler")
		return
	}
	e := h.OnJob(job)
	buildTXTResponse(r, m, envelopeTXT(e))
}

func (s *Server) errResp(r, m *dns.Msg, tool, msg string) {
	buildTXTResponse(r, m, envelopeTXT(codec.Error(tool, msg)))
}

// envelopeTXT marshals an envelope into a single TXT string, falling back to an
// error envelope on marshal failure.
func envelopeTXT(e *codec.Envelope) string {
	if e == nil {
		return string(`{"v":1,"status":"error","error":"nil envelope"}`)
	}
	b, err := e.Marshal()
	if err != nil {
		b, _ = json.Marshal(codec.Error("internal", err.Error()))
	}
	return string(b)
}
