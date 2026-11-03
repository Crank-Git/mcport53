package dns

import (
	"crypto/tls"
	"encoding/json"
	"errors"
	"log"
	"net"
	"strings"
	"sync"
	"time"

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
	// (protocol §7.3). When present, clients that hold the matching key can verify
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
	ns         string      // NS/SOA name server host; defaults to ns.<zone>
	tsig       *TsigKeys   // optional TSIG keys for transport-layer integrity (protocol §8)
	tls        *tls.Config // optional TLS config; when set, ListenAndServe serves over DoT (protocol §8)

	calls *callCache // deduplicates retransmitted call queries

	mu      sync.Mutex
	running []*dns.Server // listeners started by ListenAndServe, for Shutdown
}

// EDNS sizes (RFC 6891). The server answers UDP queries within the size the
// requester advertises, or 512 bytes when it advertises none.
const (
	minUDPSize = dns.MinMsgSize // 512: the RFC 1035 UDP limit without EDNS
	maxUDPSize = 4096           // cap on a requester's advertised size
	// EDNSBufferSize is the UDP payload size this implementation advertises
	// (the DNS Flag Day 2020 default, which avoids IP fragmentation).
	EDNSBufferSize = 1232
	// tsigReserve is room kept for the TSIG record that is appended after
	// truncation; a hmac-sha256 TSIG with a short key name is about 100 bytes.
	tsigReserve = 128
)

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
		calls:      newCallCache(0, 0),
	}
}

// WithCallCache sizes the cache that answers retransmitted copies of a call
// query from the first copy's result (defaults DefaultCallCacheEntries and
// DefaultCallCacheTTL). The TTL should cover the replay window.
func (s *Server) WithCallCache(entries int, ttl time.Duration) *Server {
	s.calls = newCallCache(entries, ttl)
	return s
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

	// Transport-layer integrity (protocol §8): when TSIG is configured every
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
		m.Rcode = dns.RcodeFormatError
		_ = w.WriteMsg(m)
		return
	}

	q := r.Question[0]
	// Parse a lowercased copy: resolvers may randomise the case of the name
	// (DNS 0x20) and every label the protocol emits is lowercase. The reply
	// keeps the question as received, so it echoes the resolver's case.
	labels := NameToLabels(strings.ToLower(q.Name))
	prefix, ok := s.splitZone(labels)
	if !ok {
		// Not authoritative for this name (RFC 1035 §4.1.1).
		m.Authoritative = false
		m.Rcode = dns.RcodeRefused
		_ = w.WriteMsg(m)
		return
	}
	caller := callerAddr(w.RemoteAddr())
	wantTXT := q.Qtype == dns.TypeTXT || q.Qtype == dns.TypeANY

	switch {
	case len(prefix) == 0:
		s.serveApex(r, m)
	case isDiscovery(prefix):
		s.serveDiscovery(r, m)
	case !wantTXT:
		// Tool data is carried in TXT only. Any other type is NODATA, and a
		// call is never run for it (RFC 2308 §2.2).
		s.nodata(r, m)
	case isSchema(prefix):
		s.serveSchema(r, m, prefix)
	case isCall(prefix):
		s.serveCall(r, m, labels, caller)
	case isChunk(prefix):
		s.serveChunk(r, m, labels)
	case isJob(prefix):
		s.serveJob(r, m, labels)
	default:
		// Every name under the zone may be an ancestor of a call name, so an
		// unknown shape is an empty non-terminal: NODATA, never NXDOMAIN. A
		// QNAME-minimising resolver walks these names on the way down, and
		// NXDOMAIN would tell it nothing exists below (RFC 8020).
		s.nodata(r, m)
	}
	s.fitResponse(w, r, m)
	// Sign the response with the same TSIG key that authenticated the query
	// (protocol §8), so the client can confirm the answer came from this server
	// and was not tampered with on the wire.
	if s.tsig != nil {
		if t := r.IsTsig(); t != nil {
			m.SetTsig(t.Hdr.Name, s.tsig.Algorithm(), s.tsig.Fudge(), 0)
		}
	}
	_ = w.WriteMsg(m)
}

// fitResponse echoes EDNS0 when the query used it and, over UDP, truncates the
// answer to the requester's advertised size (512 bytes without EDNS), setting
// TC so the requester retries over TCP (RFC 1035 §4.2.1, RFC 6891 §7).
func (s *Server) fitResponse(w dns.ResponseWriter, r, m *dns.Msg) {
	size := minUDPSize
	if opt := r.IsEdns0(); opt != nil {
		m.SetEdns0(EDNSBufferSize, false)
		if n := int(opt.UDPSize()); n > size {
			size = n
		}
	}
	if !isUDP(w) {
		return
	}
	if size > maxUDPSize {
		size = maxUDPSize
	}
	if s.tsig != nil && r.IsTsig() != nil {
		size -= tsigReserve
	}
	m.Truncate(size)
}

// isUDP reports whether w answers over UDP.
func isUDP(w dns.ResponseWriter) bool {
	if a := w.LocalAddr(); a != nil {
		return a.Network() == "udp"
	}
	return false
}

// WithTSIG requires every query to carry a valid TSIG signature over secret
// (protocol §8). The server verifies each query's signature and signs its
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

// WithTSIGKeys installs a pre-built set of TSIG keys (protocol §8). It allows a
// server to accept more than one key name.
func (s *Server) WithTSIGKeys(keys *TsigKeys) *Server {
	s.tsig = keys
	return s
}

// WithTLS configures TLS for ListenAndServe, which then serves over
// DNS-over-TLS (RFC 7858) instead of UDP (protocol §8). The supplied
// *tls.Config must carry a certificate and private key.
func (s *Server) WithTLS(cfg *tls.Config) *Server {
	s.tls = cfg
	return s
}

// ListenAndServe starts the server on addr (e.g. "127.0.0.1:53") and blocks
// until a listener fails or Shutdown is called. It serves UDP and TCP on the
// same address (TCP carries answers too large for UDP), or only DNS-over-TLS
// when WithTLS has configured a certificate.
//
// Sockets are bound before ListenAndServe starts serving, so a bind failure is
// returned without leaving another listener running.
func (s *Server) ListenAndServe(addr string) error {
	var servers []*dns.Server
	closeAll := func() {
		for _, srv := range servers {
			if srv.PacketConn != nil {
				_ = srv.PacketConn.Close()
			}
			if srv.Listener != nil {
				_ = srv.Listener.Close()
			}
		}
	}
	newServer := func() *dns.Server {
		return &dns.Server{Handler: s, TsigProvider: s.tsig.provider()}
	}
	if s.tls != nil {
		l, err := tls.Listen("tcp", addr, s.tls)
		if err != nil {
			return err
		}
		srv := newServer()
		srv.Listener = l
		servers = append(servers, srv)
	} else {
		pc, err := net.ListenPacket("udp", addr)
		if err != nil {
			return err
		}
		udp := newServer()
		udp.PacketConn = pc
		servers = append(servers, udp)
		// Bind TCP to the port UDP actually got (addr may use port 0).
		l, err := net.Listen("tcp", pc.LocalAddr().String())
		if err != nil {
			closeAll()
			return err
		}
		tcp := newServer()
		tcp.Listener = l
		servers = append(servers, tcp)
	}

	errc := make(chan error, len(servers))
	ready := make(chan struct{}, len(servers))
	for _, srv := range servers {
		srv.NotifyStartedFunc = func() { ready <- struct{}{} }
		go func() { errc <- srv.ActivateAndServe() }()
	}
	// Wait until every listener is serving, so Shutdown always reaches them.
	for range servers {
		select {
		case <-ready:
		case err := <-errc:
			closeAll()
			return err
		}
	}
	s.mu.Lock()
	s.running = servers
	s.mu.Unlock()

	err := <-errc // first listener to stop (failure or Shutdown)
	s.Shutdown()
	return err
}

// Addr returns the address ListenAndServe is serving on, or "" before it has
// started. It is useful with an ephemeral port (":0").
func (s *Server) Addr() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, srv := range s.running {
		if srv.PacketConn != nil {
			return srv.PacketConn.LocalAddr().String()
		}
		if srv.Listener != nil {
			return srv.Listener.Addr().String()
		}
	}
	return ""
}

// Shutdown stops every listener started by ListenAndServe.
func (s *Server) Shutdown() {
	s.mu.Lock()
	running := s.running
	s.running = nil
	s.mu.Unlock()
	for _, srv := range running {
		_ = srv.Shutdown()
	}
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

// verifyTSIG enforces transport-layer integrity (protocol §8). It returns nil
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

// zoneFqdn returns the zone apex as a fully-qualified name.
func (s *Server) zoneFqdn() string { return dns.Fqdn(s.zone) }

// soa returns the zone's SOA record. The minimum TTL is 0 so resolvers do not
// cache negative answers: every call name is new, and a cached NODATA would
// only get in the way.
func (s *Server) soa() *dns.SOA {
	return &dns.SOA{
		Hdr:     dns.RR_Header{Name: s.zoneFqdn(), Rrtype: dns.TypeSOA, Class: dns.ClassINET, Ttl: 0},
		Ns:      s.nameserver(),
		Mbox:    dns.Fqdn("hostmaster." + s.zone),
		Serial:  1,
		Refresh: 3600,
		Retry:   600,
		Expire:  86400,
		Minttl:  0,
	}
}

// nameserver is the NS target for the apex: the name set with WithNameserver,
// or ns.<zone>.
func (s *Server) nameserver() string {
	if s.ns != "" {
		return s.ns
	}
	return dns.Fqdn("ns." + s.zone)
}

// WithNameserver sets the host name the zone's NS and SOA records name. It
// should match the NS records that delegate the zone in its parent.
func (s *Server) WithNameserver(host string) *Server {
	s.ns = dns.Fqdn(host)
	return s
}

// nodata answers NOERROR with no records and the SOA in the authority
// section (RFC 2308).
func (s *Server) nodata(r, m *dns.Msg) {
	buildEmptyResponse(r, m)
	m.Ns = append(m.Ns, s.soa())
}

// serveApex answers SOA and NS at the zone apex, and NODATA for other types.
func (s *Server) serveApex(r, m *dns.Msg) {
	buildEmptyResponse(r, m)
	switch r.Question[0].Qtype {
	case dns.TypeSOA:
		m.Answer = append(m.Answer, s.soa())
	case dns.TypeNS:
		m.Answer = append(m.Answer, &dns.NS{
			Hdr: dns.RR_Header{Name: s.zoneFqdn(), Rrtype: dns.TypeNS, Class: dns.ClassINET, Ttl: 0},
			Ns:  s.nameserver(),
		})
	case dns.TypeANY:
		m.Answer = append(m.Answer, s.soa())
	default:
		m.Ns = append(m.Ns, s.soa())
	}
}

// serveDiscovery answers the discovery name (protocol §2.1): the document as
// TXT, the SRV record as SRV, both for ANY, and NODATA for other types.
func (s *Server) serveDiscovery(r, m *dns.Msg) {
	qt := r.Question[0].Qtype
	if qt != dns.TypeTXT && qt != dns.TypeSRV && qt != dns.TypeANY {
		s.nodata(r, m)
		return
	}
	if qt == dns.TypeSRV {
		buildEmptyResponse(r, m)
		s.appendSRV(m)
		return
	}
	s.serveDiscoveryTXT(r, m)
	if qt == dns.TypeANY {
		s.appendSRV(m)
	}
}

func (s *Server) appendSRV(m *dns.Msg) {
	if s.srvTarget == "" {
		return
	}
	m.Answer = append(m.Answer, &dns.SRV{
		Hdr:    dns.RR_Header{Name: m.Question[0].Name, Rrtype: dns.TypeSRV, Class: dns.ClassINET, Ttl: 0},
		Target: dns.Fqdn(s.srvTarget),
		Port:   s.srvPort,
	})
}

func (s *Server) serveDiscoveryTXT(r, m *dns.Msg) {
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

// serveCall answers a call query. Copies of the same call name (resolver
// retransmissions) are answered from the first copy's result; see callCache.
func (s *Server) serveCall(r, m *dns.Msg, labels []string, caller string) {
	key := strings.Join(labels, ".")
	e, leader := s.calls.begin(key)
	if !leader {
		txt, ok := s.calls.wait(e)
		if !ok {
			txt = envelopeTXT(codec.Error("", "dns: duplicate call did not complete"))
		}
		buildTXTResponse(r, m, txt)
		return
	}
	if e == nil { // cache full of in-flight calls: run uncached
		s.runCall(r, m, labels, caller)
		return
	}
	finished := false
	defer func() {
		if !finished {
			s.calls.abort(e) // the call panicked: release waiters, let a copy retry
		}
	}()
	txt := s.runCall(r, m, labels, caller)
	s.calls.finish(e, txt)
	finished = true
}

// runCall parses, verifies and runs a call, writes the answer into m, and
// returns the envelope text it answered with.
func (s *Server) runCall(r, m *dns.Msg, labels []string, caller string) string {
	txt := s.callTXT(labels, caller)
	buildTXTResponse(r, m, txt)
	return txt
}

func (s *Server) callTXT(labels []string, caller string) string {
	cn, err := codec.ParseCallName(labels)
	if err != nil {
		return envelopeTXT(codec.Error("", err.Error()))
	}
	h := s.handlers
	if h.OnCall == nil {
		return envelopeTXT(codec.Error(cn.Tool, "server: no call handler"))
	}
	req := &CallRequest{Tool: cn.Tool, Args: cn.Args, Nonce: cn.Nonce, Sig: cn.Sig, Zone: s.zone, Caller: caller}
	if h.OnVerify != nil {
		if err := h.OnVerify(req); err != nil {
			return envelopeTXT(codec.Error(cn.Tool, err.Error()))
		}
	}
	e := h.OnCall(req)
	if e == nil {
		return envelopeTXT(codec.Error(cn.Tool, "call handler returned nil"))
	}
	return envelopeTXT(e)
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
