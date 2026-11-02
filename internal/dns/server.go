package dns

import (
	"encoding/json"
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
}

// CallRequest is a decoded tool call received on a DNS query (protocol §2.3).
type CallRequest struct {
	Tool  string
	Args  []byte
	Nonce string
	Sig   string
	Zone  string
}

// ChunkRequest is a decoded result-chunk query (protocol §2.4).
type ChunkRequest struct {
	Chunk   int
	Session string
	Zone    string
}

// Handlers implements the application logic a Server dispatches to. Every field
// is required; a nil handler yields a generic error envelope.
type Handlers struct {
	OnCall      func(req *CallRequest) *codec.Envelope
	OnDiscovery func() *DiscoveryResponse
	OnSchema    func(tool string) *codec.Envelope
	OnChunk     func(req *ChunkRequest) *codec.Envelope
	OnJob       func(job string) *codec.Envelope
}

// Server is an authoritative DNS server for a tool zone.
type Server struct {
	zone       string
	zoneLabels []string
	handlers   Handlers
	srvTarget  string // SRV target advertised in discovery; defaults to "localhost."
	srvPort    uint16 // SRV port advertised in discovery; defaults to 53
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
	m := new(dns.Msg)
	*m = *reply(r)
	m.Authoritative = true

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

	switch {
	case isDiscovery(prefix):
		s.serveDiscovery(r, m)
	case isSchema(prefix):
		s.serveSchema(r, m, prefix)
	case isCall(prefix):
		s.serveCall(r, m, labels)
	case isChunk(prefix):
		s.serveChunk(r, m, labels)
	case isJob(prefix):
		s.serveJob(r, m, labels)
	default:
		m.Rcode = dns.RcodeNameError
	}
	_ = w.WriteMsg(m)
}

// ListenAndServe starts the server on addr (e.g. "127.0.0.1:53") over UDP.
func (s *Server) ListenAndServe(addr string) error {
	return (&dns.Server{Addr: addr, Net: "udp", Handler: s}).ListenAndServe()
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

func (s *Server) serveCall(r, m *dns.Msg, labels []string) {
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
	req := &CallRequest{Tool: cn.Tool, Args: cn.Args, Nonce: cn.Nonce, Sig: cn.Sig, Zone: s.zone}
	e := h.OnCall(req)
	if e == nil {
		s.errResp(r, m, cn.Tool, "call handler returned nil")
		return
	}
	buildTXTResponse(r, m, envelopeTXT(e))
}

func (s *Server) serveChunk(r, m *dns.Msg, labels []string) {
	idx, session, _, err := codec.ParseChunkName(labels)
	if err != nil {
		s.errResp(r, m, "", err.Error())
		return
	}
	h := s.handlers
	if h.OnChunk == nil {
		s.errResp(r, m, "", "server: no chunk handler")
		return
	}
	req := &ChunkRequest{Chunk: idx, Session: session, Zone: s.zone}
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
