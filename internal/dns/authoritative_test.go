package dns

import (
	"sync/atomic"
	"testing"

	"github.com/Crank-Git/mcport53/internal/codec"
	"github.com/miekg/dns"
)

// countingServer runs a server whose call handler counts invocations.
func countingServer(t *testing.T, configure func(*Server) *Server) (*Client, *atomic.Int64) {
	t.Helper()
	var calls atomic.Int64
	srv := NewServer(testZone, &Handlers{
		OnCall: func(req *CallRequest) *codec.Envelope {
			calls.Add(1)
			return codec.OK(req.Tool, "ran", 0)
		},
		OnDiscovery: func() *DiscoveryResponse { return &DiscoveryResponse{Version: 1, Tools: []Tool{{Name: "echo"}}} },
		OnSchema:    func(tool string) *codec.Envelope { return codec.OK(tool, `{}`, 0) },
	}).WithDiscovery("127.0.0.1.", 5300)
	if configure != nil {
		srv = configure(srv)
	}
	c, _ := startServerWithAddr(t, srv)
	return c, &calls
}

func ask(t *testing.T, c *Client, name string, qtype uint16) *dns.Msg {
	t.Helper()
	resp, err := c.Query(name, qtype)
	if err != nil {
		t.Fatalf("%s %s: %v", name, dns.TypeToString[qtype], err)
	}
	return resp
}

func callName(tool string) string {
	nonce, _ := codec.RandomNonce()
	return LabelsToName(codec.BuildCallName(NameToLabels(testZone), tool, []byte(`{}`), nonce, ""))
}

// isNODATA reports NOERROR, no answers, and exactly the zone SOA in authority.
func isNODATA(m *dns.Msg) bool {
	if m.Rcode != dns.RcodeSuccess || len(m.Answer) != 0 || len(m.Ns) != 1 {
		return false
	}
	soa, ok := m.Ns[0].(*dns.SOA)
	return ok && soa.Hdr.Name == testZone && soa.Minttl == 0
}

// TestResponsesSetQR checks QR (and the echoed id, opcode and RD) on every
// kind of reply the server sends. Resolvers drop replies without QR.
func TestResponsesSetQR(t *testing.T) {
	c, _ := countingServer(t, nil)
	for _, tc := range []struct {
		name  string
		qtype uint16
		rcode int
	}{
		{callName("echo"), dns.TypeTXT, dns.RcodeSuccess},        // answer
		{"x.y." + testZone, dns.TypeA, dns.RcodeSuccess},         // NODATA
		{testZone, dns.TypeSOA, dns.RcodeSuccess},                // apex
		{"other.invalid.", dns.TypeTXT, dns.RcodeRefused},        // foreign
		{"abc.chunk." + testZone, dns.TypeTXT, dns.RcodeSuccess}, // error envelope
	} {
		resp := ask(t, c, tc.name, tc.qtype)
		if !resp.Response || resp.Rcode != tc.rcode || !resp.RecursionDesired || resp.Opcode != dns.OpcodeQuery {
			t.Errorf("%s %s: qr=%v rcode=%s rd=%v opcode=%d", tc.name, dns.TypeToString[tc.qtype],
				resp.Response, dns.RcodeToString[resp.Rcode], resp.RecursionDesired, resp.Opcode)
		}
	}
}

// TestServfailAndTSIGRejectSetQR covers the two early-exit replies.
func TestServfailAndTSIGRejectSetQR(t *testing.T) {
	c := startTestServer(t, &Handlers{OnCall: func(*CallRequest) *codec.Envelope { panic("x") }})
	if resp := ask(t, c, callName("boom"), dns.TypeTXT); !resp.Response || resp.Rcode != dns.RcodeServerFailure {
		t.Errorf("SERVFAIL reply: qr=%v rcode=%s", resp.Response, dns.RcodeToString[resp.Rcode])
	}
	ts, _ := countingServer(t, func(s *Server) *Server { return s.WithTSIG("k.", []byte("s")) })
	if resp := ask(t, ts, callName("echo"), dns.TypeTXT); !resp.Response {
		t.Error("TSIG rejection reply has no QR")
	}
}

// TestCallRunsOnlyForTXT is the qtype matrix for a call name: TXT and ANY run
// the tool; every other type is NODATA and must not run it.
func TestCallRunsOnlyForTXT(t *testing.T) {
	c, calls := countingServer(t, nil)
	for _, qt := range []uint16{dns.TypeA, dns.TypeAAAA, dns.TypeNS, dns.TypeSRV, dns.TypeMX, dns.TypeCNAME} {
		if resp := ask(t, c, callName("echo"), qt); !isNODATA(resp) {
			t.Errorf("call %s: %+v, want NODATA", dns.TypeToString[qt], resp)
		}
	}
	if calls.Load() != 0 {
		t.Fatalf("tool ran %d times for non-TXT queries", calls.Load())
	}
	for _, qt := range []uint16{dns.TypeTXT, dns.TypeANY} {
		resp := ask(t, c, callName("echo"), qt)
		if len(resp.Answer) != 1 || resp.Answer[0].Header().Rrtype != dns.TypeTXT {
			t.Errorf("call %s: answer %v, want one TXT", dns.TypeToString[qt], resp.Answer)
		}
	}
	if calls.Load() != 2 {
		t.Fatalf("tool ran %d times, want 2", calls.Load())
	}
}

// TestDiscoveryByQtype: TXT gets only the document, SRV only the SRV record,
// ANY both, and anything else NODATA.
func TestDiscoveryByQtype(t *testing.T) {
	c, _ := countingServer(t, nil)
	name := "_mcp._udp." + testZone
	types := func(m *dns.Msg) []uint16 {
		var out []uint16
		for _, rr := range m.Answer {
			out = append(out, rr.Header().Rrtype)
		}
		return out
	}
	if got := types(ask(t, c, name, dns.TypeTXT)); len(got) != 1 || got[0] != dns.TypeTXT {
		t.Errorf("TXT: %v", got)
	}
	resp := ask(t, c, name, dns.TypeSRV)
	if got := types(resp); len(got) != 1 || got[0] != dns.TypeSRV || resp.Answer[0].(*dns.SRV).Port != 5300 {
		t.Errorf("SRV: %v", resp.Answer)
	}
	if got := types(ask(t, c, name, dns.TypeANY)); len(got) != 2 {
		t.Errorf("ANY: %v", got)
	}
	if resp := ask(t, c, name, dns.TypeA); !isNODATA(resp) {
		t.Errorf("A: %+v, want NODATA", resp)
	}
	// The client reads discovery as TXT.
	if doc, err := c.Discovery(testZone); err != nil || len(doc.Tools) != 1 {
		t.Fatalf("Discovery: %+v %v", doc, err)
	}
}

// TestEmptyNonTerminals walks a call name from the top the way a
// QNAME-minimising resolver does. Every ancestor must be NODATA, not NXDOMAIN.
func TestEmptyNonTerminals(t *testing.T) {
	c, calls := countingServer(t, nil)
	nonce, _ := codec.RandomNonce()
	labels := codec.BuildCallName(NameToLabels(testZone), "echo", []byte(`{"text":"hi"}`), nonce, "")
	zl := len(NameToLabels(testZone))
	for i := len(labels) - zl - 1; i >= 1; i-- {
		name := LabelsToName(labels[i:])
		for _, qt := range []uint16{dns.TypeA, dns.TypeNS} {
			if resp := ask(t, c, name, qt); !isNODATA(resp) {
				t.Errorf("%s %s: rcode=%s answer=%d ns=%d, want NODATA", name, dns.TypeToString[qt],
					dns.RcodeToString[resp.Rcode], len(resp.Answer), len(resp.Ns))
			}
		}
	}
	if calls.Load() != 0 {
		t.Fatalf("walking ancestors ran the tool %d times", calls.Load())
	}
	for _, name := range []string{"anything." + testZone, "a.b.c.d." + testZone, "_udp." + testZone} {
		if resp := ask(t, c, name, dns.TypeTXT); !isNODATA(resp) {
			t.Errorf("%s TXT: want NODATA", name)
		}
	}
}

// TestApexSOAAndNS checks the zone apex.
func TestApexSOAAndNS(t *testing.T) {
	c, _ := countingServer(t, func(s *Server) *Server { return s.WithNameserver("dns.example.net") })
	resp := ask(t, c, testZone, dns.TypeSOA)
	soa, ok := firstRR(resp).(*dns.SOA)
	if !ok || soa.Ns != "dns.example.net." || soa.Mbox != "hostmaster."+testZone || soa.Minttl != 0 {
		t.Fatalf("SOA: %v", resp.Answer)
	}
	resp = ask(t, c, testZone, dns.TypeNS)
	if ns, ok := firstRR(resp).(*dns.NS); !ok || ns.Ns != "dns.example.net." {
		t.Fatalf("NS: %v", resp.Answer)
	}
	if resp := ask(t, c, testZone, dns.TypeA); len(resp.Answer) != 0 || len(resp.Ns) != 1 {
		t.Fatalf("apex A: %+v, want NODATA", resp)
	}
	if resp := ask(t, c, testZone, dns.TypeANY); len(resp.Answer) != 1 {
		t.Fatalf("apex ANY: %v", resp.Answer)
	}

	d, _ := countingServer(t, nil)
	if soa, ok := firstRR(ask(t, d, testZone, dns.TypeSOA)).(*dns.SOA); !ok || soa.Ns != "ns."+testZone {
		t.Fatalf("default nameserver: %v", soa)
	}
}

// TestAnswerTypesMatchQuestion: no answer record may have a type other than
// the one asked (ANY aside).
func TestAnswerTypesMatchQuestion(t *testing.T) {
	c, _ := countingServer(t, nil)
	names := []string{testZone, "_mcp._udp." + testZone, "echo.schema." + testZone, callName("echo"),
		"0.sess.chunk." + testZone, "j1.job." + testZone, "unknown." + testZone}
	for _, name := range names {
		for _, qt := range []uint16{dns.TypeA, dns.TypeAAAA, dns.TypeTXT, dns.TypeSRV, dns.TypeNS, dns.TypeSOA} {
			for _, rr := range ask(t, c, name, qt).Answer {
				if rr.Header().Rrtype != qt {
					t.Errorf("%s %s: answer contains %s", name, dns.TypeToString[qt], dns.TypeToString[rr.Header().Rrtype])
				}
			}
		}
	}
}

// TestClientSendsRD: through a resolver RD=0 means "cache only", which is
// refused for names the resolver has not seen.
func TestClientSendsRD(t *testing.T) {
	seen := make(chan bool, 4)
	c := startRawServer(t, func(req *dns.Msg) *dns.Msg {
		seen <- req.RecursionDesired
		return reply(req)
	})
	_, _ = c.Query("a."+testZone, dns.TypeTXT)
	_, _ = c.Discovery(testZone)
	for i := 0; i < 2; i++ {
		if !<-seen {
			t.Fatal("query sent with RD=0")
		}
	}
}

func firstRR(m *dns.Msg) dns.RR {
	if len(m.Answer) == 0 {
		return nil
	}
	return m.Answer[0]
}
