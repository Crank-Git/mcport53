package dns

import (
	"net"
	"strings"
	"testing"

	"github.com/Crank-Git/mcport53/internal/codec"
	"github.com/miekg/dns"
)

// callerAddr: nil address and a non host:port address (no port to split off).
func TestCallerAddrNil(t *testing.T) {
	if got := callerAddr(nil); got != "" {
		t.Errorf("callerAddr(nil) = %q, want empty", got)
	}
}

func TestCallerAddrNoPort(t *testing.T) {
	addr, err := net.ResolveUnixAddr("unix", "dockersock")
	if err != nil {
		t.Fatalf("resolve unix addr: %v", err)
	}
	if got := callerAddr(addr); got != "dockersock" {
		t.Errorf("callerAddr(unix) = %q, want %q", got, "dockersock")
	}
}

// NameToLabels: empty input yields no labels.
func TestNameToLabelsEmpty(t *testing.T) {
	if got := NameToLabels(""); len(got) != 0 {
		t.Errorf("NameToLabels(\"\") = %v, want no labels", got)
	}
}

// extractTXT: missing answer and undecodable base64.
func TestExtractTXTNoAnswer(t *testing.T) {
	if _, err := extractTXT(new(dns.Msg)); err == nil {
		t.Fatal("expected error for a message without TXT answers")
	}
}

func TestExtractTXTDecodeError(t *testing.T) {
	m := new(dns.Msg)
	m.Answer = append(m.Answer, &dns.TXT{Txt: []string{"!!!not-base64!!!"}})
	if _, err := extractTXT(m); err == nil {
		t.Fatal("expected a base64 decode error")
	}
}

// envelopeTXT: nil envelope falls back to an error envelope.
func TestEnvelopeTXTNil(t *testing.T) {
	got := envelopeTXT(nil)
	if !strings.Contains(got, "nil envelope") {
		t.Errorf("envelopeTXT(nil) = %q, want a mention of 'nil envelope'", got)
	}
}

// Nil handlers: every dispatch path returns an error envelope rather than
// panicking, so a server built with &Handlers{} still answers.
func TestNilHandlersDiscovery(t *testing.T) {
	c := startTestServer(t, &Handlers{})
	doc, err := c.Discovery(testZone)
	if err != nil {
		t.Fatalf("discovery with nil handler: %v", err)
	}
	if doc.Version != 0 || len(doc.Tools) != 0 {
		t.Errorf("nil-handler discovery = %+v, want empty", doc)
	}
}

func TestNilHandlersSchema(t *testing.T) {
	c := startTestServer(t, &Handlers{})
	e, err := c.Schema(testZone, "echo")
	if err != nil {
		t.Fatalf("schema: %v", err)
	}
	if e.Status != codec.StatusError {
		t.Errorf("nil-handler schema status = %q, want error", e.Status)
	}
}

func TestNilHandlersCall(t *testing.T) {
	c := startTestServer(t, &Handlers{})
	name := signedCallName(t, testZone, "echo", []byte(`{}`), "nonce", "")
	e := callEnvelope(t, c, name)
	if e.Status != codec.StatusError {
		t.Errorf("nil-handler call status = %q, want error", e.Status)
	}
}

func TestNilHandlersChunk(t *testing.T) {
	c := startTestServer(t, &Handlers{})
	name := LabelsToName(codec.ChunkName(NameToLabels(testZone), "sess-1", 0))
	e := callEnvelope(t, c, name)
	if e.Status != codec.StatusError {
		t.Errorf("nil-handler chunk status = %q, want error", e.Status)
	}
}

func TestNilHandlersJob(t *testing.T) {
	c := startTestServer(t, &Handlers{})
	name := LabelsToName(codec.JobName(NameToLabels(testZone), "job-1"))
	e := callEnvelope(t, c, name)
	if e.Status != codec.StatusError {
		t.Errorf("nil-handler job status = %q, want error", e.Status)
	}
}

// Malformed names route to the right handler but fail to parse; each yields an
// error envelope (NOERROR rcode) rather than crashing the server.
func TestMalformedCallName(t *testing.T) {
	c := startTestServer(t, &Handlers{})
	// "call" as the leftmost label: the tool label is missing.
	e := callEnvelope(t, c, dns.Fqdn("call.abc.example."))
	if e.Status != codec.StatusError {
		t.Errorf("malformed call status = %q, want error", e.Status)
	}
}

func TestMalformedChunkName(t *testing.T) {
	c := startTestServer(t, &Handlers{})
	e := callEnvelope(t, c, dns.Fqdn("chunk.example."))
	if e.Status != codec.StatusError {
		t.Errorf("malformed chunk status = %q, want error", e.Status)
	}
}

func TestMalformedJobName(t *testing.T) {
	c := startTestServer(t, &Handlers{})
	e := callEnvelope(t, c, dns.Fqdn("job.example."))
	if e.Status != codec.StatusError {
		t.Errorf("malformed job status = %q, want error", e.Status)
	}
}

// queryTXT / queryEnvelope: a name that matches no known shape gets NODATA,
// which carries no TXT answer.
func TestQueryTXTNODATA(t *testing.T) {
	c := startTestServer(t, &Handlers{})
	if _, err := c.queryTXT(dns.Fqdn("nonexistent.example."), dns.TypeTXT); err == nil {
		t.Fatal("expected an error for a NODATA query")
	}
}

// Discovery: a foreign zone is REFUSED.
func TestDiscoveryForeignZone(t *testing.T) {
	c := startTestServer(t, &Handlers{})
	if _, err := c.Discovery("nonexample."); err == nil {
		t.Fatal("expected an error for a foreign zone")
	}
}

// SetNet switches the underlying transport; it is exercised for its side effect.
func TestSetNet(t *testing.T) {
	c := NewClient("127.0.0.1:1")
	c.SetNet("tcp")
}

// A foreign-zone schema query is REFUSED, surfacing through queryEnvelope.
func TestSchemaForeignZone(t *testing.T) {
	c := startTestServer(t, &Handlers{})
	if _, err := c.Schema("nonexample.", "echo"); err == nil {
		t.Fatal("expected an error for a foreign-zone schema query")
	}
}

// ListenAndServe reports an error when it cannot bind the address.
func TestListenAndServeBadAddr(t *testing.T) {
	srv := NewServer(testZone, &Handlers{})
	if err := srv.ListenAndServe(net.JoinHostPort("127.0.0.1", "70000")); err == nil {
		t.Fatal("expected a bind error for an out-of-range port")
	}
}

// buildEmptyResponse and buildNXDOMAIN write the expected authoritative replies.
func TestBuildHelpers(t *testing.T) {
	req := new(dns.Msg)
	req.SetQuestion(dns.Fqdn("a.example."), dns.TypeTXT)

	empty := new(dns.Msg)
	buildEmptyResponse(req, empty)
	if !empty.Authoritative || len(empty.Answer) != 0 {
		t.Errorf("buildEmptyResponse = %+v, want authoritative and empty", empty)
	}

	nx := new(dns.Msg)
	buildNXDOMAIN(req, nx)
	if nx.Rcode != dns.RcodeNameError || !nx.Authoritative {
		t.Errorf("buildNXDOMAIN = %+v, want NXDOMAIN and authoritative", nx)
	}
}
