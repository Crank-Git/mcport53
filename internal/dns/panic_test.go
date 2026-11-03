package dns

import (
	"testing"

	"github.com/Crank-Git/mcport53/internal/codec"
	"github.com/miekg/dns"
)

// TestMalformedChunkNameKeepsServerUp sends the query that used to crash the
// process (one label before "chunk") to a real listening server, then checks
// the same server still answers a normal call. Before the fix the panic
// escaped the miekg/dns goroutine and killed the test binary.
func TestMalformedChunkNameKeepsServerUp(t *testing.T) {
	c, _ := newTestServer(t)
	for _, name := range []string{
		"abc.chunk.example.",
		"chunk.example.",
		"job.example.",
		"call.example.",
		"tool.call.example.",
		"tool.call.signed.n.example.",
	} {
		resp, err := c.Query(name, dns.TypeTXT)
		if err != nil {
			t.Fatalf("query %s: %v (server down?)", name, err)
		}
		if resp.Rcode != dns.RcodeSuccess {
			continue // NXDOMAIN/SERVFAIL are acceptable; only liveness matters
		}
		txt, err := extractTXT(resp)
		if err != nil {
			t.Fatalf("query %s: %v", name, err)
		}
		e, err := codec.ParseEnvelope([]byte(txt))
		if err != nil || e.Status != codec.StatusError {
			t.Errorf("query %s: envelope %+v err=%v, want error envelope", name, e, err)
		}
	}
	e, err := c.Call(testZone, "echo", []byte(`{"text":"still-up"}`), "")
	if err != nil || e.Status != codec.StatusOK {
		t.Fatalf("call after malformed queries: env=%+v err=%v", e, err)
	}
}

// TestHandlerPanicAnswersServfail checks that a panicking handler costs one
// query (answered SERVFAIL) rather than the process, and that the server keeps
// serving afterwards.
func TestHandlerPanicAnswersServfail(t *testing.T) {
	c := startTestServer(t, &Handlers{
		OnCall: func(req *CallRequest) *codec.Envelope {
			if req.Tool == "boom" {
				panic("tool bug")
			}
			return codec.OK(req.Tool, "ok", 0)
		},
		OnJob: func(string) *codec.Envelope { panic("job bug") },
	})

	for _, q := range []string{
		LabelsToName(codec.BuildCallName([]string{"example"}, "boom", []byte(`{}`), "n1", "")),
		LabelsToName(codec.JobName([]string{"example"}, "j1")),
	} {
		resp, err := c.Query(q, dns.TypeTXT)
		if err != nil {
			t.Fatalf("query %s: %v", q, err)
		}
		if resp.Rcode != dns.RcodeServerFailure {
			t.Errorf("query %s: rcode %s, want SERVFAIL", q, dns.RcodeToString[resp.Rcode])
		}
		if resp.Id == 0 || len(resp.Question) != 1 {
			t.Errorf("query %s: SERVFAIL reply must echo id and question, got %+v", q, resp)
		}
	}

	e, err := c.Call(testZone, "fine", []byte(`{}`), "")
	if err != nil || e.Status != codec.StatusOK {
		t.Fatalf("call after panics: env=%+v err=%v", e, err)
	}
}

func TestQuestionName(t *testing.T) {
	if got := questionName(nil); got != "" {
		t.Errorf("nil msg: %q", got)
	}
	if got := questionName(new(dns.Msg)); got != "" {
		t.Errorf("no question: %q", got)
	}
	m := new(dns.Msg)
	m.SetQuestion("a.example.", dns.TypeTXT)
	if got := questionName(m); got != "a.example." {
		t.Errorf("got %q", got)
	}
}
