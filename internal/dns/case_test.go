package dns

import (
	"math/rand"
	"strings"
	"testing"
	"time"

	"github.com/Crank-Git/mcport53/internal/auth"
	"github.com/Crank-Git/mcport53/internal/codec"
	"github.com/miekg/dns"
)

// randomCase flips the case of each letter at random, as a 0x20 resolver
// does, and guarantees at least one uppercase letter.
func randomCase(r *rand.Rand, s string) string {
	b := []byte(s)
	flipped := false
	for i, c := range b {
		if c >= 'a' && c <= 'z' && r.Intn(2) == 0 {
			b[i] = c - 32
			flipped = true
		}
	}
	if !flipped {
		for i, c := range b {
			if c >= 'a' && c <= 'z' {
				b[i] = c - 32
				break
			}
		}
	}
	return string(b)
}

// caseServer echoes what the server parsed so tests can check it.
func caseServer(t *testing.T, verify func(*CallRequest) error) *Client {
	t.Helper()
	return startTestServer(t, &Handlers{
		OnCall: func(req *CallRequest) *codec.Envelope {
			return codec.OK(req.Tool, req.Nonce+"|"+string(req.Args), 0)
		},
		OnVerify:    verify,
		OnSchema:    func(tool string) *codec.Envelope { return codec.OK(tool, "schema:"+tool, 0) },
		OnChunk:     func(req *ChunkRequest) *codec.Envelope { return codec.OK("", req.Session+"|"+req.Cursor, req.Chunk) },
		OnJob:       func(job string) *codec.Envelope { return codec.OK("", "job:"+job, 0) },
		OnDiscovery: func() *DiscoveryResponse { return &DiscoveryResponse{Version: 1, Tools: []Tool{{Name: "echo"}}} },
	})
}

// askCase sends name in random case and returns the envelope, checking that
// the answer echoes the exact case of the question.
func askCase(t *testing.T, c *Client, r *rand.Rand, name string) *codec.Envelope {
	t.Helper()
	mixed := randomCase(r, name)
	resp, err := c.Query(mixed, dns.TypeTXT)
	if err != nil {
		t.Fatalf("%s: %v", mixed, err)
	}
	if resp.Question[0].Name != mixed {
		t.Errorf("question echoed as %q, sent %q", resp.Question[0].Name, mixed)
	}
	for _, rr := range resp.Answer {
		if rr.Header().Name != mixed {
			t.Errorf("answer owner %q, want %q", rr.Header().Name, mixed)
		}
	}
	txt, err := extractTXT(resp)
	if err != nil {
		t.Fatalf("%s: %v", mixed, err)
	}
	e, err := codec.ParseEnvelope([]byte(txt))
	if err != nil {
		t.Fatal(err)
	}
	return e
}

func TestMixedCaseNames(t *testing.T) {
	r := rand.New(rand.NewSource(1))
	c := caseServer(t, nil)
	zone := NameToLabels(testZone)
	for i := 0; i < 50; i++ {
		nonce, _ := codec.RandomNonce()
		args := []byte(`{"text":"Case Matters In Args"}`)
		e := askCase(t, c, r, LabelsToName(codec.BuildCallName(zone, "echo", args, nonce, "")))
		if e.Status != codec.StatusOK || e.Tool != "echo" || e.Result != nonce+"|"+string(args) {
			t.Fatalf("call: %+v (want tool echo, nonce %s, exact args)", e, nonce)
		}
	}
	if e := askCase(t, c, r, "echo.schema."+testZone); e.Result != "schema:echo" {
		t.Errorf("schema: %+v", e)
	}
	if e := askCase(t, c, r, LabelsToName(codec.ChunkName(zone, "sessabc", 3))); e.Result != "sessabc|" || e.Ms != 3 {
		t.Errorf("chunk: %+v", e)
	}
	if e := askCase(t, c, r, LabelsToName(codec.CursorName(zone, "sessabc", "cursorxyz"))); e.Result != "sessabc|cursorxyz" {
		t.Errorf("cursor: %+v", e)
	}
	if e := askCase(t, c, r, LabelsToName(codec.JobName(zone, "jobq"))); e.Result != "job:jobq" {
		t.Errorf("job: %+v", e)
	}
	resp, err := c.Query(randomCase(r, "_mcp._udp."+testZone), dns.TypeTXT)
	if err != nil || len(resp.Answer) != 1 {
		t.Fatalf("discovery: %v %v", resp, err)
	}
}

// TestMixedCaseSignedCall: the signature covers the lowercase nonce and tool
// the client sent, so a case-randomised copy must still verify.
func TestMixedCaseSignedCall(t *testing.T) {
	secret := []byte("case-key")
	c := caseServer(t, func(req *CallRequest) error {
		return auth.Check(secret, req.Sig, req.Tool, req.Nonce, req.Args, time.Now(), time.Minute)
	})
	r := rand.New(rand.NewSource(2))
	for i := 0; i < 50; i++ {
		nonce, _ := codec.RandomNonce()
		args := []byte(`{"n":` + strings.Repeat("7", i%20+1) + `}`)
		sig := auth.Sign(secret, "echo", nonce, args, time.Now().Unix())
		name := LabelsToName(codec.BuildCallName(NameToLabels(testZone), "echo", args, nonce, sig))
		if e := askCase(t, c, r, name); e.Status != codec.StatusOK {
			t.Fatalf("signed mixed-case call %d: %+v", i, e)
		}
	}
}
