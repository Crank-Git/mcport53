package mcp

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Crank-Git/mcport53/internal/codec"
	"github.com/Crank-Git/mcport53/internal/dns"
	miedns "github.com/miekg/dns"
)

// longZone pushes question names toward the 255-byte limit.
const longZone = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb.example."

var longTool = strings.Repeat("t", 63)

// budgetServer serves srv on UDP with TSIG and returns its address.
func budgetServer(t *testing.T, srv *Server, zone string, tsigSecret []byte) string {
	t.Helper()
	h := srv.Handlers()
	ds := dns.NewServer(zone, &h).WithTSIG("budget.", tsigSecret)
	conn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1")})
	if err != nil {
		t.Fatal(err)
	}
	ms := &miedns.Server{PacketConn: conn, Handler: ds.Handler(), TsigSecret: tsigSecrets(tsigSecret)}
	ready, done := make(chan struct{}), make(chan struct{})
	ms.NotifyStartedFunc = func() { close(ready) }
	go func() { _ = ms.ActivateAndServe(); close(done) }()
	<-ready
	t.Cleanup(func() { _ = ms.Shutdown(); <-done })
	return conn.LocalAddr().String()
}

func tsigSecrets(secret []byte) map[string]string {
	return map[string]string{"budget.": base64.StdEncoding.EncodeToString(secret)}
}

// exchange1232 sends q over UDP advertising exactly 1232 bytes, TSIG-signed,
// and returns the response and its packed size.
func exchange1232(t *testing.T, addr, name string, secret []byte) (*miedns.Msg, int) {
	t.Helper()
	q := new(miedns.Msg)
	q.SetQuestion(name, miedns.TypeTXT)
	q.SetEdns0(1232, false)
	q.SetTsig("budget.", miedns.HmacSHA256, 300, time.Now().Unix())
	c := &miedns.Client{Net: "udp", UDPSize: 1232, Timeout: 2 * time.Second, TsigSecret: tsigSecrets(secret)}
	resp, _, err := c.Exchange(q, addr)
	if err != nil {
		t.Fatalf("exchange %s: %v", name, err)
	}
	// Measure as sent: the server packs with name compression, so the answer's
	// owner name is a pointer to the question. The client's 1232-byte receive
	// buffer would also have failed the exchange on anything larger.
	resp.Compress = true
	b, _ := resp.Pack()
	return resp, len(b)
}

func txtEnvelope(t *testing.T, resp *miedns.Msg) *codec.Envelope {
	t.Helper()
	raw, err := dns.ExtractTXT(resp)
	if err != nil {
		t.Fatalf("TXT answer: %v", err)
	}
	e, err := codec.ParseEnvelope([]byte(raw))
	if err != nil {
		t.Fatalf("envelope: %v (%q)", err, raw)
	}
	return e
}

// TestEveryResponseFits1232 builds the largest responses the server emits —
// a single envelope at the size limit with worst-case JSON escaping, chunk 0
// with cursor and compression markers, and later chunks with five-digit
// indices — under a long zone, a 63-character tool name, a near-255-byte
// question name and TSIG, and requires each to arrive whole in a 1232-byte
// UDP message.
func TestEveryResponseFits1232(t *testing.T) {
	secret := []byte("budget-secret")
	zone := dns.NameToLabels(longZone)

	// The largest result string whose marshaled envelope still fits.
	quotes := func(n int) string { return strings.Repeat(`"`, n) } // each escapes to two bytes
	fitting := 0
	for n := 1; ; n++ {
		b, _ := codec.OK(longTool, quotes(n), 999999).Marshal()
		if len(b) > codec.MaxEnvelopeTXT {
			break
		}
		fitting = n
	}

	r := NewRegistry()
	_ = r.Register(&Tool{Name: longTool, Call: func(_ context.Context, args []byte) (*codec.Envelope, error) {
		switch string(args) {
		case "single":
			return codec.OK(longTool, quotes(fitting), 999999), nil
		default: // huge incompressible payload -> thousands of chunks
			buf := make([]byte, codec.ChunkSize*12000)
			_, _ = rand.Read(buf)
			return codec.OK(longTool, base64.StdEncoding.EncodeToString(buf), 999999), nil
		}
	}})
	// Building the multi-megabyte fixture can take longer than the inline
	// budget on a slow machine, which would answer "queued" instead of the
	// chunk-0 envelope this test measures.
	srv := NewServer(r).WithCompression().WithCursorPagination().WithInlineBudget(time.Minute)
	addr := budgetServer(t, srv, longZone, secret)

	callName := func(args string) string {
		// Pad the nonce label so the call name lands close to 255 bytes.
		nonce, _ := codec.RandomNonce()
		labels := codec.BuildCallName(zone, longTool, []byte(args), nonce, "")
		pad := 255 - codec.NameWireLength(labels)
		if pad > 0 {
			nonce += strings.Repeat("a", min(pad, codec.MaxLabel-len(nonce)))
			labels = codec.BuildCallName(zone, longTool, []byte(args), nonce, "")
		}
		if codec.NameWireLength(labels) < 200 {
			t.Fatalf("question only %d bytes", codec.NameWireLength(labels))
		}
		return dns.LabelsToName(labels)
	}

	check := func(what, name string) *codec.Envelope {
		t.Helper()
		resp, size := exchange1232(t, addr, name, secret)
		if resp.Truncated || size > 1232 {
			t.Fatalf("%s: truncated=%v size=%d (question %d bytes)", what, resp.Truncated, size, len(name))
		}
		t.Logf("%-28s %4d bytes (question %3d)", what, size, len(name))
		return txtEnvelope(t, resp)
	}

	if e := check("single envelope at limit", callName("single")); e.Status != codec.StatusOK || len(e.Result) != fitting {
		t.Fatalf("single: %+v", e)
	}
	first := check("chunk 0 (cursor+gzip)", callName("huge"))
	if first.Status != codec.StatusChunked || first.Cursor == "" || first.Total < 10000 {
		t.Fatalf("chunk 0: status=%s cursor=%q total=%d", first.Status, first.Cursor, first.Total)
	}
	for _, idx := range []int{1, first.Total / 2, first.Total - 2, first.Total - 1} {
		name := dns.LabelsToName(codec.ChunkName(zone, first.Session, idx))
		e := check(fmt.Sprintf("chunk %d/%d (fixed)", idx, first.Total), name)
		if e.Chunk != idx {
			t.Fatalf("chunk %d: got %+v", idx, e)
		}
	}
	cur := dns.LabelsToName(codec.CursorName(zone, first.Session, first.Cursor))
	if e := check("chunk 1 (by cursor)", cur); e.Chunk != 1 || e.Cursor == "" {
		t.Fatalf("cursor chunk: %+v", e)
	}
}

// countingAgent starts srv behind a UDP-only server (no TCP listener, so any
// response that does not fit UDP fails the call) and counts queries.
func countingAgent(t *testing.T, srv *Server) (*Agent, *atomic.Int64) {
	t.Helper()
	var n atomic.Int64
	h := srv.Handlers()
	onCall, onChunk := h.OnCall, h.OnChunk
	h.OnCall = func(r *dns.CallRequest) *codec.Envelope { n.Add(1); return onCall(r) }
	h.OnChunk = func(r *dns.ChunkRequest) *codec.Envelope { n.Add(1); return onChunk(r) }
	ds := dns.NewServer(agentZone, &h)
	addr := listenFor(t, "udp4", "127.0.0.1:0", ds.Handler())
	return NewAgent(addr, agentZone), &n
}

// TestLargeResultRoundTrips covers compression on/off x fixed/cursor
// pagination x compressible/incompressible payloads, checks the assembled
// result is byte-identical, and pins the number of DNS queries.
func TestLargeResultRoundTrips(t *testing.T) {
	random := make([]byte, 6000)
	_, _ = rand.Read(random)
	payloads := map[string]string{
		"compressible":   strings.Repeat("the quick brown fox jumps over the lazy dog. ", 450), // ~20 KB
		"incompressible": base64.StdEncoding.EncodeToString(random),                            // 8 KB
	}
	for pname, text := range payloads {
		for _, compress := range []bool{false, true} {
			for _, cursor := range []bool{false, true} {
				name := fmt.Sprintf("%s/compress=%v/cursor=%v", pname, compress, cursor)
				t.Run(name, func(t *testing.T) {
					resultJSON, _ := codec.JSONResult(map[string]string{"text": text})
					r := NewRegistry()
					_ = r.Register(&Tool{Name: "big", Call: func(context.Context, []byte) (*codec.Envelope, error) {
						return codec.OK("big", resultJSON, 0), nil
					}})
					srv := NewServer(r)
					if compress {
						srv = srv.WithCompression()
					}
					if cursor {
						srv = srv.WithCursorPagination()
					}
					agent, queries := countingAgent(t, srv)
					re, err := agent.Call(context.Background(), "big", []byte(`{}`))
					if err != nil {
						t.Fatal(err)
					}
					var got map[string]string
					if err := json.Unmarshal([]byte(re.Value), &got); err != nil || got["text"] != text {
						t.Fatalf("assembled result differs (err %v)", err)
					}

					// Expected queries: one per chunk of the (possibly
					// compressed) payload, or one for a single envelope.
					payload := []byte(resultJSON)
					if compress {
						c, _ := codec.CompressorFor(codec.CompressionGzip)
						if z, _ := c.Compress(payload); len(z) < len(payload) {
							payload = z
						}
					}
					want := (len(payload) + codec.ChunkSize - 1) / codec.ChunkSize
					if b, _ := codec.OK("big", base64.StdEncoding.EncodeToString(payload), 0).Marshal(); compress && len(payload) < len(resultJSON) && len(b) <= codec.MaxEnvelopeTXT {
						want = 1
					}
					if got := int(queries.Load()); got != want {
						t.Fatalf("%d queries, want %d (payload %d bytes)", got, want, len(payload))
					}
					t.Logf("%d bytes of result -> %d queries", len(resultJSON), queries.Load())
				})
			}
		}
	}
}

// TestCompressionHelpsLargeResults is the regression from the issue: with
// compression enabled, a large compressible result used to be chunked
// uncompressed. It must now take far fewer queries.
func TestCompressionHelpsLargeResults(t *testing.T) {
	resultJSON, _ := codec.JSONResult(strings.Repeat("abcdefgh", 2500)) // 20 KB
	count := func(compress bool) int64 {
		r := NewRegistry()
		_ = r.Register(&Tool{Name: "big", Call: func(context.Context, []byte) (*codec.Envelope, error) {
			return codec.OK("big", resultJSON, 0), nil
		}})
		srv := NewServer(r)
		if compress {
			srv = srv.WithCompression()
		}
		agent, n := countingAgent(t, srv)
		if _, err := agent.Call(context.Background(), "big", []byte(`{}`)); err != nil {
			t.Fatal(err)
		}
		return n.Load()
	}
	plain, gz := count(false), count(true)
	if gz*10 > plain {
		t.Fatalf("compressed: %d queries vs %d uncompressed; want at least 10x fewer", gz, plain)
	}
	t.Logf("20 KB compressible result: %d queries uncompressed, %d compressed (was 200+ at 100-byte chunks)", plain, gz)
}

// TestTenKBResultQueryCount pins the query count for a 10 KB incompressible
// result: one query per 400-byte chunk now that envelopes travel as raw TXT
// bytes (it was 42 at 240-byte chunks, and 100 at the original 100).
func TestTenKBResultQueryCount(t *testing.T) {
	random := make([]byte, 7500)
	_, _ = rand.Read(random)
	resultJSON, _ := codec.JSONResult(base64.StdEncoding.EncodeToString(random)) // ~10 KB
	r := NewRegistry()
	_ = r.Register(&Tool{Name: "big", Call: func(context.Context, []byte) (*codec.Envelope, error) {
		return codec.OK("big", resultJSON, 0), nil
	}})
	agent, queries := countingAgent(t, NewServer(r))
	if _, err := agent.Call(context.Background(), "big", []byte(`{}`)); err != nil {
		t.Fatal(err)
	}
	want := (len(resultJSON) + 399) / 400
	if got := int(queries.Load()); got != want || want > 26 {
		t.Fatalf("%d-byte result: %d queries, want %d", len(resultJSON), got, want)
	}
	t.Logf("%d-byte result -> %d queries", len(resultJSON), queries.Load())
}
