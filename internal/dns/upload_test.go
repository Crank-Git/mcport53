package dns

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"net"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Crank-Git/mcport53/internal/auth"
	"github.com/Crank-Git/mcport53/internal/codec"
	"github.com/miekg/dns"
)

// uploadServer answers calls with the sha256 of the arguments it received
// and counts upload-part queries and calls.
type uploadServer struct {
	srv          *Server
	client       *Client
	parts, calls atomic.Int64
}

func newUploadServer(t *testing.T, secret []byte, configure func(*Server) *Server) *uploadServer {
	t.Helper()
	us := &uploadServer{}
	h := &Handlers{OnCall: func(req *CallRequest) *codec.Envelope {
		us.calls.Add(1)
		sum := sha256.Sum256(req.Args)
		return codec.OK(req.Tool, hex.EncodeToString(sum[:]), len(req.Args))
	}}
	if secret != nil {
		h.OnVerify = func(req *CallRequest) error {
			return auth.Check(secret, req.Sig, req.Tool, req.Nonce, req.Args, time.Now(), time.Minute)
		}
	}
	us.srv = NewServer(testZone, h)
	if configure != nil {
		us.srv = configure(us.srv)
	}
	counted := dns.HandlerFunc(func(w dns.ResponseWriter, r *dns.Msg) {
		if len(r.Question) == 1 && strings.Contains(strings.ToLower(r.Question[0].Name), ".upload.") {
			us.parts.Add(1)
		}
		us.srv.ServeDNS(w, r)
	})
	addr := listenHandler(t, counted)
	us.client = NewClient(addr)
	if secret != nil {
		us.client.WithSigner(func(tool, nonce string, args []byte, ts int64) string {
			return auth.Sign(secret, tool, nonce, args, ts)
		})
	}
	return us
}

func listenHandler(t *testing.T, h dns.Handler) string {
	t.Helper()
	conn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1")})
	if err != nil {
		t.Fatal(err)
	}
	ms := &dns.Server{PacketConn: conn, Handler: h}
	ready, done := make(chan struct{}), make(chan struct{})
	ms.NotifyStartedFunc = func() { close(ready) }
	go func() { _ = ms.ActivateAndServe(); close(done) }()
	<-ready
	t.Cleanup(func() { _ = ms.Shutdown(); <-done })
	return conn.LocalAddr().String()
}

func sha(b []byte) string {
	s := sha256.Sum256(b)
	return hex.EncodeToString(s[:])
}

// TestUploadRoundTrips sends arguments at and beyond the inline limit up to
// the upload limit, signed and unsigned, and checks the handler receives the
// exact bytes, in one call, after the expected number of part queries.
func TestUploadRoundTrips(t *testing.T) {
	for _, signed := range []bool{false, true} {
		var secret []byte
		if signed {
			secret = []byte("upload-key")
		}
		us := newUploadServer(t, secret, nil)
		for _, n := range []int{200, 1000, 10_000, DefaultUploadMaxBytes} {
			args := make([]byte, n)
			_, _ = rand.Read(args)
			beforeParts, beforeCalls := us.parts.Load(), us.calls.Load()
			e, err := us.client.Call(testZone, "echo", args, "")
			if err != nil || e.Status != codec.StatusOK || e.Result != sha(args) || e.Ms != n {
				t.Fatalf("signed=%v n=%d: env=%+v err=%v", signed, n, e, err)
			}
			if got := us.calls.Load() - beforeCalls; got != 1 {
				t.Fatalf("signed=%v n=%d: %d calls, want 1", signed, n, got)
			}
			parts := us.parts.Load() - beforeParts
			if parts < int64((n+125)/126) || parts > int64(n/100+1) {
				t.Errorf("signed=%v n=%d: %d part queries", signed, n, parts)
			}
			t.Logf("signed=%v %6d bytes -> %4d upload queries + 1 call", signed, n, parts)
		}
		if count, total := us.srv.uploads.stats(); count != 0 || total != 0 {
			t.Errorf("uploads left after their calls: %d (%d bytes)", count, total)
		}
	}
}

// manual helpers drive the upload protocol by hand.
func putPart(t *testing.T, c *Client, id string, idx int, data []byte) *codec.Envelope {
	t.Helper()
	e, err := c.queryEnvelope(LabelsToName(codec.UploadPartName(NameToLabels(testZone), id, idx, data)), dns.TypeTXT)
	if err != nil {
		t.Fatal(err)
	}
	return e
}

func callUpload(t *testing.T, c *Client, id string, parts int, sig, nonce string) *codec.Envelope {
	t.Helper()
	e, err := c.queryEnvelope(LabelsToName(codec.BuildUploadCallName(NameToLabels(testZone), "echo", id, parts, nonce, sig)), dns.TypeTXT)
	if err != nil {
		t.Fatal(err)
	}
	return e
}

func TestUploadPartRules(t *testing.T) {
	us := newUploadServer(t, nil, func(s *Server) *Server { return s.WithUploadLimits(UploadLimits{MaxParts: 4}) })
	c := us.client
	nonce := func() string { n, _ := codec.RandomNonce(); return n }

	// Out of order is fine; a missing part is named.
	putPart(t, c, "up1", 2, []byte("cc"))
	putPart(t, c, "up1", 0, []byte("aa"))
	if e := callUpload(t, c, "up1", 3, "", nonce()); e.Status != codec.StatusError || !strings.Contains(e.Error, "missing part 1 of 3") {
		t.Fatalf("missing part: %+v", e)
	}
	// An identical re-send is accepted; different bytes for an index are not.
	if e := putPart(t, c, "up1", 1, []byte("bb")); e.Status != codec.StatusOK {
		t.Fatalf("part 1: %+v", e)
	}
	if e := putPart(t, c, "up1", 1, []byte("bb")); e.Status != codec.StatusOK {
		t.Fatalf("identical re-send: %+v", e)
	}
	if e := putPart(t, c, "up1", 1, []byte("XX")); e.Status != codec.StatusError || !strings.Contains(e.Error, "different content") {
		t.Fatalf("conflicting part: %+v", e)
	}
	if e := callUpload(t, c, "up1", 3, "", nonce()); e.Status != codec.StatusOK || e.Result != sha([]byte("aabbcc")) {
		t.Fatalf("assembled call: %+v", e)
	}
	// The upload is gone once used.
	if e := callUpload(t, c, "up1", 3, "", nonce()); e.Status != codec.StatusError || !strings.Contains(e.Error, "unknown or expired") {
		t.Fatalf("reused upload: %+v", e)
	}
	// Index and part-count bounds.
	if e := putPart(t, c, "up2", 4, []byte("x")); e.Status != codec.StatusError || !strings.Contains(e.Error, "out of range") {
		t.Fatalf("part index 4 of max 4: %+v", e)
	}
	putPart(t, c, "up3", 0, []byte("x"))
	if e := callUpload(t, c, "up3", 5, "", nonce()); e.Status != codec.StatusError || !strings.Contains(e.Error, "out of range") {
		t.Fatalf("5 parts of max 4: %+v", e)
	}
}

func TestUploadSizeLimits(t *testing.T) {
	us := newUploadServer(t, nil, func(s *Server) *Server {
		return s.WithUploadLimits(UploadLimits{MaxBytes: 100, MaxTotal: 150})
	})
	c := us.client
	putPart(t, c, "a", 0, make([]byte, 60))
	if e := putPart(t, c, "a", 1, make([]byte, 60)); e.Status != codec.StatusError || !strings.Contains(e.Error, "size limit") {
		t.Fatalf("upload over 100 bytes: %+v", e)
	}
	putPart(t, c, "b", 0, make([]byte, 80))
	if e := putPart(t, c, "c", 0, make([]byte, 20)); e.Status != codec.StatusError || !strings.Contains(e.Error, "too many uploads") {
		t.Fatalf("store over 150 bytes: %+v", e)
	}
	if count, total := us.srv.uploads.stats(); count != 2 || total != 140 {
		t.Fatalf("stats = %d uploads, %d bytes; want 2, 140", count, total)
	}
}

func TestUploadExpiry(t *testing.T) {
	var offset atomic.Int64
	base := time.Now()
	us := newUploadServer(t, nil, func(s *Server) *Server {
		s = s.WithUploadLimits(UploadLimits{TTL: time.Minute})
		s.uploads.now = func() time.Time { return base.Add(time.Duration(offset.Load())) }
		return s
	})
	putPart(t, us.client, "e", 0, []byte("x"))
	offset.Store(int64(50 * time.Second))
	putPart(t, us.client, "e", 1, []byte("y")) // refreshes the TTL
	offset.Store(int64(100 * time.Second))
	n, _ := codec.RandomNonce()
	if e := callUpload(t, us.client, "e", 2, "", n); e.Status != codec.StatusOK {
		t.Fatalf("within TTL of the last part: %+v", e)
	}
	putPart(t, us.client, "f", 0, []byte("x"))
	offset.Store(int64(200 * time.Second))
	n, _ = codec.RandomNonce()
	if e := callUpload(t, us.client, "f", 1, "", n); e.Status != codec.StatusError || !strings.Contains(e.Error, "unknown or expired") {
		t.Fatalf("after TTL: %+v", e)
	}
}

// TestTamperedPartFailsSignedCall: the signature covers the assembled
// arguments, so substituting a part fails verification.
func TestTamperedPartFailsSignedCall(t *testing.T) {
	secret := []byte("upload-key")
	us := newUploadServer(t, secret, nil)
	nonce, _ := codec.RandomNonce()
	sig := auth.Sign(secret, "echo", nonce, []byte("aabb"), time.Now().Unix())
	putPart(t, us.client, "t", 0, []byte("aa"))
	putPart(t, us.client, "t", 1, []byte("XX")) // attacker's bytes
	if e := callUpload(t, us.client, "t", 2, sig, nonce); e.Status != codec.StatusError || !strings.Contains(e.Error, "invalid signature") {
		t.Fatalf("tampered upload: %+v", e)
	}
	if us.calls.Load() != 0 {
		t.Fatal("handler ran for a tampered upload")
	}
	nonce2, _ := codec.RandomNonce()
	sig2 := auth.Sign(secret, "echo", nonce2, []byte("aabb"), time.Now().Unix())
	putPart(t, us.client, "g", 0, []byte("aa"))
	putPart(t, us.client, "g", 1, []byte("bb"))
	if e := callUpload(t, us.client, "g", 2, sig2, nonce2); e.Status != codec.StatusOK {
		t.Fatalf("genuine upload: %+v", e)
	}
}
