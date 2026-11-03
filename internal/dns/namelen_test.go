package dns

import (
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Crank-Git/mcport53/internal/auth"
	"github.com/Crank-Git/mcport53/internal/codec"
)

// argLenServer echoes the decoded argument length and counts calls.
func argLenServer(t *testing.T, verify func(*CallRequest) error) (*Client, *atomic.Int64) {
	t.Helper()
	var calls atomic.Int64
	c := startTestServer(t, &Handlers{
		OnCall: func(req *CallRequest) *codec.Envelope {
			calls.Add(1)
			return codec.OK(req.Tool, strconv.Itoa(len(req.Args)), 0)
		},
		OnVerify: verify,
	})
	return c, &calls
}

// TestCallArgBoundaryOverDNS sends the largest call that fits inline, then one
// byte more (which is uploaded), then more than the upload limit (refused
// locally).
func TestCallArgBoundaryOverDNS(t *testing.T) {
	secret := []byte("k")
	for _, signed := range []bool{false, true} {
		var verify func(*CallRequest) error
		if signed {
			verify = func(r *CallRequest) error {
				return auth.Check(secret, r.Sig, r.Tool, r.Nonce, r.Args, time.Now(), time.Minute)
			}
		}
		c, calls := argLenServer(t, verify)
		sigLen := 0
		if signed {
			c.WithSigner(func(tool, nonce string, args []byte, ts int64) string {
				s := auth.Sign(secret, tool, nonce, args, ts)
				sigLen = len(s)
				return s
			})
		}
		nonce, _ := codec.RandomNonce()
		sig := ""
		if signed {
			sig = auth.Sign(secret, "echo", nonce, nil, 0)
		}
		max := codec.MaxCallArgs(NameToLabels(testZone), "echo", nonce, sig)

		args := make([]byte, max)
		for i := range args {
			args[i] = 'a'
		}
		e, err := c.Call(testZone, "echo", args, "")
		if err != nil || e.Status != codec.StatusOK || e.Result != strconv.Itoa(max) {
			t.Fatalf("signed=%v: %d-byte call: env=%+v err=%v", signed, max, e, err)
		}
		if signed && sigLen != len(sig) {
			t.Fatalf("signature length changed between sizing (%d) and signing (%d)", len(sig), sigLen)
		}

		// One byte more no longer fits inline, so the client uploads the
		// arguments (protocol §3.1): still one call, with every byte intact.
		before := calls.Load()
		e, err = c.Call(testZone, "echo", append(args, 'a'), "")
		if err != nil || e.Status != codec.StatusOK || e.Result != strconv.Itoa(max+1) {
			t.Fatalf("signed=%v: %d-byte call via upload: env=%+v err=%v", signed, max+1, e, err)
		}
		if calls.Load() != before+1 {
			t.Errorf("signed=%v: uploaded call ran the handler %d times, want 1", signed, calls.Load()-before)
		}
		// Beyond the upload limit the client refuses locally.
		before = calls.Load()
		if _, err := c.Call(testZone, "echo", make([]byte, DefaultUploadMaxBytes+1), ""); err == nil || !strings.Contains(err.Error(), "upload limit") {
			t.Errorf("signed=%v: over-limit call: err = %v", signed, err)
		}
		if calls.Load() != before {
			t.Errorf("signed=%v: an over-limit call reached the server", signed)
		}
		t.Logf("signed=%v: max argument size on zone %q is %d bytes", signed, testZone, max)
	}
}
