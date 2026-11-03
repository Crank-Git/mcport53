package dns

import (
	"errors"
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

// TestCallArgBoundaryOverDNS sends the largest call that fits, then one byte
// more. The first must reach the server intact; the second must fail on the
// client with ErrNameTooLong and never be sent.
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

		before := calls.Load()
		_, err = c.Call(testZone, "echo", append(args, 'a'), "")
		if !errors.Is(err, codec.ErrNameTooLong) {
			t.Fatalf("signed=%v: %d-byte call: err = %v, want ErrNameTooLong", signed, max+1, err)
		}
		if want := "max " + strconv.Itoa(max); !strings.Contains(err.Error(), want) {
			t.Errorf("error %q does not report %q", err, want)
		}
		if calls.Load() != before {
			t.Errorf("signed=%v: an over-long call reached the server", signed)
		}
		t.Logf("signed=%v: max argument size on zone %q is %d bytes", signed, testZone, max)
	}
}
