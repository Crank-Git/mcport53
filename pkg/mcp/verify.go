package mcp

import (
	"errors"
	"time"

	"github.com/Crank-Git/mcport53/internal/auth"
	"github.com/Crank-Git/mcport53/internal/dns"
)

// errReplay is returned when a verified call reuses a nonce.
var errReplay = errors.New("mcp: replay detected")

// DefaultVerifyWindow is the accepted timestamp skew for HMAC verification.
const DefaultVerifyWindow = 5 * time.Minute

// DefaultMaxNonces is the replay-guard cache size when none is supplied.
const DefaultMaxNonces = 4096

// HMACVerify builds a dns.OnVerify hook that requires a valid HMAC signature and
// enforces one-time nonces via a replay guard (protocol §7). Unsigned calls are
// rejected. The replay guard is only consulted after a signature verifies, so
// forged or malformed calls never consume a nonce.
func HMACVerify(secret []byte, window time.Duration, maxNonces int) func(*dns.CallRequest) error {
	if window <= 0 {
		window = DefaultVerifyWindow
	}
	if maxNonces <= 0 {
		maxNonces = DefaultMaxNonces
	}
	guard := auth.NewReplayGuard(maxNonces, window)
	return func(req *dns.CallRequest) error {
		if err := auth.Check(secret, req.Sig, req.Tool, req.Nonce, req.Args, time.Now(), window); err != nil {
			return err
		}
		if !guard.Check(req.Caller, req.Nonce, time.Now()) {
			return errReplay
		}
		return nil
	}
}
