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

// HMACVerifyKeys builds a dns.OnVerify hook that verifies each call with the
// per-tool HMAC key from reg (protocol §8): the key registered for the called
// tool, falling back to reg's default. Unsigned calls, signatures made with the
// wrong key, and stale timestamps are rejected, and a replay guard rejects reused
// nonces. reg must be non-nil.
func HMACVerifyKeys(reg *auth.KeyRegistry) func(*dns.CallRequest) error {
	guard := auth.NewReplayGuard(DefaultMaxNonces, DefaultVerifyWindow)
	return func(req *dns.CallRequest) error {
		if err := reg.Check(req.Tool, req.Sig, req.Nonce, req.Args, time.Now(), DefaultVerifyWindow); err != nil {
			return err
		}
		if !guard.Check(req.Caller, req.Nonce, time.Now()) {
			return errReplay
		}
		return nil
	}
}

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
