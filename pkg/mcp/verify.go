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
const DefaultMaxNonces = auth.DefaultReplayMaxEntries

// timeNow is the clock used for verification; tests replace it.
var timeNow = time.Now

// replayTTL is how long a nonce must be remembered for a verify window. A
// signature is accepted while |ts - now| <= window, so a call signed at
// now+window stays valid until now+2*window; forgetting its nonce any sooner
// would let it be replayed.
func replayTTL(window time.Duration) time.Duration {
	return 2*window + time.Second
}

// HMACVerifyKeys builds a dns.OnVerify hook that verifies each call with the
// per-tool HMAC key from reg (protocol §7.3): the key registered for the called
// tool, falling back to reg's default. Unsigned calls, signatures made with the
// wrong key, and stale timestamps are rejected, and a replay guard rejects reused
// nonces. reg must be non-nil.
func HMACVerifyKeys(reg *auth.KeyRegistry) func(*dns.CallRequest) error {
	return verifier(DefaultVerifyWindow, DefaultMaxNonces, func(req *dns.CallRequest, now time.Time) error {
		return reg.Check(req.Tool, req.Sig, req.Nonce, req.Args, now, DefaultVerifyWindow)
	})
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
	return verifier(window, maxNonces, func(req *dns.CallRequest, now time.Time) error {
		return auth.Check(secret, req.Sig, req.Tool, req.Nonce, req.Args, now, window)
	})
}

// verifier combines a signature check with a replay guard keyed on the
// (signed) nonce alone, so a captured call cannot be replayed from another
// source address.
func verifier(window time.Duration, maxNonces int, check func(*dns.CallRequest, time.Time) error) func(*dns.CallRequest) error {
	guard := auth.NewReplayGuard(maxNonces, replayTTL(window))
	return func(req *dns.CallRequest) error {
		now := timeNow()
		if err := check(req, now); err != nil {
			return err
		}
		switch err := guard.Check(req.Nonce, now); {
		case errors.Is(err, auth.ErrReplay):
			return errReplay
		case err != nil:
			return err
		}
		return nil
	}
}
