// Package auth implements the optional shared-secret call authentication for
// MCPort53 (protocol §7). A call is signed with HMAC-SHA256 over the tool,
// arguments, nonce, and a timestamp; the server verifies the signature and,
// together with a ReplayGuard, rejects forged or replayed calls.
//
// The 32-byte digest is base32-encoded (RFC 4648, no padding) into a single
// DNS label (53 chars, ≤ MaxLabel) and placed as the leftmost label of the
// call name.
package auth

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base32"
	"errors"
	"fmt"
	"strings"
	"time"
)

// separator is the NUL byte that delimits the signed fields. It is part of the
// signed message, so it must never change without re-signing every call.
const separator = "\x00"

// ErrUnsigned is returned when a call carries no signature but signing is
// required.
var ErrUnsigned = errors.New("auth: call is not signed")

// ErrInvalidSig is returned when the signature does not match any valid
// timestamp within the accepted window.
var ErrInvalidSig = errors.New("auth: invalid signature")

// ErrStale is returned when the signature's timestamp falls outside the
// accepted window around now.
var ErrStale = errors.New("auth: timestamp outside accepted window")

// Sign computes the base32 HMAC-SHA256 signature for a call, per protocol §7.1:
//
//	sig = HMAC_SHA256(secret, tool || NUL || argBytes || NUL || nonce || NUL || ts)
//
// ts is a Unix timestamp in seconds. The returned label is safe to use as a
// single DNS label.
func Sign(secret []byte, tool, nonce string, args []byte, ts int64) string {
	return base32.NewEncoding("abcdefghijklmnopqrstuvwxyz234567").
		WithPadding(base32.NoPadding).
		EncodeToString(signBytes(secret, tool, nonce, args, ts))
}

// SignAt is Sign with a time.Time timestamp.
func SignAt(secret []byte, tool, nonce string, args []byte, t time.Time) string {
	return Sign(secret, tool, nonce, args, t.Unix())
}

// signBytes builds the canonical signed message for secret/tool/nonce/args/ts.
func signBytes(secret []byte, tool, nonce string, args []byte, ts int64) []byte {
	h := hmac.New(sha256.New, secret)
	_, _ = h.Write([]byte(tool))
	_, _ = h.Write([]byte(separator))
	_, _ = h.Write(args)
	_, _ = h.Write([]byte(separator))
	_, _ = h.Write([]byte(nonce))
	_, _ = h.Write([]byte(separator))
	_, _ = fmt.Fprintf(h, "%d", ts)
	return h.Sum(nil)
}

// Verify reports whether sig is a valid signature for the given fields at the
// exact timestamp ts. Comparison is constant-time.
func Verify(secret []byte, sig, tool, nonce string, args []byte, ts int64) bool {
	return hmac.Equal([]byte(Sign(secret, tool, nonce, args, ts)), []byte(sig))
}

// sigDigest decodes a base32 signature into its raw digest. The second return
// reports whether the label was well-formed base32.
func sigDigest(sig string) ([]byte, bool) {
	enc := base32.NewEncoding("abcdefghijklmnopqrstuvwxyz234567").WithPadding(base32.NoPadding)
	b, err := enc.DecodeString(strings.ToLower(sig))
	if err != nil {
		return nil, false
	}
	return b, true
}

// VerifyInWindow recovers the timestamp by trying every second in
// [now-window, now+window] and reports whether any produces a valid signature.
// It returns the matching timestamp and true on success. The signature is
// decoded once; per-candidate comparisons are against the raw digest, so the
// cost is O(window) HMAC-SHA256 operations.
func VerifyInWindow(secret []byte, sig, tool, nonce string, args []byte, now, window int64) (int64, bool) {
	want, ok := sigDigest(sig)
	if !ok {
		return 0, false
	}
	for ts := now - window; ts <= now+window; ts++ {
		if hmac.Equal(signBytes(secret, tool, nonce, args, ts), want) {
			return ts, true
		}
	}
	return 0, false
}

// Check validates sig for a call received at time now, accepting timestamps
// within +/- window of now. It returns nil on success, ErrUnsigned if the call
// is unsigned, ErrInvalidSig if the signature is not well-formed base32, or
// ErrStale if it is well-formed but no timestamp within the window verifies.
func Check(secret []byte, sig, tool, nonce string, args []byte, now time.Time, window time.Duration) error {
	if sig == "" {
		return ErrUnsigned
	}
	if _, ok := sigDigest(sig); !ok {
		return ErrInvalidSig
	}
	if _, ok := VerifyInWindow(secret, sig, tool, nonce, args, now.Unix(), int64(window.Seconds())); !ok {
		return ErrStale
	}
	return nil
}
