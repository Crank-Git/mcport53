// Package auth implements the optional shared-secret call authentication for
// MCPort53 (protocol §7). A call is signed with HMAC-SHA256 over the tool,
// arguments, nonce, and a timestamp; the server verifies the signature and,
// together with a ReplayGuard, rejects forged or replayed calls.
//
// The signature label carries the timestamp alongside the MAC:
//
//	label = base32(ts as 5-byte big-endian || HMAC-SHA256(...)[:16])
//
// 21 bytes encode to a 34-character label. Carrying the timestamp lets the
// server verify with a single HMAC instead of searching the window. The MAC is
// truncated to 128 bits, within RFC 2104's guidance (at least half the output).
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

// ErrInvalidSig is returned when the signature label is malformed or its MAC
// does not match the call.
var ErrInvalidSig = errors.New("auth: invalid signature")

// ErrStale is returned when the signature's timestamp falls outside the
// accepted window around now.
var ErrStale = errors.New("auth: timestamp outside accepted window")

// tsBytes and macBytes are the sizes of the signature label's two fields.
const (
	tsBytes  = 5
	macBytes = 16
	sigBytes = tsBytes + macBytes
)

// SigLabelLen is the length of a signature label in characters.
const SigLabelLen = (sigBytes*8 + 4) / 5

var sigEncoding = base32.NewEncoding("abcdefghijklmnopqrstuvwxyz234567").WithPadding(base32.NoPadding)

// Sign computes the signature label for a call, per protocol §7.1:
//
//	mac   = HMAC_SHA256(secret, tool || NUL || argBytes || NUL || nonce || NUL || ts)
//	label = base32(ts_uint40 || mac[:16])
//
// ts is a Unix timestamp in seconds (0 <= ts < 2^40). The returned label is
// safe to use as a single DNS label.
func Sign(secret []byte, tool, nonce string, args []byte, ts int64) string {
	b := make([]byte, sigBytes)
	putUint40(b, uint64(ts))
	copy(b[tsBytes:], macFor(secret, tool, nonce, args, ts))
	return sigEncoding.EncodeToString(b)
}

// SignAt is Sign with a time.Time timestamp.
func SignAt(secret []byte, tool, nonce string, args []byte, t time.Time) string {
	return Sign(secret, tool, nonce, args, t.Unix())
}

// macFor builds the truncated MAC over the canonical signed message.
func macFor(secret []byte, tool, nonce string, args []byte, ts int64) []byte {
	h := hmac.New(sha256.New, secret)
	_, _ = h.Write([]byte(tool))
	_, _ = h.Write([]byte(separator))
	_, _ = h.Write(args)
	_, _ = h.Write([]byte(separator))
	_, _ = h.Write([]byte(nonce))
	_, _ = h.Write([]byte(separator))
	_, _ = fmt.Fprintf(h, "%d", ts)
	return h.Sum(nil)[:macBytes]
}

// ParseSig splits a signature label into its timestamp and MAC. ok is false
// when the label is not well-formed (wrong length or not base32).
func ParseSig(sig string) (ts int64, mac []byte, ok bool) {
	if len(sig) != SigLabelLen {
		return 0, nil, false
	}
	b, err := sigEncoding.DecodeString(strings.ToLower(sig))
	if err != nil || len(b) != sigBytes {
		return 0, nil, false
	}
	return int64(uint40(b)), b[tsBytes:], true
}

// Verify reports whether sig is a valid signature for the given fields made
// at exactly timestamp ts. Comparison is constant-time.
func Verify(secret []byte, sig, tool, nonce string, args []byte, ts int64) bool {
	got, mac, ok := ParseSig(sig)
	if !ok || got != ts {
		return false
	}
	return hmac.Equal(mac, macFor(secret, tool, nonce, args, ts))
}

// Check validates sig for a call received at time now, accepting timestamps
// within +/- window of now. It returns nil on success, ErrUnsigned if the call
// is unsigned, ErrInvalidSig if the label is malformed or the MAC does not
// match, and ErrStale if the carried timestamp is outside the window. It
// computes at most one HMAC, and none for a stale or malformed label.
func Check(secret []byte, sig, tool, nonce string, args []byte, now time.Time, window time.Duration) error {
	if sig == "" {
		return ErrUnsigned
	}
	ts, mac, ok := ParseSig(sig)
	if !ok {
		return ErrInvalidSig
	}
	if d := now.Unix() - ts; d > int64(window.Seconds()) || -d > int64(window.Seconds()) {
		return ErrStale
	}
	if !hmac.Equal(mac, macFor(secret, tool, nonce, args, ts)) {
		return ErrInvalidSig
	}
	return nil
}

func putUint40(b []byte, v uint64) {
	for i := tsBytes - 1; i >= 0; i-- {
		b[i] = byte(v)
		v >>= 8
	}
}

func uint40(b []byte) uint64 {
	var v uint64
	for i := 0; i < tsBytes; i++ {
		v = v<<8 | uint64(b[i])
	}
	return v
}
