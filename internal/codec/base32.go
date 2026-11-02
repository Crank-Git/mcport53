// Package codec implements the MCPort53 on-the-wire encoding: DNS-safe
// lowercase base32 (RFC 4648), label chunking to respect DNS limits, call-name
// construction/parsing, result envelopes, and the chunk/session/job protocol.
package codec

import (
	"encoding/base32"
	"strings"
)

// b32Encoding is the lowercase RFC 4648 base32 alphabet (a–z2–7), no padding.
var b32Encoding = base32.NewEncoding("abcdefghijklmnopqrstuvwxyz234567").WithPadding(base32.NoPadding)

// MaxLabel is the maximum length of a DNS label in bytes (RFC 1035 §5.1).
const MaxLabel = 63

// EncodeBase32 lowercases and returns the no-padding RFC 4648 base32 encoding of b.
func EncodeBase32(b []byte) string {
	return b32Encoding.EncodeToString(b)
}

// DecodeBase32 decodes a lowercase (or uppercase) RFC 4648 base32 string.
func DecodeBase32(s string) ([]byte, error) {
	return b32Encoding.DecodeString(strings.ToLower(strings.TrimSpace(s)))
}

// ChunkLabels splits s into consecutive substrings of at most MaxLabel runes.
// An empty string yields no labels.
func ChunkLabels(s string) []string {
	if s == "" {
		return nil
	}
	var out []string
	for len(s) > 0 {
		n := MaxLabel
		if n > len(s) {
			n = len(s)
		}
		out = append(out, s[:n])
		s = s[n:]
	}
	return out
}

// UnchunkLabels concatenates labels back into a single string in order.
func UnchunkLabels(labels []string) string {
	return strings.Join(labels, "")
}
