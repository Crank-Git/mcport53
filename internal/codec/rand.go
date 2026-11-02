package codec

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
)

// RandomHex returns n cryptographically random bytes as a lowercase hex string.
func RandomHex(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("codec: reading randomness: %w", err)
	}
	return hex.EncodeToString(b), nil
}

// RandomBase32 returns a lowercase base32 string of roughly n bytes (no padding).
// The caller should treat the returned string as opaque (e.g. a nonce, session,
// or job id). Length is deterministic for a given n.
func RandomBase32(n int) (string, error) {
	hexID, err := RandomHex(n)
	if err != nil {
		return "", err
	}
	return EncodeBase32([]byte(hexID)), nil
}

// RandomNonce returns a short random label (default 12 bytes -> ~20 base32 chars)
// used to make each call query uncacheable and unique.
func RandomNonce() (string, error) { return RandomBase32(12) }

// RandomSession returns a random session id for a large/long-running result.
func RandomSession() (string, error) { return RandomBase32(16) }

// RandomJob returns a random job id for a long-running call.
func RandomJob() (string, error) { return RandomBase32(16) }
