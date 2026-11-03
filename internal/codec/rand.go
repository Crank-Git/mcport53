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

// RandomBase32 returns n cryptographically random bytes as a lowercase base32
// string (no padding), ceil(8n/5) characters long. The caller should treat the
// returned string as opaque (e.g. a nonce, session, or job id).
func RandomBase32(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("codec: reading randomness: %w", err)
	}
	return EncodeBase32(b), nil
}

// Identifier sizes in random bytes. Call names are limited to 255 bytes, so
// every character spent on an identifier is one fewer for arguments.
const (
	NonceBytes   = 10 // 80 bits -> 16 chars; unique per call within the replay window
	SessionBytes = 16 // 128 bits -> 26 chars; unguessable
	JobBytes     = 16 // 128 bits -> 26 chars; unguessable
)

// RandomNonce returns a random 16-character label used to make each call query
// uncacheable and unique (protocol §6).
func RandomNonce() (string, error) { return RandomBase32(NonceBytes) }

// RandomSession returns a random session id for a large/long-running result.
func RandomSession() (string, error) { return RandomBase32(SessionBytes) }

// RandomJob returns a random job id for a long-running call.
func RandomJob() (string, error) { return RandomBase32(JobBytes) }
