package auth

import (
	"sync"
	"time"
)

// KeyRegistry resolves the HMAC key for a tool: a per-tool key when one is
// registered, otherwise a default key (protocol §7.3). This lets a server give
// each tool its own secret rather than a single shared one, and lets a client
// sign each call with the matching key. It is safe for concurrent use.
type KeyRegistry struct {
	mu    sync.RWMutex
	def   []byte
	tools map[string][]byte
}

// NewKeyRegistry builds a registry with def as the default key. A nil default
// means a tool is unsigned unless a per-tool key is registered; verification of
// such a tool therefore rejects unsigned calls.
func NewKeyRegistry(def []byte) *KeyRegistry {
	return &KeyRegistry{def: def, tools: make(map[string][]byte)}
}

// Default returns the registry's default key.
func (r *KeyRegistry) Default() []byte {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.def
}

// For returns the key for tool: the per-tool key if one is registered, else the
// default key.
func (r *KeyRegistry) For(tool string) []byte {
	r.mu.RLock()
	defer r.mu.RUnlock()
	if k, ok := r.tools[tool]; ok {
		return k
	}
	return r.def
}

// Add registers (or replaces) the key for tool.
func (r *KeyRegistry) Add(tool string, key []byte) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.tools[tool] = key
}

// Sign signs a call for tool using that tool's key (protocol §7.1).
func (r *KeyRegistry) Sign(tool, nonce string, args []byte, ts int64) string {
	return Sign(r.For(tool), tool, nonce, args, ts)
}

// Verify reports whether sig is a valid signature for tool using that tool's
// key.
func (r *KeyRegistry) Verify(tool, sig, nonce string, args []byte, ts int64) bool {
	return Verify(r.For(tool), sig, tool, nonce, args, ts)
}

// Check validates a signature for tool received at now, accepting timestamps
// within +/- window, using that tool's key.
func (r *KeyRegistry) Check(tool, sig, nonce string, args []byte, now time.Time, window time.Duration) error {
	return Check(r.For(tool), sig, tool, nonce, args, now, window)
}
