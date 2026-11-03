package dns

import (
	"bytes"
	"errors"
	"fmt"
	"sync"
	"time"
)

// Upload limits (protocol §3.1).
const (
	DefaultUploadMaxBytes = 64 << 10        // largest assembled argument blob
	DefaultUploadMaxParts = 1024            // most parts in one upload
	DefaultUploadTTL      = 5 * time.Minute // an upload expires this long after its last part
	DefaultUploadMaxTotal = 16 << 20        // all uploads held at once
)

var (
	errUploadConflict = errors.New("dns: upload part already received with different content")
	errUploadTooLarge = errors.New("dns: upload exceeds the size limit")
	errUploadFull     = errors.New("dns: too many uploads in progress")
)

// UploadLimits bounds argument uploads. Zero fields take the defaults.
type UploadLimits struct {
	MaxBytes int           // largest assembled upload
	MaxParts int           // most parts per upload
	TTL      time.Duration // lifetime after the last part
	MaxTotal int           // total bytes across all uploads
}

type upload struct {
	parts   map[int][]byte
	size    int
	expires time.Time
}

// uploadStore holds argument parts until the call that references them
// arrives. It is safe for concurrent use.
type uploadStore struct {
	limits UploadLimits
	now    func() time.Time

	mu    sync.Mutex
	byID  map[string]*upload
	total int
}

func newUploadStore(l UploadLimits) *uploadStore {
	if l.MaxBytes <= 0 {
		l.MaxBytes = DefaultUploadMaxBytes
	}
	if l.MaxParts <= 0 {
		l.MaxParts = DefaultUploadMaxParts
	}
	if l.TTL <= 0 {
		l.TTL = DefaultUploadTTL
	}
	if l.MaxTotal <= 0 {
		l.MaxTotal = DefaultUploadMaxTotal
	}
	return &uploadStore{limits: l, now: time.Now, byID: make(map[string]*upload)}
}

// put records one part. Re-sending a part with the same bytes is accepted
// (resolvers retransmit); different bytes for a received index are rejected.
func (s *uploadStore) put(id string, index int, data []byte) error {
	if index < 0 || index >= s.limits.MaxParts {
		return fmt.Errorf("dns: upload part index %d out of range (max %d parts)", index, s.limits.MaxParts)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	now := s.now()
	s.expireLocked(now)
	u := s.byID[id]
	if u == nil {
		u = &upload{parts: make(map[int][]byte)}
		s.byID[id] = u
	}
	if old, ok := u.parts[index]; ok {
		if !bytes.Equal(old, data) {
			return errUploadConflict
		}
		u.expires = now.Add(s.limits.TTL)
		return nil
	}
	if u.size+len(data) > s.limits.MaxBytes {
		return errUploadTooLarge
	}
	if s.total+len(data) > s.limits.MaxTotal {
		if len(u.parts) == 0 {
			delete(s.byID, id)
		}
		return errUploadFull
	}
	u.parts[index] = append([]byte(nil), data...)
	u.size += len(data)
	s.total += len(data)
	u.expires = now.Add(s.limits.TTL)
	return nil
}

// assemble returns parts 0..parts-1 of upload id concatenated, or an error
// naming the first missing part.
func (s *uploadStore) assemble(id string, parts int) ([]byte, error) {
	if parts < 1 || parts > s.limits.MaxParts {
		return nil, fmt.Errorf("dns: upload of %d parts out of range", parts)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.expireLocked(s.now())
	u := s.byID[id]
	if u == nil {
		return nil, fmt.Errorf("dns: unknown or expired upload %s", id)
	}
	var out []byte
	for i := 0; i < parts; i++ {
		p, ok := u.parts[i]
		if !ok {
			return nil, fmt.Errorf("dns: upload %s is missing part %d of %d", id, i, parts)
		}
		out = append(out, p...)
	}
	return out, nil
}

// remove forgets an upload once its call has run.
func (s *uploadStore) remove(id string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if u, ok := s.byID[id]; ok {
		s.total -= u.size
		delete(s.byID, id)
	}
}

func (s *uploadStore) expireLocked(now time.Time) {
	for id, u := range s.byID {
		if now.After(u.expires) {
			s.total -= u.size
			delete(s.byID, id)
		}
	}
}

// stats reports the number of uploads and total bytes (for tests).
func (s *uploadStore) stats() (int, int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.byID), s.total
}
