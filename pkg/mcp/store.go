package mcp

import (
	"container/list"
	"errors"
	"sync"
	"time"

	"github.com/Crank-Git/mcport53/internal/codec"
)

// Default ResultStore limits.
const (
	DefaultResultTTL         = 5 * time.Minute
	DefaultResultMaxSessions = 4096
	DefaultResultMaxBytes    = 64 << 20 // 64 MiB of stored result payload
)

// errResultTooLarge is returned by Put when a single result exceeds the
// store's byte budget.
var errResultTooLarge = errors.New("mcp: result too large to store")

// ResultLimits bounds a ResultStore. Zero fields take the package defaults.
type ResultLimits struct {
	TTL         time.Duration // how long a session is kept after Put
	MaxSessions int           // most sessions held at once
	MaxBytes    int           // most payload bytes held at once
}

// storedResult holds one result split into chunks, plus its cursor nonce.
type storedResult struct {
	session string
	chunks  [][]byte
	size    int
	expires time.Time
	cursor  string // per-session cursor nonce (protocol §4.4); "" until first use
}

// ResultStore holds assembled results by session id so large results can be
// delivered in chunks (protocol §4.2). It is safe for concurrent use.
//
// Sessions expire after a TTL and the store is bounded by session count and
// total bytes; when a bound is reached the oldest sessions are dropped. A
// dropped session only costs its client a repeated call.
type ResultStore struct {
	limits ResultLimits
	now    func() time.Time

	mu    sync.Mutex
	byID  map[string]*list.Element
	order *list.List // front = newest, back = oldest
	bytes int
}

// NewResultStore builds an empty ResultStore with the default limits.
func NewResultStore() *ResultStore {
	return NewResultStoreWithLimits(ResultLimits{})
}

// NewResultStoreWithLimits builds an empty ResultStore bounded by l.
func NewResultStoreWithLimits(l ResultLimits) *ResultStore {
	if l.TTL <= 0 {
		l.TTL = DefaultResultTTL
	}
	if l.MaxSessions <= 0 {
		l.MaxSessions = DefaultResultMaxSessions
	}
	if l.MaxBytes <= 0 {
		l.MaxBytes = DefaultResultMaxBytes
	}
	return &ResultStore{
		limits: l,
		now:    time.Now,
		byID:   make(map[string]*list.Element),
		order:  list.New(),
	}
}

// Put stores data under a fresh session id and returns that id. The data is
// split into chunks of codec.ChunkSize bytes once, here. Put drops expired
// sessions, then the oldest live ones until the new result fits.
func (s *ResultStore) Put(data []byte) (string, error) {
	if len(data) > s.limits.MaxBytes {
		return "", errResultTooLarge
	}
	session, err := codec.RandomSession()
	if err != nil {
		return "", err
	}
	sr := &storedResult{
		session: session,
		chunks:  codec.ChunkPayload(data, codec.ChunkSize),
		size:    len(data),
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	now := s.now()
	s.expireLocked(now)
	for s.order.Len() >= s.limits.MaxSessions || s.bytes+sr.size > s.limits.MaxBytes {
		s.removeLocked(s.order.Back())
	}
	sr.expires = now.Add(s.limits.TTL)
	s.byID[session] = s.order.PushFront(sr)
	s.bytes += sr.size
	return session, nil
}

// Get returns the bytes of a single chunk, the total number of chunks for the
// session, whether more chunks follow, and whether the session and chunk exist.
func (s *ResultStore) Get(session string, chunk int) (data []byte, total int, more bool, ok bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	sr := s.liveLocked(session)
	if sr == nil || chunk < 0 || chunk >= len(sr.chunks) {
		return nil, 0, false, false
	}
	total = len(sr.chunks)
	return sr.chunks[chunk], total, chunk < total-1, true
}

// cursorNonce returns the session's cursor nonce, creating it with gen on
// first use. It returns ok=false when the session is unknown or expired, so a
// cursor never outlives its session.
func (s *ResultStore) cursorNonce(session string, gen func() (string, error)) (string, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	sr := s.liveLocked(session)
	if sr == nil {
		return "", false
	}
	if sr.cursor == "" && gen != nil {
		ns, err := gen()
		if err != nil {
			return "", false
		}
		sr.cursor = ns
	}
	return sr.cursor, sr.cursor != ""
}

// Len returns the number of stored results (for tests and observability).
func (s *ResultStore) Len() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.order.Len()
}

// Bytes returns the total stored payload size (for tests and observability).
func (s *ResultStore) Bytes() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.bytes
}

// liveLocked returns the session if it exists and has not expired, dropping it
// if it has. Callers must hold s.mu.
func (s *ResultStore) liveLocked(session string) *storedResult {
	el, ok := s.byID[session]
	if !ok {
		return nil
	}
	sr := el.Value.(*storedResult)
	if s.now().After(sr.expires) {
		s.removeLocked(el)
		return nil
	}
	return sr
}

// expireLocked drops every expired session. All sessions share one TTL, so
// they expire in insertion order and the scan stops at the first live one.
func (s *ResultStore) expireLocked(now time.Time) {
	for el := s.order.Back(); el != nil; {
		prev := el.Prev()
		if !now.After(el.Value.(*storedResult).expires) {
			return
		}
		s.removeLocked(el)
		el = prev
	}
}

func (s *ResultStore) removeLocked(el *list.Element) {
	sr := el.Value.(*storedResult)
	s.order.Remove(el)
	delete(s.byID, sr.session)
	s.bytes -= sr.size
}
