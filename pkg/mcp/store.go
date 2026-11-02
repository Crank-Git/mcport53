package mcp

import (
	"sync"

	"github.com/Crank-Git/mcport53/internal/codec"
)

// storedResult holds an assembled result and its chunk layout.
type storedResult struct {
	data  []byte
	total int // number of chunks
}

// ResultStore holds assembled results by session id so large results can be
// delivered in chunks (protocol §4.2). It is safe for concurrent use.
type ResultStore struct {
	mu   sync.Mutex
	data map[string]storedResult
}

// NewResultStore builds an empty ResultStore.
func NewResultStore() *ResultStore {
	return &ResultStore{data: make(map[string]storedResult)}
}

// Put stores data under a fresh session id and returns that id. The data is
// pre-split into chunks of codec.ChunkSize bytes.
func (s *ResultStore) Put(data []byte) string {
	s.mu.Lock()
	defer s.mu.Unlock()
	session, _ := codec.RandomSession()
	pieces := codec.ChunkPayload(data, codec.ChunkSize)
	s.data[session] = storedResult{data: data, total: len(pieces)}
	return session
}

// Get returns the bytes of a single chunk, the total number of chunks for the
// session, whether more chunks follow, and whether the session and chunk exist.
func (s *ResultStore) Get(session string, chunk int) (data []byte, total int, more bool, ok bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	sr, exists := s.data[session]
	if !exists || chunk < 0 || chunk >= sr.total {
		return nil, 0, false, false
	}
	pieces := codec.ChunkPayload(sr.data, codec.ChunkSize)
	return pieces[chunk], sr.total, chunk < sr.total-1, true
}

// Len returns the number of stored results (for tests and observability).
func (s *ResultStore) Len() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.data)
}
