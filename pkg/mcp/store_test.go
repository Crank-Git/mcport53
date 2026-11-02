package mcp

import (
	"bytes"
	"testing"

	"github.com/Crank-Git/mcport53/internal/codec"
)

func TestStorePutGetSingle(t *testing.T) {
	s := NewResultStore()
	data := []byte("hello world")
	session := s.Put(data)
	if session == "" {
		t.Fatal("Put returned empty session")
	}
	got, total, more, ok := s.Get(session, 0)
	if !ok {
		t.Fatal("Get returned ok=false for valid session/chunk")
	}
	if total != 1 {
		t.Errorf("total = %d, want 1", total)
	}
	if more {
		t.Error("more = true on single chunk")
	}
	if !bytes.Equal(got, data) {
		t.Errorf("chunk = %q, want %q", got, data)
	}
	if s.Len() != 1 {
		t.Errorf("Len = %d, want 1", s.Len())
	}
}

func TestStorePutGetMulti(t *testing.T) {
	s := NewResultStore()
	// Well above ChunkSize (100) so we get multiple chunks.
	data := bytes.Repeat([]byte("x"), 250)
	session := s.Put(data)

	total := 0
	var assembled bytes.Buffer
	for i := 0; ; i++ {
		got, t2, more, ok := s.Get(session, i)
		if !ok {
			t.Fatalf("Get(chunk %d) ok=false", i)
		}
		assembled.Write(got)
		total = t2
		if !more {
			break
		}
	}
	if total == 0 {
		t.Fatal("total chunks = 0")
	}
	if !bytes.Equal(assembled.Bytes(), data) {
		t.Error("reassembled data does not match original")
	}
}

func TestStoreGetUnknown(t *testing.T) {
	s := NewResultStore()
	if _, _, _, ok := s.Get("missing", 0); ok {
		t.Error("Get(missing session) ok=true, want false")
	}
	session := s.Put([]byte("data"))
	if _, _, _, ok := s.Get(session, 99); ok {
		t.Error("Get(out-of-range chunk) ok=true, want false")
	}
	if _, _, _, ok := s.Get(session, -1); ok {
		t.Error("Get(negative chunk) ok=true, want false")
	}
}

func TestStoreChunkPayloadConsistency(t *testing.T) {
	// Sanity-check that the codec chunking used by the store produces the
	// expected number of pieces for a known size.
	data := bytes.Repeat([]byte("y"), 100)
	pieces := codec.ChunkPayload(data, codec.ChunkSize)
	if len(pieces) != 1 {
		t.Fatalf("ChunkPayload(100) pieces = %d, want 1", len(pieces))
	}
	pieces = codec.ChunkPayload(data, codec.ChunkSize)
	if len(pieces) != 1 {
		t.Fatalf("ChunkPayload(100) pieces = %d, want 1", len(pieces))
	}
}
