package codec

import (
	"bytes"
	"compress/gzip"
	"encoding/base64"
	"fmt"
	"io"
	"sync"
)

// CompressionKind identifies a result compression algorithm used inside a
// result envelope (protocol §4.4). gzip is available via the standard library;
// the registry keeps the door open for more (for example zstd) without a wire
// change.
type CompressionKind string

const (
	CompressionGzip CompressionKind = "gzip"
	// CompressionZstd is reserved for zstd. It needs an external dependency, so
	// it is not registered by default (see RegisterCompressor).
	CompressionZstd CompressionKind = "zstd"
)

// Compressor compresses and decompresses a payload for a given kind.
type Compressor interface {
	Compress([]byte) ([]byte, error)
	Decompress([]byte) ([]byte, error)
}

var (
	compressMu  sync.RWMutex
	compressors = map[CompressionKind]Compressor{}
)

// RegisterCompressor installs a Compressor for kind. gzip is registered by
// default. Registering an existing kind replaces its compressor.
func RegisterCompressor(kind CompressionKind, c Compressor) {
	compressMu.Lock()
	compressors[kind] = c
	compressMu.Unlock()
}

// CompressorFor returns the registered compressor for kind, or an error when
// none is registered.
func CompressorFor(kind CompressionKind) (Compressor, error) {
	compressMu.RLock()
	defer compressMu.RUnlock()
	c, ok := compressors[kind]
	if !ok {
		return nil, fmt.Errorf("codec: no compressor registered for %q", kind)
	}
	return c, nil
}

// CompressResult encodes data with kind and returns a base64 result value
// ready to place in a result envelope.
func CompressResult(kind CompressionKind, data []byte) (string, error) {
	c, err := CompressorFor(kind)
	if err != nil {
		return "", err
	}
	compressed, err := c.Compress(data)
	if err != nil {
		return "", fmt.Errorf("codec: compressing with %q: %w", kind, err)
	}
	return base64.StdEncoding.EncodeToString(compressed), nil
}

// DecompressResult decodes a base64, compressed result value produced by
// CompressResult.
func DecompressResult(kind CompressionKind, value string) ([]byte, error) {
	c, err := CompressorFor(kind)
	if err != nil {
		return nil, err
	}
	raw, err := base64.StdEncoding.DecodeString(value)
	if err != nil {
		return nil, fmt.Errorf("codec: decoding compressed value: %w", err)
	}
	out, err := c.Decompress(raw)
	if err != nil {
		return nil, fmt.Errorf("codec: decompressing with %q: %w", kind, err)
	}
	return out, nil
}

func init() {
	RegisterCompressor(CompressionGzip, &gzipCompressor{})
}

type gzipCompressor struct{}

func (*gzipCompressor) Compress(data []byte) ([]byte, error) {
	var buf bytes.Buffer
	w := gzip.NewWriter(&buf)
	if _, err := w.Write(data); err != nil {
		return nil, fmt.Errorf("codec: gzip compress: %w", err)
	}
	if err := w.Close(); err != nil {
		return nil, fmt.Errorf("codec: gzip close: %w", err)
	}
	return buf.Bytes(), nil
}

func (*gzipCompressor) Decompress(data []byte) ([]byte, error) {
	r, err := gzip.NewReader(bytes.NewReader(data))
	if err != nil {
		return nil, fmt.Errorf("codec: gzip open: %w", err)
	}
	defer r.Close()
	out, err := io.ReadAll(r)
	if err != nil {
		return nil, fmt.Errorf("codec: gzip decompress: %w", err)
	}
	return out, nil
}
