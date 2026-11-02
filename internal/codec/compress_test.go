package codec

import (
	"bytes"
	"testing"
)

func TestGzipRoundTrip(t *testing.T) {
	cases := [][]byte{
		{},
		[]byte("hello over dns"),
		bytes.Repeat([]byte("abcabcabc "), 50), // highly compressible
	}
	for _, in := range cases {
		enc, err := CompressResult(CompressionGzip, in)
		if err != nil {
			t.Fatalf("compress: %v", err)
		}
		dec, err := DecompressResult(CompressionGzip, enc)
		if err != nil {
			t.Fatalf("decompress: %v", err)
		}
		if !bytes.Equal(dec, in) {
			t.Fatalf("round trip mismatch: got %q want %q", dec, in)
		}
	}
}

func TestGzipShrinksRepetitive(t *testing.T) {
	in := bytes.Repeat([]byte("the quick brown fox "), 40)
	enc, err := CompressResult(CompressionGzip, in)
	if err != nil {
		t.Fatalf("compress: %v", err)
	}
	// base64 is ~4/3 the raw compressed size; gzip should still beat the input.
	if len(enc) >= len(in) {
		t.Fatalf("gzip did not shrink: enc=%d in=%d", len(enc), len(in))
	}
}

func TestCompressorForUnknown(t *testing.T) {
	if _, err := CompressorFor(CompressionZstd); err == nil {
		t.Fatal("expected an error for the unregistered zstd kind")
	}
	if _, err := CompressResult(CompressionZstd, []byte("x")); err == nil {
		t.Fatal("expected an error compressing with an unregistered kind")
	}
	if _, err := DecompressResult(CompressionZstd, "notbase64!!"); err == nil {
		t.Fatal("expected an error decompressing with an unregistered kind")
	}
}

func TestDecompressBadBase64(t *testing.T) {
	if _, err := DecompressResult(CompressionGzip, "!!not-base64!!"); err == nil {
		t.Fatal("expected an error for non-base64 value")
	}
}

func TestDecompressBadGzip(t *testing.T) {
	// Valid base64 that is not a gzip stream.
	if _, err := DecompressResult(CompressionGzip, "aGVsbG8gd29ybGQ="); err == nil {
		t.Fatal("expected an error for valid base64 that is not gzip")
	}
}

// A custom compressor exercises the registry so the gzip default is not the only
// path covered.
type flipCompressor struct{}

func (*flipCompressor) Compress(data []byte) ([]byte, error) {
	out := make([]byte, len(data))
	for i, b := range data {
		out[i] = ^b
	}
	return out, nil
}

func (*flipCompressor) Decompress(data []byte) ([]byte, error) {
	out := make([]byte, len(data))
	for i, b := range data {
		out[i] = ^b
	}
	return out, nil
}

func TestRegisterCompressor(t *testing.T) {
	RegisterCompressor("flip", &flipCompressor{})
	enc, err := CompressResult("flip", []byte("secret-payload"))
	if err != nil {
		t.Fatalf("compress: %v", err)
	}
	dec, err := DecompressResult("flip", enc)
	if err != nil {
		t.Fatalf("decompress: %v", err)
	}
	if !bytes.Equal(dec, []byte("secret-payload")) {
		t.Fatalf("flip round trip mismatch: %q", dec)
	}
}
