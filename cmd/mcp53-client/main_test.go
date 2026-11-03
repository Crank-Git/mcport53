package main

import (
	"encoding/base64"
	"testing"

	"github.com/Crank-Git/mcport53/internal/codec"
)

func TestRenderResultJSON(t *testing.T) {
	re := &codec.ResultEnvelope{Kind: codec.KindJSON, Value: `{"b":2,"a":1}`}
	out, err := renderResult(re)
	if err != nil {
		t.Fatalf("render: %v", err)
	}
	want := "{\n  \"a\": 1,\n  \"b\": 2\n}"
	if out != want {
		t.Errorf("renderResult(JSON) = %q, want %q", out, want)
	}
}

func TestRenderResultText(t *testing.T) {
	enc := base64.StdEncoding.EncodeToString([]byte("hi"))
	re := &codec.ResultEnvelope{Kind: codec.KindText, Value: enc}
	out, err := renderResult(re)
	if err != nil {
		t.Fatalf("render: %v", err)
	}
	if out != "hi" {
		t.Errorf("renderResult(text) = %q, want %q", out, "hi")
	}
}

func TestRenderResultBase64(t *testing.T) {
	enc := base64.StdEncoding.EncodeToString([]byte{0x00, 0x01, 0x02})
	re := &codec.ResultEnvelope{Kind: codec.KindBase64, Value: enc}
	out, err := renderResult(re)
	if err != nil {
		t.Fatalf("render: %v", err)
	}
	if out != "\x00\x01\x02" {
		t.Errorf("renderResult(base64) = %q, want raw bytes", out)
	}
}

func TestRenderResultDefault(t *testing.T) {
	re := &codec.ResultEnvelope{Kind: codec.Kind("unknown"), Value: "raw"}
	out, err := renderResult(re)
	if err != nil {
		t.Fatalf("render: %v", err)
	}
	if out != "raw" {
		t.Errorf("renderResult(default) = %q, want %q", out, "raw")
	}
}

func TestRenderResultBadJSON(t *testing.T) {
	re := &codec.ResultEnvelope{Kind: codec.KindJSON, Value: "not json"}
	if _, err := renderResult(re); err == nil {
		t.Fatal("expected a JSON parse error")
	}
}

func TestRenderResultBadBase64(t *testing.T) {
	re := &codec.ResultEnvelope{Kind: codec.KindText, Value: "not base64!"}
	if _, err := renderResult(re); err == nil {
		t.Fatal("expected a base64 decode error")
	}
}

// parseArgs passes valid JSON through unchanged as raw bytes.
func TestParseArgsValid(t *testing.T) {
	got, err := parseArgs(`{"text":"hi"}`)
	if err != nil {
		t.Fatalf("parseArgs: %v", err)
	}
	if string(got) != `{"text":"hi"}` {
		t.Errorf("parseArgs = %q, want raw JSON", got)
	}
}

// parseArgs rejects arguments that are not valid JSON.
func TestParseArgsInvalid(t *testing.T) {
	if _, err := parseArgs("not json"); err == nil {
		t.Fatal("expected an error for invalid JSON args")
	}
}
