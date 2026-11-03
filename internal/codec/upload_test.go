package codec

import (
	"bytes"
	"strings"
	"testing"
)

func TestUploadPartRoundTrip(t *testing.T) {
	zone := []string{"mcp", "example"}
	for _, n := range []int{0, 1, 39, 40, 200} {
		data := bytes.Repeat([]byte{0xA5}, n)
		labels := UploadPartName(zone, "upid", 17, data)
		id, idx, got, err := ParseUploadPart(labels[:len(labels)-len(zone)])
		if err != nil || id != "upid" || idx != 17 || !bytes.Equal(got, data) {
			t.Fatalf("n=%d: id=%q idx=%d len=%d err=%v", n, id, idx, len(got), err)
		}
	}
}

// TestUploadPartDataSpellingStructuralLabels: parsing is anchored on the
// right, so data labels that spell "call", "upload" or "chunk" are data.
func TestUploadPartDataSpellingStructuralLabels(t *testing.T) {
	prefix := []string{"call", "upload", "chunk", "0", "upid", "upload"}
	id, idx, data, err := ParseUploadPart(prefix)
	want, _ := DecodeBase32("calluploadchunk")
	if err != nil || id != "upid" || idx != 0 || !bytes.Equal(data, want) {
		t.Fatalf("id=%q idx=%d data=%x err=%v", id, idx, data, err)
	}
}

func TestParseUploadPartErrors(t *testing.T) {
	for _, p := range [][]string{
		nil, {"upload"}, {"0", "upload"}, {"x", "0", "id", "notupload"},
		{"x", "zz", "id", "upload"}, {"x", "0", "", "upload"}, {"1!", "0", "id", "upload"},
		{"x", "99999999999", "id", "upload"},
	} {
		if _, _, _, err := ParseUploadPart(p); err == nil {
			t.Errorf("ParseUploadPart(%v) accepted", p)
		}
	}
}

func TestUploadCallNameRoundTrip(t *testing.T) {
	zone := []string{"example"}
	for _, sig := range []string{"", strings.Repeat("s", 34)} {
		labels := BuildUploadCallName(zone, "echo", "upid", 12, "nonce", sig)
		cn, err := ParseCallName(labels)
		if err != nil || cn.Upload != "upid" || cn.Parts != 12 || cn.Tool != "echo" || cn.Sig != sig || cn.Nonce != "nonce" || cn.Args != nil {
			t.Fatalf("sig=%v: %+v err=%v", sig != "", cn, err)
		}
	}
	// An inline call is unaffected.
	cn, err := ParseCallName(BuildCallName(zone, "echo", []byte("hi"), "nonce", ""))
	if err != nil || cn.Upload != "" || string(cn.Args) != "hi" {
		t.Fatalf("inline: %+v %v", cn, err)
	}
	for _, bad := range []string{"u-", "u-id", "u-id-", "u--3", "u-id-0", "u-id-x"} {
		if _, err := ParseCallName([]string{bad, "echo", "call", "nonce", "example"}); err == nil {
			t.Errorf("upload ref %q accepted", bad)
		}
	}
}

func TestMaxUploadPart(t *testing.T) {
	zone := []string{"example"}
	id, _ := RandomSession()
	per := MaxUploadPart(zone, id, 4)
	if per < 100 {
		t.Fatalf("per-part capacity %d too small", per)
	}
	if CheckName(UploadPartName(zone, id, 9999, make([]byte, per))) != nil {
		t.Fatal("max part does not fit")
	}
	if CheckName(UploadPartName(zone, id, 9999, make([]byte, per+1))) == nil {
		t.Fatal("max+1 part fits")
	}
	t.Logf("upload part capacity on %v: %d bytes", zone, per)
}
