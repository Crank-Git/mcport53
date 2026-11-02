package codec

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"testing"
)

func equalStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func TestBase32RoundTrip(t *testing.T) {
	cases := [][]byte{
		{},
		{0x00},
		[]byte("hello world over dns"),
		bytes.Repeat([]byte{0xAB}, 100),
	}
	for _, in := range cases {
		enc := EncodeBase32(in)
		// Only a-z2-7 allowed.
		for _, r := range enc {
			if !((r >= 'a' && r <= 'z') || (r >= '2' && r <= '7')) {
				t.Fatalf("non-alphabet char %q in %q", r, enc)
			}
		}
		// No label should exceed 63 chars.
		for _, lbl := range ChunkLabels(enc) {
			if len(lbl) > MaxLabel {
				t.Fatalf("label %q exceeds %d", lbl, MaxLabel)
			}
		}
		dec, err := DecodeBase32(enc)
		if err != nil {
			t.Fatalf("decode %q: %v", enc, err)
		}
		if !bytes.Equal(dec, in) {
			t.Fatalf("round trip mismatch: got %v want %v", dec, in)
		}
	}
}

func TestChunkLabelsLimitsAndRoundTrip(t *testing.T) {
	s := "abcdefghij" // 10 chars repeated to exceed a single label
	big := ""
	for i := 0; i < 10; i++ {
		big += s
	}
	chunks := ChunkLabels(big)
	if len(chunks) == 0 {
		t.Fatal("expected chunks")
	}
	for _, c := range chunks {
		if len(c) > MaxLabel {
			t.Fatalf("chunk %q too long: %d", c, len(c))
		}
	}
	if got := UnchunkLabels(chunks); got != big {
		t.Fatalf("chunk round trip: got %q want %q", got, big)
	}
	if got := UnchunkLabels(ChunkLabels("")); got != "" {
		t.Fatalf("empty chunking: got %q", got)
	}
}

func TestCallNameUnsignedRoundTrip(t *testing.T) {
	zone := []string{"example"}
	args := []byte(`{"text":"hi there"}`)
	nonce, _ := RandomNonce()
	labels := BuildCallName(zone, "echo", args, nonce, "")

	cn, err := ParseCallName(labels)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if cn.Tool != "echo" {
		t.Fatalf("tool = %q, want echo", cn.Tool)
	}
	if !bytes.Equal(cn.Args, args) {
		t.Fatalf("args = %q, want %q", cn.Args, args)
	}
	if cn.Nonce != nonce {
		t.Fatalf("nonce = %q, want %q", cn.Nonce, nonce)
	}
	if cn.Sig != "" {
		t.Fatalf("sig = %q, want empty", cn.Sig)
	}
	if !equalStrings(cn.Zone, zone) {
		t.Fatalf("zone = %v, want %v", cn.Zone, zone)
	}
}

func TestCallNameSignedRoundTrip(t *testing.T) {
	zone := []string{"mcp", "example"}
	args := []byte(`{"n":42}`)
	nonce, _ := RandomNonce()
	sig := EncodeBase32([]byte("signaturesignaturesig")) // 31 chars, one label
	labels := BuildCallName(zone, "compute", args, nonce, sig)

	cn, err := ParseCallName(labels)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if cn.Tool != "compute" {
		t.Fatalf("tool = %q", cn.Tool)
	}
	if !bytes.Equal(cn.Args, args) {
		t.Fatalf("args = %q, want %q", cn.Args, args)
	}
	if cn.Sig != sig {
		t.Fatalf("sig = %q, want %q", cn.Sig, sig)
	}
	if cn.Nonce != nonce {
		t.Fatalf("nonce mismatch")
	}
	if !equalStrings(cn.Zone, zone) {
		t.Fatalf("zone = %v", cn.Zone)
	}
}

func TestCallNameEmptyArgs(t *testing.T) {
	zone := []string{"example"}
	nonce, _ := RandomNonce()
	labels := BuildCallName(zone, "ping", nil, nonce, "")
	cn, err := ParseCallName(labels)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if cn.Tool != "ping" || len(cn.Args) != 0 {
		t.Fatalf("unexpected: tool=%q args=%v", cn.Tool, cn.Args)
	}
}

func TestParseCallNameErrors(t *testing.T) {
	if _, err := ParseCallName([]string{"echo", "nonce", "example"}); err == nil {
		t.Fatal("expected error for missing call label")
	}
	if _, err := ParseCallName([]string{"call", "nonce", "example"}); err == nil {
		t.Fatal("expected error for missing tool")
	}
	if _, err := ParseCallName([]string{"a", "echo", "call", "example"}); err == nil {
		t.Fatal("expected error for missing nonce/zone")
	}
}

func TestChunkNameRoundTrip(t *testing.T) {
	zone := []string{"example"}
	name := ChunkName(zone, "sess123", 2)
	chunk, session, z, err := ParseChunkName(name)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if chunk != 2 || session != "sess123" || !equalStrings(z, zone) {
		t.Fatalf("got chunk=%d session=%q zone=%v", chunk, session, z)
	}
}

func TestJobNameRoundTrip(t *testing.T) {
	zone := []string{"example"}
	name := JobName(zone, "job99")
	job, z, err := ParseJobName(name)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if job != "job99" || !equalStrings(z, zone) {
		t.Fatalf("got job=%q zone=%v", job, z)
	}
}

func TestEnvelopeMarshalUnmarshal(t *testing.T) {
	e := OK("echo", `{"ok":true}`, 3)
	b, err := e.Marshal()
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	got, err := ParseEnvelope(b)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if got.Status != StatusOK || got.Tool != "echo" || got.Ms != 3 {
		t.Fatalf("unexpected envelope: %+v", got)
	}
	if got.Result != `{"ok":true}` {
		t.Fatalf("result = %q", got.Result)
	}
}

func TestEnvelopeStatuses(t *testing.T) {
	cases := []*Envelope{
		Error("echo", "boom"),
		Queued("long", "j1"),
		Running("long", "j1"),
		Done("long", "j1", "s1"),
		Chunked("big", "s1", 0, 3, true, base64.StdEncoding.EncodeToString([]byte("half"))),
	}
	for _, in := range cases {
		b, _ := in.Marshal()
		got, err := ParseEnvelope(b)
		if err != nil {
			t.Fatalf("parse %+v: %v", in, err)
		}
		if got.Status != in.Status {
			t.Fatalf("status = %q, want %q", got.Status, in.Status)
		}
	}
}

func TestResultSerialization(t *testing.T) {
	js, err := JSONResult(map[string]any{"ok": true, "n": 5})
	if err != nil {
		t.Fatalf("JSONResult: %v", err)
	}
	re, err := ParseResultEnvelope(js)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if re.Kind != KindJSON {
		t.Fatalf("kind = %q", re.Kind)
	}
	var m map[string]any
	if err := json.Unmarshal([]byte(re.Value), &m); err != nil {
		t.Fatalf("result not valid JSON: %v", err)
	}

	txt := TextResult("text/plain", "hello")
	re2, _ := ParseResultEnvelope(txt)
	if re2.Kind != KindText {
		t.Fatalf("text kind = %q", re2.Kind)
	}
	raw2, _ := base64.StdEncoding.DecodeString(re2.Value)
	if string(raw2) != "hello" {
		t.Fatalf("text value = %q", string(raw2))
	}

	bin := BinaryResult("image/png", []byte{0x01, 0x02, 0x03})
	re3, _ := ParseResultEnvelope(bin)
	if re3.Kind != KindBase64 {
		t.Fatalf("bin kind = %q", re3.Kind)
	}
	raw, _ := base64.StdEncoding.DecodeString(re3.Value)
	if !bytes.Equal(raw, []byte{0x01, 0x02, 0x03}) {
		t.Fatalf("bin value wrong: %v", raw)
	}
}

func TestChunkPayload(t *testing.T) {
	data := []byte("0123456789") // 10 bytes
	chunks := ChunkPayload(data, 4)
	if len(chunks) != 3 {
		t.Fatalf("expected 3 chunks, got %d", len(chunks))
	}
	if !bytes.Equal(Assemble(chunks), data) {
		t.Fatalf("assemble mismatch")
	}
	if got := ChunkPayload(nil, 4); got != nil {
		t.Fatalf("empty payload should yield no chunks, got %v", got)
	}
}

func TestRandomIDsNonEmpty(t *testing.T) {
	for name, fn := range map[string]func() (string, error){
		"nonce":   RandomNonce,
		"session": RandomSession,
		"job":     RandomJob,
	} {
		s, err := fn()
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if s == "" {
			t.Fatalf("%s: empty id", name)
		}
	}
}
