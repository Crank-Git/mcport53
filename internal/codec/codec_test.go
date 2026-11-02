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
	// Signed call name with a nonce but no zone labels.
	if _, err := ParseCallName([]string{"echo", "call", "signed", "nonce"}); err == nil {
		t.Fatal("expected error for a call name with no zone after the nonce")
	}
	// Signed call name with a tool but no args to sign.
	if _, err := ParseCallName([]string{"tool", "call", "signed", "nonce", "example"}); err == nil {
		t.Fatal("expected error for a signed call name with no signature label")
	}
	// A call name whose args decode to invalid base32 (args precede the tool).
	if _, err := ParseCallName([]string{"not-valid-base32!!", "tool", "call", "nonce", "example"}); err == nil {
		t.Fatal("expected error for an undecodable args label")
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
	// A non-positive size falls back to the default ChunkSize (100).
	long := bytes.Repeat([]byte("a"), 250)
	if got := ChunkPayload(long, 0); len(got) != 3 {
		t.Fatalf("ChunkPayload(long, 0) = %d chunks, want 3 (default size 100)", len(got))
	}
	if got := ChunkPayload(long, -1); len(got) != 3 {
		t.Fatalf("ChunkPayload(long, -1) = %d chunks, want 3 (default size 100)", len(got))
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

func TestParseEnvelopeError(t *testing.T) {
	if _, err := ParseEnvelope([]byte("not json")); err == nil {
		t.Fatal("expected a parse error for invalid JSON")
	}
}

func TestParseEnvelopeDefaultsV(t *testing.T) {
	e, err := ParseEnvelope([]byte(`{"status":"ok"}`))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if e.V != 1 {
		t.Errorf("V = %d, want default 1", e.V)
	}
}

func TestParseResultEnvelopeError(t *testing.T) {
	if _, err := ParseResultEnvelope("not json"); err == nil {
		t.Fatal("expected a parse error for invalid JSON")
	}
}

func TestBuildCallNamePanics(t *testing.T) {
	cases := []struct {
		name string
		run  func()
	}{
		{"empty zone", func() { BuildCallName(nil, "echo", nil, "nonce", "") }},
		{"empty tool", func() { BuildCallName([]string{"example"}, "", nil, "nonce", "") }},
		{"empty nonce", func() { BuildCallName([]string{"example"}, "echo", nil, "", "") }},
	}
	for _, c := range cases {
		func() {
			defer func() {
				if recover() == nil {
					t.Errorf("%s: expected a panic", c.name)
				}
			}()
			c.run()
		}()
	}
}

func TestParseChunkNameErrors(t *testing.T) {
	if _, _, _, err := ParseChunkName([]string{"foo", "bar"}); err == nil {
		t.Error("expected error for a missing chunk label")
	}
	if _, _, _, err := ParseChunkName([]string{"chunk", "sess", "example"}); err == nil {
		t.Error("expected error for a chunk label with no index")
	}
	if _, _, _, err := ParseChunkName([]string{"x", "sess", "chunk", "example"}); err == nil {
		t.Error("expected error for a non-numeric chunk index")
	}
	// An empty chunk index is rejected.
	if _, _, _, err := ParseChunkName([]string{"", "sess", "chunk", "example"}); err == nil {
		t.Error("expected error for an empty chunk index")
	}
	// A chunk name with an empty zone suffix.
	if _, _, _, err := ParseChunkName([]string{"0", "sess", "chunk"}); err == nil {
		t.Error("expected error for a chunk name with no zone")
	}
	// A chunk name with an empty session.
	if _, _, _, err := ParseChunkName([]string{"0", "", "chunk", "example"}); err == nil {
		t.Error("expected error for a chunk name with no session")
	}
}

func TestParseJobNameErrors(t *testing.T) {
	if _, _, err := ParseJobName([]string{"job", "example"}); err == nil {
		t.Error("expected error for a job label with no name")
	}
	// A job name with an empty job label.
	if _, _, err := ParseJobName([]string{"", "job", "example"}); err == nil {
		t.Error("expected error for an empty job label")
	}
}

func TestRandomHexLength(t *testing.T) {
	s, err := RandomHex(8)
	if err != nil {
		t.Fatalf("RandomHex: %v", err)
	}
	if len(s) != 16 {
		t.Errorf("RandomHex(8) = %q, want 16 hex chars", s)
	}
}

func TestCursorNameRoundTrip(t *testing.T) {
	zone := []string{"example"}
	name := CursorName(zone, "sess123", "abc123cursor")
	cursor, session, z, err := ParseCursorName(name)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if cursor != "abc123cursor" || session != "sess123" || !equalStrings(z, zone) {
		t.Fatalf("got cursor=%q session=%q zone=%v", cursor, session, z)
	}
}

func TestCursorNameErrors(t *testing.T) {
	// Missing session (cursor directly before the chunk label).
	if _, _, _, err := ParseCursorName([]string{"cursor", "chunk", "example"}); err == nil {
		t.Error("expected error for a cursor name with no session")
	}
	// Missing zone.
	if _, _, _, err := ParseCursorName([]string{"cursor", "sess"}); err == nil {
		t.Error("expected error for a cursor name with no zone")
	}
	// An empty cursor is rejected.
	if _, _, _, err := ParseCursorName([]string{"", "sess", "chunk", "example"}); err == nil {
		t.Error("expected error for a cursor name with an empty cursor")
	}
}

func TestParseResultEnvelopeFromUncompressed(t *testing.T) {
	js, _ := JSONResult(map[string]any{"ok": true})
	env := OK("echo", js, 2)
	// No compression marker: behaves like ParseResultEnvelope.
	if env.Compression != "" {
		t.Fatalf("unexpected compression marker: %q", env.Compression)
	}
	re, err := ParseResultEnvelopeFrom(env)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if re.Kind != KindJSON {
		t.Fatalf("kind = %q, want json", re.Kind)
	}
}

func TestParseResultEnvelopeFromCompressed(t *testing.T) {
	inner, _ := JSONResult(map[string]any{"big": bytes.Repeat([]byte("z"), 20)})
	// Compress the serialized inner result, as a server would (protocol §4.4).
	enc, err := CompressResult(CompressionGzip, []byte(inner))
	if err != nil {
		t.Fatalf("compress: %v", err)
	}
	env := NewEnvelope(StatusOK)
	env.Tool = "echo"
	env.Result = enc
	env.Compression = string(CompressionGzip)
	env.Ms = 4
	b, _ := env.Marshal()
	got, err := ParseEnvelope(b)
	if err != nil {
		t.Fatalf("parse envelope: %v", err)
	}
	if got.Compression != string(CompressionGzip) {
		t.Fatalf("compression = %q, want gzip", got.Compression)
	}
	re, err := ParseResultEnvelopeFrom(got)
	if err != nil {
		t.Fatalf("decompress+parse: %v", err)
	}
	if re.Kind != KindJSON {
		t.Fatalf("kind = %q, want json", re.Kind)
	}
	var gotMap map[string]any
	if err := json.Unmarshal([]byte(re.Value), &gotMap); err != nil {
		t.Fatalf("result not valid JSON after decompress: %v", err)
	}
}

func TestParseResultEnvelopeFromNil(t *testing.T) {
	if _, err := ParseResultEnvelopeFrom(nil); err == nil {
		t.Fatal("expected an error for a nil envelope")
	}
}

func TestParseResultEnvelopeFromBadCompression(t *testing.T) {
	env := OK("echo", `{"kind":"json","value":{}}`, 0)
	env.Compression = "gzip"
	if _, err := ParseResultEnvelopeFrom(env); err == nil {
		t.Fatal("expected an error decompressing invalid gzip data")
	}
}
