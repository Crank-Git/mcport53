package dns

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"strings"
	"testing"

	"github.com/miekg/dns"
)

// roundTrip packs payload into a TXT answer with TXTStrings, sends it
// through miekg's wire format, and decodes it with ExtractTXT.
func roundTrip(t testing.TB, payload string) string {
	t.Helper()
	m := new(dns.Msg)
	m.SetQuestion("x.example.", dns.TypeTXT)
	buildTXTResponse(m, m, payload)
	wire, err := m.Pack()
	if err != nil {
		t.Fatalf("pack: %v", err)
	}
	out := new(dns.Msg)
	if err := out.Unpack(wire); err != nil {
		t.Fatalf("unpack: %v", err)
	}
	got, err := ExtractTXT(out)
	if err != nil {
		t.Fatalf("extract: %v", err)
	}
	return got
}

// rawTXTData parses a packed, uncompressed single-question message by hand
// and returns the concatenated TXT character-strings of its first answer:
// the bytes actually on the wire, independent of miekg's presentation layer.
func rawTXTData(t *testing.T, wire []byte) []byte {
	t.Helper()
	off := 12
	skipName := func() {
		for wire[off] != 0 {
			off += int(wire[off]) + 1
		}
		off++
	}
	skipName() // question name
	off += 4   // qtype, qclass
	skipName() // answer owner (uncompressed)
	off += 8   // type, class, ttl
	rdlen := int(binary.BigEndian.Uint16(wire[off:]))
	off += 2
	rdata := wire[off : off+rdlen]
	var out []byte
	for i := 0; i < len(rdata); {
		n := int(rdata[i])
		if n > 255 || i+1+n > len(rdata) {
			t.Fatalf("bad character-string at %d", i)
		}
		out = append(out, rdata[i+1:i+1+n]...)
		i += 1 + n
	}
	return out
}

func TestTXTEveryByteValue(t *testing.T) {
	var all []byte
	for i := 0; i < 256; i++ {
		all = append(all, byte(i))
	}
	payload := string(all) + string(all) // 512 bytes: crosses two string boundaries
	if got := roundTrip(t, payload); got != payload {
		t.Fatalf("byte values not preserved")
	}
}

func TestTXTSpecialCharacters(t *testing.T) {
	for _, p := range []string{
		``, `"`, `\`, `\\`, `\"`, `\065`, `\999`, `{"a":"b\"c"}`,
		"tab\there", "nul\x00byte", "é ünïcode ✓ 日本", `;comment ( paren ) $origin @`,
		strings.Repeat(`\`, 300), strings.Repeat(`"`, 300),
	} {
		if got := roundTrip(t, p); got != p {
			t.Errorf("%q came back as %q", p, got)
		}
	}
}

// TestTXTStringBoundaries checks every length around the 255-byte limit.
func TestTXTStringBoundaries(t *testing.T) {
	for _, n := range []int{1, 254, 255, 256, 509, 510, 511, 1000} {
		b := make([]byte, n)
		_, _ = rand.Read(b)
		p := string(b)
		strs := TXTStrings(p)
		if want := (n + 254) / 255; len(strs) != want {
			t.Errorf("n=%d: %d strings, want %d", n, len(strs), want)
		}
		if got := roundTrip(t, p); got != p {
			t.Errorf("n=%d: payload not preserved", n)
		}
	}
}

// TestTXTWireIsRawPayload: the TXT data on the wire is the payload's exact
// bytes (no base64, no escapes), split into <=255-byte strings.
func TestTXTWireIsRawPayload(t *testing.T) {
	payload := `{"v":1,"status":"ok","result":"{\"kind\":\"json\",\"value\":\"quote \\\" slash \\\\ é\"}"}` + strings.Repeat("x", 600)
	m := new(dns.Msg)
	m.SetQuestion("x.example.", dns.TypeTXT)
	buildTXTResponse(m, m, payload)
	m.Compress = false
	wire, err := m.Pack()
	if err != nil {
		t.Fatal(err)
	}
	if got := rawTXTData(t, wire); !bytes.Equal(got, []byte(payload)) {
		t.Fatalf("wire TXT data differs from payload:\n got %q\nwant %q", got, payload)
	}
	// Wire size is the payload plus one length byte per string: no encoding.
	rdlen := len(payload) + (len(payload)+254)/255
	if !bytes.Contains(wire, []byte(payload[:200])) || len(wire) > 12+2*13+4+10+rdlen+20 {
		t.Fatalf("wire is %d bytes for a %d-byte payload", len(wire), len(payload))
	}
}

func TestUnescapeTXTErrors(t *testing.T) {
	for _, bad := range []string{`\`, `abc\`, `\1`, `\12`, `\25a`, `\256`, `\999`} {
		if _, err := unescapeTXT(bad); err == nil {
			t.Errorf("unescapeTXT(%q) accepted", bad)
		}
	}
	if got, err := unescapeTXT(`a\"b\\c\065\010`); err != nil || string(got) != "a\"b\\cA\n" {
		t.Fatalf("got %q %v", got, err)
	}
}

func FuzzTXTRoundTrip(f *testing.F) {
	f.Add("")
	f.Add(`{"a":"\"\\"}`)
	f.Add(strings.Repeat("\xff", 300))
	f.Fuzz(func(t *testing.T, p string) {
		if len(p) > 4000 {
			return
		}
		if got := roundTrip(t, p); got != p {
			t.Fatalf("%q came back as %q", p, got)
		}
		_, _ = unescapeTXT(p) // never panics on arbitrary input
	})
}
