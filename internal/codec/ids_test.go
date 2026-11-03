package codec

import (
	"strings"
	"testing"
)

func TestRandomIDLengths(t *testing.T) {
	for _, tc := range []struct {
		name string
		fn   func() (string, error)
		want int
	}{
		{"nonce", RandomNonce, 16},
		{"session", RandomSession, 26},
		{"job", RandomJob, 26},
	} {
		s, err := tc.fn()
		if err != nil {
			t.Fatalf("%s: %v", tc.name, err)
		}
		if len(s) != tc.want {
			t.Errorf("%s = %q (%d chars), want %d", tc.name, s, len(s), tc.want)
		}
		if strings.Trim(s, "abcdefghijklmnopqrstuvwxyz234567") != "" {
			t.Errorf("%s = %q has characters outside a-z2-7", tc.name, s)
		}
	}
	// The spec (§6) requires an 8-16 character nonce.
	if n, _ := RandomNonce(); len(n) < 8 || len(n) > 16 {
		t.Errorf("nonce length %d outside spec range 8-16", len(n))
	}
}

func TestRandomIDsUnique(t *testing.T) {
	seen := make(map[string]bool, 100000)
	for i := 0; i < 100000; i++ {
		n, err := RandomNonce()
		if err != nil {
			t.Fatal(err)
		}
		if seen[n] {
			t.Fatalf("duplicate nonce after %d draws: %s", i, n)
		}
		seen[n] = true
	}
}

func TestRandomBase32DecodesToNBytes(t *testing.T) {
	for n := 1; n <= 32; n++ {
		s, err := RandomBase32(n)
		if err != nil {
			t.Fatal(err)
		}
		b, err := DecodeBase32(s)
		if err != nil || len(b) != n {
			t.Fatalf("RandomBase32(%d) = %q decodes to %d bytes (err %v)", n, s, len(b), err)
		}
	}
}

func TestNameWireLength(t *testing.T) {
	if got := NameWireLength(nil); got != 1 {
		t.Errorf("root = %d, want 1", got)
	}
	if got := NameWireLength([]string{"www", "example", "com"}); got != 17 {
		t.Errorf("www.example.com = %d, want 17", got)
	}
}

func TestCheckName(t *testing.T) {
	if err := CheckName([]string{strings.Repeat("a", 63), "example"}); err != nil {
		t.Errorf("63-byte label: %v", err)
	}
	if err := CheckName([]string{strings.Repeat("a", 64), "example"}); err == nil {
		t.Error("64-byte label accepted")
	}
	// 4 x 63-byte labels = 4*64 + 1 = 257 > 255.
	long := []string{strings.Repeat("a", 63), strings.Repeat("b", 63), strings.Repeat("c", 63), strings.Repeat("d", 63)}
	if err := CheckName(long); err == nil {
		t.Error("257-byte name accepted")
	}
	// Exactly 255: 3 x 63 (192) + one 61-byte label (62) + root = 255.
	exact := []string{strings.Repeat("a", 63), strings.Repeat("b", 63), strings.Repeat("c", 63), strings.Repeat("d", 61)}
	if n := NameWireLength(exact); n != 255 {
		t.Fatalf("fixture is %d bytes", n)
	}
	if err := CheckName(exact); err != nil {
		t.Errorf("255-byte name rejected: %v", err)
	}
}

// TestMaxCallArgsIsTheBoundary checks, across zones and signing, that
// MaxCallArgs bytes fit and one more does not.
func TestMaxCallArgsIsTheBoundary(t *testing.T) {
	nonce, _ := RandomNonce()
	sig := strings.Repeat("s", 34)
	for _, zone := range [][]string{{"example"}, {"mcp", "example", "com"}, {"a-much-longer-zone-label", "example", "org"}} {
		for _, s := range []string{"", sig} {
			max := MaxCallArgs(zone, "echo", nonce, s)
			if max <= 0 {
				t.Fatalf("zone %v sig=%v: max = %d", zone, s != "", max)
			}
			if err := CheckName(BuildCallName(zone, "echo", make([]byte, max), nonce, s)); err != nil {
				t.Errorf("zone %v sig=%v: %d bytes should fit: %v", zone, s != "", max, err)
			}
			if err := CheckName(BuildCallName(zone, "echo", make([]byte, max+1), nonce, s)); err == nil {
				t.Errorf("zone %v sig=%v: %d bytes should not fit", zone, s != "", max+1)
			}
		}
	}
	// A zone that leaves no room at all.
	huge := []string{strings.Repeat("z", 63), strings.Repeat("z", 63), strings.Repeat("z", 63), strings.Repeat("z", 40)}
	if got := MaxCallArgs(huge, "echo", nonce, ""); got != -1 {
		t.Errorf("no-room zone: max = %d, want -1", got)
	}
}
