package auth

import (
	"strings"
	"testing"
	"time"
)

const testSecret = "shared-top-secret"

var (
	testTool  = "echo"
	testNonce = "xzfrb0nqk8v3m2p7"
	testArgs  = []byte(`{"text":"hi"}`)
)

// b32Label reports whether s is a non-empty label of only the lowercase
// RFC 4648 base32 alphabet (a-z2-7).
func b32Label(s string) bool {
	if s == "" || len(s) > 63 {
		return false
	}
	for _, r := range s {
		if !(r >= 'a' && r <= 'z' || r >= '2' && r <= '7') {
			return false
		}
	}
	return true
}

func TestSignProducesDNSLabel(t *testing.T) {
	sig := Sign([]byte(testSecret), testTool, testNonce, testArgs, 1_700_000_000)
	if !b32Label(sig) {
		t.Fatalf("signature %q is not a DNS-safe <=63 char base32 label", sig)
	}
}

func TestVerifyRoundTrip(t *testing.T) {
	ts := int64(1_700_000_000)
	sig := Sign([]byte(testSecret), testTool, testNonce, testArgs, ts)
	if !Verify([]byte(testSecret), sig, testTool, testNonce, testArgs, ts) {
		t.Fatal("Verify rejected a freshly signed call")
	}
}

func TestVerifyRejectsWrongSecret(t *testing.T) {
	sig := Sign([]byte(testSecret), testTool, testNonce, testArgs, 1_700_000_000)
	if Verify([]byte("wrong-secret"), sig, testTool, testNonce, testArgs, 1_700_000_000) {
		t.Fatal("Verify accepted a signature made with a different secret")
	}
}

func TestVerifyRejectsTamperedFields(t *testing.T) {
	ts := int64(1_700_000_000)
	sig := Sign([]byte(testSecret), testTool, testNonce, testArgs, ts)

	cases := []struct {
		name, tool, nonce string
		args              []byte
		ts                int64
	}{
		{"tool", "different", testNonce, testArgs, ts},
		{"nonce", testTool, "other", testArgs, ts},
		{"args", testTool, testNonce, []byte(`{}`), ts},
		{"ts", testTool, testNonce, testArgs, ts + 1},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if Verify([]byte(testSecret), sig, c.tool, c.nonce, c.args, c.ts) {
				t.Fatalf("Verify accepted a %s mismatch", c.name)
			}
		})
	}
}

func TestCheckWindow(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	sig := Sign([]byte(testSecret), testTool, testNonce, testArgs, now.Unix())

	if err := Check([]byte(testSecret), sig, testTool, testNonce, testArgs, now, time.Minute); err != nil {
		t.Fatalf("Check accepted an in-window signature: %v", err)
	}

	// Stale: signed 2 minutes before now, 1-minute window.
	old := Sign([]byte(testSecret), testTool, testNonce, testArgs, now.Add(-2*time.Minute).Unix())
	if err := Check([]byte(testSecret), old, testTool, testNonce, testArgs, now, time.Minute); err != ErrStale {
		t.Fatalf("Check err = %v, want ErrStale", err)
	}

	// Future: signed 2 minutes ahead, 1-minute window.
	future := Sign([]byte(testSecret), testTool, testNonce, testArgs, now.Add(2*time.Minute).Unix())
	if err := Check([]byte(testSecret), future, testTool, testNonce, testArgs, now, time.Minute); err != ErrStale {
		t.Fatalf("Check err = %v, want ErrStale for future ts", err)
	}
}

func TestCheckUnsigned(t *testing.T) {
	err := Check([]byte(testSecret), "", testTool, testNonce, testArgs, time.Now(), time.Minute)
	if err != ErrUnsigned {
		t.Fatalf("Check err = %v, want ErrUnsigned", err)
	}
}

func TestCheckInvalidSig(t *testing.T) {
	err := Check([]byte(testSecret), "not-a-valid-base32-sig!!!", testTool, testNonce, testArgs, time.Now(), time.Minute)
	if err != ErrInvalidSig {
		t.Fatalf("Check err = %v, want ErrInvalidSig", err)
	}
}

func TestVerifyInWindow(t *testing.T) {
	now := int64(1_700_000_000)
	sig := Sign([]byte(testSecret), testTool, testNonce, testArgs, now-30)
	ts, ok := VerifyInWindow([]byte(testSecret), sig, testTool, testNonce, testArgs, now, 60)
	if !ok || ts != now-30 {
		t.Fatalf("VerifyInWindow = (%d, %v), want (%d, true)", ts, ok, now-30)
	}

	if _, ok := VerifyInWindow([]byte(testSecret), sig, testTool, testNonce, testArgs, now, 10); ok {
		t.Fatal("VerifyInWindow accepted a signature outside its window")
	}
}

// TestSignIsCaseSensitive alphabet guards against accidentally accepting an
// uppercase base32 signature on the wire.
func TestSignIsCaseSensitive(t *testing.T) {
	sig := Sign([]byte(testSecret), testTool, testNonce, testArgs, 1_700_000_000)
	if strings.ContainsAny(sig, "ABCDEFGHIJKLMNOPQRSTUVWXYZ") {
		t.Fatal("Sign emitted uppercase letters; signatures must be lowercase base32")
	}
}
