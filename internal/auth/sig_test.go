package auth

import (
	"errors"
	"strings"
	"testing"
	"time"
)

func TestSigLabelFormat(t *testing.T) {
	if SigLabelLen != 34 {
		t.Fatalf("SigLabelLen = %d, want 34", SigLabelLen)
	}
	for _, ts := range []int64{0, 1, 1_700_000_000, 1<<40 - 1} {
		sig := Sign([]byte(testSecret), testTool, testNonce, testArgs, ts)
		if len(sig) != SigLabelLen || !b32Label(sig) {
			t.Fatalf("ts=%d: label %q (%d chars)", ts, sig, len(sig))
		}
		got, mac, ok := ParseSig(sig)
		if !ok || got != ts || len(mac) != 16 {
			t.Fatalf("ts=%d: ParseSig = (%d, %d-byte mac, %v)", ts, got, len(mac), ok)
		}
	}
}

// TestCheckWindowBoundary pins the window edges exactly.
func TestCheckWindowBoundary(t *testing.T) {
	secret := []byte(testSecret)
	now := time.Unix(1_800_000_000, 0)
	window := time.Minute
	for _, tc := range []struct {
		offset int64
		want   error
	}{
		{0, nil},
		{60, nil},
		{-60, nil},
		{61, ErrStale},
		{-61, ErrStale},
		{-3600, ErrStale},
	} {
		sig := Sign(secret, testTool, testNonce, testArgs, now.Unix()+tc.offset)
		if err := Check(secret, sig, testTool, testNonce, testArgs, now, window); !errors.Is(err, tc.want) && err != tc.want {
			t.Errorf("offset %+ds: err = %v, want %v", tc.offset, err, tc.want)
		}
	}
}

// TestCheckRejectsTampering covers every field a forger could change.
func TestCheckRejectsTampering(t *testing.T) {
	secret := []byte(testSecret)
	now := time.Unix(1_800_000_000, 0)
	sig := Sign(secret, testTool, testNonce, testArgs, now.Unix())

	// Re-encode the label with a shifted timestamp but the original MAC: the
	// timestamp is covered by the MAC, so this must not verify.
	_, mac, _ := ParseSig(sig)
	b := make([]byte, sigBytes)
	putUint40(b, uint64(now.Unix()-10))
	copy(b[tsBytes:], mac)
	shiftedTS := sigEncoding.EncodeToString(b)

	// Flip one MAC bit.
	b2 := make([]byte, sigBytes)
	putUint40(b2, uint64(now.Unix()))
	copy(b2[tsBytes:], mac)
	b2[sigBytes-1] ^= 1
	flippedMAC := sigEncoding.EncodeToString(b2)

	for _, tc := range []struct {
		name, sig, tool, nonce string
		args                   []byte
		secret                 []byte
	}{
		{"timestamp", shiftedTS, testTool, testNonce, testArgs, secret},
		{"mac", flippedMAC, testTool, testNonce, testArgs, secret},
		{"tool", sig, "other", testNonce, testArgs, secret},
		{"nonce", sig, testTool, "othernonce", testArgs, secret},
		{"args", sig, testTool, testNonce, []byte(`{"text":"evil"}`), secret},
		{"secret", sig, testTool, testNonce, testArgs, []byte("wrong")},
	} {
		if err := Check(tc.secret, tc.sig, tc.tool, tc.nonce, tc.args, now, time.Minute); !errors.Is(err, ErrInvalidSig) {
			t.Errorf("tampered %s: err = %v, want ErrInvalidSig", tc.name, err)
		}
	}
	if err := Check(secret, sig, testTool, testNonce, testArgs, now, time.Minute); err != nil {
		t.Fatalf("untampered: %v", err)
	}
}

func TestCheckMalformedLabels(t *testing.T) {
	secret := []byte(testSecret)
	now := time.Unix(1_800_000_000, 0)
	good := Sign(secret, testTool, testNonce, testArgs, now.Unix())
	if err := Check(secret, "", testTool, testNonce, testArgs, now, time.Minute); err != ErrUnsigned {
		t.Errorf("empty: %v", err)
	}
	for _, bad := range []string{
		good[:SigLabelLen-1],
		good + "a",
		strings.Repeat("a", 52), // old-format length
		strings.Repeat("a", 63),
		good[:SigLabelLen-1] + "1", // '1' is outside base32
		good[:SigLabelLen-1] + "!",
	} {
		if err := Check(secret, bad, testTool, testNonce, testArgs, now, time.Minute); err != ErrInvalidSig {
			t.Errorf("label %q: err = %v, want ErrInvalidSig", bad, err)
		}
	}
}

// TestCheckAcceptsUppercaseLabel: DNS names are case-insensitive and some
// resolvers randomise case, so the label decodes regardless of case.
func TestCheckAcceptsUppercaseLabel(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	sig := Sign([]byte(testSecret), testTool, testNonce, testArgs, now.Unix())
	if err := Check([]byte(testSecret), strings.ToUpper(sig), testTool, testNonce, testArgs, now, time.Minute); err != nil {
		t.Fatalf("uppercase label: %v", err)
	}
}

// TestForgedCheckIsConstantCost: a forged but well-formed label used to cost
// 2*window+1 HMACs (601 for 5 minutes, ~190us). It now costs one.
func TestForgedCheckIsConstantCost(t *testing.T) {
	secret := []byte(testSecret)
	now := time.Now()
	forged := Sign([]byte("attacker"), testTool, testNonce, testArgs, now.Unix())
	const n = 2000
	start := time.Now()
	for i := 0; i < n; i++ {
		_ = Check(secret, forged, testTool, testNonce, testArgs, now, 5*time.Minute)
	}
	per := time.Since(start) / n
	// One HMAC-SHA256 is ~1us (~10us under -race); 601 were ~190us (~2ms).
	if per > 50*time.Microsecond {
		t.Fatalf("forged check costs %v per call; want a single HMAC", per)
	}
	t.Logf("forged check: %v per call", per)
}

func BenchmarkCheckForged(b *testing.B) {
	secret := []byte(testSecret)
	now := time.Now()
	forged := Sign([]byte("attacker"), testTool, testNonce, testArgs, now.Unix())
	for i := 0; i < b.N; i++ {
		_ = Check(secret, forged, testTool, testNonce, testArgs, now, 5*time.Minute)
	}
}

func FuzzCheck(f *testing.F) {
	f.Add(Sign([]byte(testSecret), testTool, testNonce, testArgs, 1_800_000_000))
	f.Add("")
	f.Add(strings.Repeat("z", SigLabelLen))
	f.Fuzz(func(t *testing.T, sig string) {
		_ = Check([]byte(testSecret), sig, testTool, testNonce, testArgs, time.Unix(1_800_000_000, 0), time.Minute)
		_, _, _ = ParseSig(sig)
	})
}
