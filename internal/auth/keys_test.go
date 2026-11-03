package auth

import (
	"testing"
	"time"
)

func TestKeyRegistryForDefaultAndPerTool(t *testing.T) {
	reg := NewKeyRegistry([]byte("default-secret"))
	reg.Add("echo", []byte("echo-secret"))

	if got := reg.For("ping"); string(got) != "default-secret" {
		t.Fatalf("For(ping) = %q, want default-secret", got)
	}
	if got := reg.For("echo"); string(got) != "echo-secret" {
		t.Fatalf("For(echo) = %q, want echo-secret", got)
	}
	if string(reg.Default()) != "default-secret" {
		t.Fatalf("Default() = %q, want default-secret", reg.Default())
	}
}

func TestKeyRegistrySignVerifyRoundTrip(t *testing.T) {
	reg := NewKeyRegistry([]byte("default-secret"))
	reg.Add("echo", []byte("echo-secret"))

	nonce := "xzfrb0nqk8v3m2p7"
	args := []byte(`{"text":"hi"}`)
	ts := int64(1_700_000_000)

	// Signed with the per-tool key for echo.
	sig := reg.Sign("echo", nonce, args, ts)
	if !reg.Verify("echo", sig, nonce, args, ts) {
		t.Fatal("Verify rejected a per-tool signature")
	}
	// The same signature is invalid for a different tool's key.
	if reg.Verify("ping", sig, nonce, args, ts) {
		t.Fatal("Verify accepted an echo signature against the default key")
	}
}

func TestKeyRegistrySignUsesPerToolKey(t *testing.T) {
	perTool := []byte("echo-secret")
	reg := NewKeyRegistry([]byte("default-secret"))
	reg.Add("echo", perTool)

	nonce := "xzfrb0nqk8v3m2p7"
	args := []byte(`{}`)
	ts := int64(1_700_000_000)

	sig := reg.Sign("echo", nonce, args, ts)
	// The signature must equal one made directly with the per-tool key, and
	// differ from one made with the default key.
	if sig != Sign(perTool, "echo", nonce, args, ts) {
		t.Fatal("Sign did not use the per-tool key")
	}
	if sig == Sign([]byte("default-secret"), "echo", nonce, args, ts) {
		t.Fatal("Sign used the default key instead of the per-tool key")
	}
}

func TestKeyRegistryCheck(t *testing.T) {
	reg := NewKeyRegistry([]byte("default-secret"))
	reg.Add("echo", []byte("echo-secret"))

	nonce := "xzfrb0nqk8v3m2p7"
	args := []byte(`{}`)
	now := time.Unix(1_700_000_000, 0)
	sig := reg.Sign("echo", nonce, args, now.Unix())

	if err := reg.Check("echo", sig, nonce, args, now, time.Minute); err != nil {
		t.Fatalf("Check accepted an in-window per-tool signature: %v", err)
	}

	// Wrong tool key.
	if err := reg.Check("ping", sig, nonce, args, now, time.Minute); err == nil {
		t.Fatal("Check accepted a signature for the wrong tool")
	}

	// Unsigned.
	if err := reg.Check("echo", "", nonce, args, now, time.Minute); err != ErrUnsigned {
		t.Fatalf("Check err = %v, want ErrUnsigned", err)
	}
}

func TestKeyRegistryReplace(t *testing.T) {
	reg := NewKeyRegistry([]byte("default"))
	reg.Add("echo", []byte("v1"))
	reg.Add("echo", []byte("v2"))
	if got := reg.For("echo"); string(got) != "v2" {
		t.Fatalf("For(echo) = %q, want replaced key v2", got)
	}
}
