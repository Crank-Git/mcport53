package mcp

import (
	"errors"
	"testing"
	"time"

	"github.com/Crank-Git/mcport53/internal/auth"
	"github.com/Crank-Git/mcport53/internal/codec"
	"github.com/Crank-Git/mcport53/internal/dns"
)

func TestHMACVerifyDefaults(t *testing.T) {
	// Zero window / maxNonces should fall back to the documented defaults
	// without panicking.
	fn := HMACVerify([]byte("secret"), 0, 0)
	if fn == nil {
		t.Fatal("HMACVerify returned nil hook")
	}
}

func TestHMACVerifySignedOK(t *testing.T) {
	secret := []byte("shared-top-secret")
	fn := HMACVerify(secret, time.Minute, 128)
	nonce, _ := codec.RandomNonce()
	args := []byte(`{"text":"hi"}`)
	sig := auth.Sign(secret, "echo", nonce, args, time.Now().Unix())

	req := &dns.CallRequest{Tool: "echo", Nonce: nonce, Sig: sig, Args: args, Caller: "1.2.3.4:1"}
	if err := fn(req); err != nil {
		t.Fatalf("signed call: %v", err)
	}
}

func TestHMACVerifyUnsigned(t *testing.T) {
	fn := HMACVerify([]byte("secret"), time.Minute, 128)
	req := &dns.CallRequest{Tool: "echo", Nonce: "n1", Sig: "", Args: nil, Caller: "1.2.3.4:1"}
	err := fn(req)
	if err == nil {
		t.Fatal("unsigned call: expected error")
	}
	if !errors.Is(err, auth.ErrUnsigned) {
		t.Errorf("error = %v, want ErrUnsigned", err)
	}
}

func TestHMACVerifyInvalidSig(t *testing.T) {
	fn := HMACVerify([]byte("secret"), time.Minute, 128)
	req := &dns.CallRequest{Tool: "echo", Nonce: "n1", Sig: "not-base32!!", Args: nil, Caller: "1.2.3.4:1"}
	err := fn(req)
	if err == nil {
		t.Fatal("malformed signature: expected error")
	}
	if !errors.Is(err, auth.ErrInvalidSig) {
		t.Errorf("error = %v, want ErrInvalidSig", err)
	}
}

func TestHMACVerifyTampered(t *testing.T) {
	secret := []byte("shared-top-secret")
	fn := HMACVerify(secret, time.Minute, 128)
	nonce, _ := codec.RandomNonce()
	args := []byte(`{"text":"hi"}`)
	sig := auth.Sign(secret, "echo", nonce, args, time.Now().Unix())
	tampered := []byte(`{"text":"evil"}`)

	req := &dns.CallRequest{Tool: "echo", Nonce: nonce, Sig: sig, Args: tampered, Caller: "1.2.3.4:1"}
	err := fn(req)
	if err == nil {
		t.Fatal("tampered args: expected error")
	}
	if !errors.Is(err, auth.ErrInvalidSig) {
		t.Errorf("error = %v, want ErrInvalidSig", err)
	}
}

func TestHMACVerifyReplay(t *testing.T) {
	secret := []byte("shared-top-secret")
	fn := HMACVerify(secret, time.Minute, 128)
	nonce, _ := codec.RandomNonce()
	args := []byte(`{"text":"hi"}`)
	sig := auth.Sign(secret, "echo", nonce, args, time.Now().Unix())
	req := &dns.CallRequest{Tool: "echo", Nonce: nonce, Sig: sig, Args: args, Caller: "1.2.3.4:1"}

	if err := fn(req); err != nil {
		t.Fatalf("first signed call: %v", err)
	}
	// Replay the exact same request (same nonce).
	err := fn(req)
	if err == nil {
		t.Fatal("replayed call: expected error")
	}
	if !errors.Is(err, errReplay) {
		t.Errorf("error = %v, want errReplay", err)
	}
}

func TestHMACVerifyStale(t *testing.T) {
	secret := []byte("shared-top-secret")
	fn := HMACVerify(secret, time.Minute, 128)
	nonce, _ := codec.RandomNonce()
	args := []byte(`{"text":"hi"}`)
	// Sign with a timestamp far in the past.
	sig := auth.Sign(secret, "echo", nonce, args, time.Now().Unix()-3600)
	req := &dns.CallRequest{Tool: "echo", Nonce: nonce, Sig: sig, Args: args, Caller: "1.2.3.4:1"}
	err := fn(req)
	if err == nil {
		t.Fatal("stale timestamp: expected error")
	}
	if !errors.Is(err, auth.ErrStale) {
		t.Errorf("error = %v, want ErrStale", err)
	}
}
