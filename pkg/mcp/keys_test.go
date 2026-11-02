package mcp

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/Crank-Git/mcport53/internal/auth"
	"github.com/Crank-Git/mcport53/internal/codec"
	"github.com/Crank-Git/mcport53/internal/dns"
	sdkmcp "github.com/modelcontextprotocol/go-sdk/mcp"
)

// echoRegistry builds a registry with a single echo tool for auth tests.
func echoRegistry(t *testing.T) *Registry {
	t.Helper()
	reg := NewRegistry()
	_ = reg.AddMCPTool(&sdkmcp.Tool{Name: "echo", Description: "echo text"}, func(ctx context.Context, req *sdkmcp.CallToolRequest) (*sdkmcp.CallToolResult, error) {
		return textResult("hi"), nil
	})
	return reg
}

// A per-tool registry on both sides: the signed call verifies and succeeds.
func TestPerToolCallOK(t *testing.T) {
	reg := echoRegistry(t)
	key := auth.NewKeyRegistry([]byte("shared-default"))
	key.Add("echo", []byte("echo-key"))

	agent := startAgentServerConfig(t, reg, func(s *Server) *Server {
		return s.WithKeys(key)
	}).WithKeys(key)
	re, err := agent.Call(context.Background(), "echo", []byte(`{}`))
	if err != nil {
		t.Fatalf("signed call: %v", err)
	}
	if re.Kind != codec.KindJSON || !strings.Contains(re.Value, "hi") {
		t.Fatalf("unexpected result: %+v", re)
	}
}

// The client signs with one registry but the server verifies against a
// different registry (different per-tool key); the call is rejected.
func TestPerToolWrongKeyRejected(t *testing.T) {
	reg := echoRegistry(t)

	clientKey := auth.NewKeyRegistry([]byte("shared-default"))
	clientKey.Add("echo", []byte("client-echo-key"))

	serverKey := auth.NewKeyRegistry([]byte("shared-default"))
	serverKey.Add("echo", []byte("server-echo-key"))

	agent := startAgentServerConfig(t, reg, func(s *Server) *Server { return s.WithKeys(serverKey) })
	agent.client.WithSigner(clientKey.Sign)
	if _, err := agent.Call(context.Background(), "echo", []byte(`{}`)); err == nil {
		t.Fatal("expected a rejected call when the client and server keys differ")
	}
}

// The default key is used for a tool with no per-tool key on either side.
func TestPerToolDefaultKey(t *testing.T) {
	reg := echoRegistry(t)
	key := auth.NewKeyRegistry([]byte("shared-default")) // no per-tool key for echo

	agent := startAgentServerConfig(t, reg, func(s *Server) *Server { return s.WithKeys(key) })
	agent.WithKeys(key)
	if _, err := agent.Call(context.Background(), "echo", []byte(`{}`)); err != nil {
		t.Fatalf("default-key call: %v", err)
	}
}

// A signed discovery document verifies when both sides share the discovery key.
func TestSignedDiscoveryVerify(t *testing.T) {
	reg := echoRegistry(t)
	key := []byte("discovery-root-key")

	agent := startAgentServerConfig(t, reg, func(s *Server) *Server { return s.WithDiscoveryKey(key) })
	agent.WithDiscoveryKey(key)
	doc, err := agent.Discovery()
	if err != nil {
		t.Fatalf("verified discovery: %v", err)
	}
	if doc.Sig == "" {
		t.Fatal("expected the server to sign the discovery document")
	}
}

// A discovery document signed with a different key fails verification.
func TestSignedDiscoveryWrongKey(t *testing.T) {
	reg := echoRegistry(t)

	serverKey := []byte("server-discovery-key")
	clientKey := []byte("client-discovery-key")

	agent := startAgentServerConfig(t, reg, func(s *Server) *Server { return s.WithDiscoveryKey(serverKey) })
	agent.client.WithDiscoveryKey(clientKey)
	if _, err := agent.Discovery(); err == nil {
		t.Fatal("expected a verification failure for a discovery signed with the wrong key")
	}
}

// Without a discovery key the client does not verify, even if the server signs.
func TestSignedDiscoveryUnverified(t *testing.T) {
	reg := echoRegistry(t)

	agent := startAgentServerConfig(t, reg, func(s *Server) *Server { return s.WithDiscoveryKey([]byte("key")) })
	doc, err := agent.Discovery()
	if err != nil {
		t.Fatalf("unverified discovery: %v", err)
	}
	if doc.Sig == "" {
		t.Fatal("expected the server to sign the discovery document")
	}
}

// HMACVerifyKeys rejects a reused nonce (replay) after the signature verifies.
func TestHMACVerifyKeysReplayRejected(t *testing.T) {
	key := auth.NewKeyRegistry([]byte("shared-default"))
	verify := HMACVerifyKeys(key)

	nonce, _ := codec.RandomNonce()
	args := []byte(`{}`)
	sig := key.Sign("echo", nonce, args, time.Now().Unix())
	req := &dns.CallRequest{Tool: "echo", Args: args, Nonce: nonce, Sig: sig, Caller: "127.0.0.1"}

	if err := verify(req); err != nil {
		t.Fatalf("first verify: %v", err)
	}
	if err := verify(req); err != errReplay {
		t.Fatalf("replay verify err = %v, want errReplay", err)
	}
}

// HMACVerifyKeys rejects an unsigned call when keys are configured.
func TestHMACVerifyKeysUnsignedRejected(t *testing.T) {
	verify := HMACVerifyKeys(auth.NewKeyRegistry([]byte("shared-default")))
	if err := verify(&dns.CallRequest{Tool: "echo", Caller: "127.0.0.1"}); err == nil {
		t.Fatal("expected a rejection of an unsigned call")
	}
}
