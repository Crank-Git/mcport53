package mcp

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/Crank-Git/mcport53/internal/auth"
	"github.com/Crank-Git/mcport53/internal/codec"
	"github.com/Crank-Git/mcport53/internal/dns"
	"github.com/Crank-Git/mcport53/internal/testresolver"
)

// serveFull runs srv on UDP+TCP via ListenAndServe and returns its address.
func serveFull(t *testing.T, srv *Server, zone string) string {
	t.Helper()
	h := srv.Handlers()
	ds := srv.ApplyTransport(dns.NewServer(zone, &h).WithDiscovery("127.0.0.1.", 53))
	errc := make(chan error, 1)
	go func() { errc <- ds.ListenAndServe("127.0.0.1:0") }()
	deadline := time.Now().Add(5 * time.Second)
	for ds.Addr() == "" {
		select {
		case err := <-errc:
			t.Fatalf("ListenAndServe: %v", err)
		default:
		}
		if time.Now().After(deadline) {
			t.Fatal("server did not start")
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Cleanup(func() { ds.Shutdown(); <-errc })
	return ds.Addr()
}

// viaResolver returns an Agent that reaches srv only through a real Unbound
// resolver (QNAME minimisation on).
func viaResolver(t *testing.T, srv *Server, opt testresolver.Options) *Agent {
	t.Helper()
	upstream := serveFull(t, srv, agentZone)
	resolver := testresolver.Start(t, upstream, agentZone, opt)
	a := NewAgent(resolver, agentZone)
	a.SetTimeout(5 * time.Second)
	return a
}

func resolverRegistry(t *testing.T) *Registry {
	t.Helper()
	random := make([]byte, 6000)
	_, _ = rand.Read(random)
	big := base64.StdEncoding.EncodeToString(random)
	r := echoRegistry(t)
	_ = r.Register(&Tool{Name: "digest", Call: func(_ context.Context, args []byte) (*codec.Envelope, error) {
		sum := sha256.Sum256(args)
		re, _ := codec.JSONResult(map[string]string{"text": hex.EncodeToString(sum[:])})
		return codec.OK("digest", re, 0), nil
	}})
	_ = r.Register(&Tool{Name: "big", Call: func(_ context.Context, args []byte) (*codec.Envelope, error) {
		text := big
		if string(args) == `"compressible"` {
			text = strings.Repeat("compressible text ", 1500)
		}
		re, _ := codec.JSONResult(map[string]string{"text": text})
		return codec.OK("big", re, 0), nil
	}})
	return r
}

func jsonText(t *testing.T, re *codec.ResultEnvelope) string {
	t.Helper()
	var v map[string]string
	if err := json.Unmarshal([]byte(re.Value), &v); err != nil {
		t.Fatalf("result: %v (%q)", err, re.Value)
	}
	return v["text"]
}

// TestThroughResolver runs every feature that should work through a
// recursive resolver against a real Unbound, with and without DNS 0x20 case
// randomisation (use-caps-for-id).
func TestThroughResolver(t *testing.T) {
	for _, caps := range []bool{false, true} {
		name := "plain"
		if caps {
			name = "0x20"
		}
		t.Run(name, func(t *testing.T) { throughResolver(t, testresolver.Options{CapsForID: caps}) })
	}
}

func throughResolver(t *testing.T, opt testresolver.Options) {
	t.Run("discovery", func(t *testing.T) {
		a := viaResolver(t, NewServer(resolverRegistry(t)), opt)
		doc, err := a.Discovery()
		if err != nil || len(doc.Tools) != 3 {
			t.Fatalf("discovery: %+v %v", doc, err)
		}
	})
	t.Run("call", func(t *testing.T) {
		a := viaResolver(t, NewServer(resolverRegistry(t)), opt)
		re, err := a.Call(context.Background(), "echo", []byte(`{}`))
		if err != nil || !strings.Contains(re.Value, "hi") {
			t.Fatalf("call: %+v %v", re, err)
		}
	})
	t.Run("signed call", func(t *testing.T) {
		keys := auth.NewKeyRegistry([]byte("resolver-key"))
		a := viaResolver(t, NewServer(resolverRegistry(t)).WithKeys(keys), opt)
		if _, err := a.Call(context.Background(), "echo", []byte(`{}`)); err == nil || !strings.Contains(err.Error(), "not signed") {
			t.Fatalf("unsigned call: err = %v, want not signed", err)
		}
		a.WithKeys(keys)
		if _, err := a.Call(context.Background(), "echo", []byte(`{}`)); err != nil {
			t.Fatalf("signed call: %v", err)
		}
	})
	for _, signed := range []bool{false, true} {
		name := "uploaded args"
		if signed {
			name = "uploaded args signed"
		}
		t.Run(name, func(t *testing.T) {
			srv := NewServer(resolverRegistry(t))
			keys := auth.NewKeyRegistry([]byte("upload-key"))
			if signed {
				srv = srv.WithKeys(keys)
			}
			a := viaResolver(t, srv, opt)
			if signed {
				a.WithKeys(keys)
			}
			args, _ := json.Marshal(map[string]string{"doc": strings.Repeat("a long tool argument ", 200)}) // ~4 KB
			sum := sha256.Sum256(args)
			re, err := a.Call(context.Background(), "digest", args)
			if err != nil {
				t.Fatalf("%d-byte call through the resolver: %v", len(args), err)
			}
			if got := jsonText(t, re); got != hex.EncodeToString(sum[:]) {
				t.Fatalf("server received different arguments: digest %s", got)
			}
		})
	}
	for _, mode := range []struct {
		name             string
		compress, cursor bool
		args             string
	}{
		{"chunked", false, false, `{}`},
		{"chunked cursor", false, true, `{}`},
		{"compressed", true, false, `"compressible"`},
		{"compressed chunked cursor", true, true, `{}`},
	} {
		t.Run(mode.name, func(t *testing.T) {
			srv := NewServer(resolverRegistry(t))
			if mode.compress {
				srv = srv.WithCompression()
			}
			if mode.cursor {
				srv = srv.WithCursorPagination()
			}
			direct, _ := countingAgent(t, srv)
			want, err := direct.Call(context.Background(), "big", []byte(mode.args))
			if err != nil {
				t.Fatal(err)
			}
			a := viaResolver(t, srv, opt)
			got, err := a.Call(context.Background(), "big", []byte(mode.args))
			if err != nil {
				t.Fatalf("via resolver: %v", err)
			}
			if jsonText(t, got) != jsonText(t, want) {
				t.Fatal("result through the resolver differs from the direct result")
			}
		})
	}
}

// TestLargeDiscoveryThroughResolver: a discovery document larger than a
// 1232-byte UDP answer makes Unbound retry over TCP to the server.
func TestLargeDiscoveryThroughResolver(t *testing.T) {
	r := NewRegistry()
	for i := 0; i < 20; i++ {
		_ = r.Register(&Tool{
			Name:        fmt.Sprintf("tool%02d", i),
			Description: "a tool with a description long enough to make the discovery document large",
			InputSchema: []byte(`{"type":"object","properties":{"text":{"type":"string"}},"required":["text"]}`),
			Call:        func(context.Context, []byte) (*codec.Envelope, error) { return codec.OK("t", "{}", 0), nil },
		})
	}
	a := viaResolver(t, NewServer(r), testresolver.Options{CapsForID: true})
	doc, err := a.Discovery()
	if err != nil || len(doc.Tools) != 20 {
		t.Fatalf("discovery of 20 tools through the resolver: %d tools, %v", len(doc.Tools), err)
	}
	b, _ := json.Marshal(doc)
	if len(b) < 2000 {
		t.Fatalf("fixture too small to need TCP: %d bytes", len(b))
	}
}

// TestTSIGDoesNotSurviveAResolver documents a limitation: TSIG authenticates
// one hop. A recursive resolver does not forward the client's TSIG record,
// so a server that requires TSIG rejects calls that arrive through one. Use
// HMAC call signing (§7), which is end to end, on the resolver path.
func TestTSIGDoesNotSurviveAResolver(t *testing.T) {
	srv := NewServer(resolverRegistry(t)).WithTSIG("mcport53.", []byte("tsig-secret"))
	upstream := serveFull(t, srv, agentZone)
	resolver := testresolver.Start(t, upstream, agentZone, testresolver.Options{})
	a := NewAgent(resolver, agentZone)
	a.SetTimeout(3 * time.Second)
	_, err := a.Call(context.Background(), "echo", []byte(`{}`))
	if err == nil {
		t.Fatal("a TSIG-only server accepted a call relayed by a resolver")
	}
	if !strings.Contains(err.Error(), "not signed with the required TSIG key") {
		t.Fatalf("err = %v, want the server to see the relayed query unsigned", err)
	}
}
