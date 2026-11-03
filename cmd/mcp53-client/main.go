// Command mcp53-client issues MCP tool calls over DNS (protocol §11). With no
// --tool it lists the server's tools; with --tool it calls the tool and prints
// the assembled result.
package main

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"time"

	"github.com/Crank-Git/mcport53/internal/cli"
	"github.com/Crank-Git/mcport53/internal/codec"
	"github.com/Crank-Git/mcport53/pkg/mcp"
)

func main() {
	var (
		server  = flag.String("server", "127.0.0.1:5333", "DNS server address (host:port)")
		zone    = flag.String("zone", "example.", "authoritative base domain (tool zone)")
		tool    = flag.String("tool", "", "tool name to call (omit to list tools)")
		args    = flag.String("args", "{}", "JSON arguments for the tool call")
		timeout = flag.Duration("timeout", 5*time.Second, "per-query timeout")
		doh     = flag.String("doh", "", "DNS-over-HTTPS endpoint (RFC 8484); when set, queries go here instead of --server")
		key     = flag.String("key", "", "HMAC key used to sign calls (matches the server's --key or --secret)")
		keys    = flag.String("keys", "", "per-tool HMAC key overrides as tool=key,tool=key")
		verify  = flag.Bool("verify-discovery", false, "reject a discovery document not signed with --key")
		tsig    = flag.String("tsig", "", "sign every query with TSIG, as name:secret")
		useTLS  = flag.Bool("tls", false, "reach the server over DNS-over-TLS")
		tlsCA   = flag.String("tls-ca", "", "PEM file of CA or server certificates to trust for --tls")
		tlsSkip = flag.Bool("tls-insecure", false, "accept any server certificate (testing only)")
	)
	flag.Parse()

	agent, err := buildAgent(agentConfig{
		server: *server, zone: *zone, timeout: *timeout, doh: *doh,
		key: *key, keys: *keys, verify: *verify, tsig: *tsig,
		tls: *useTLS, tlsCA: *tlsCA, tlsInsecure: *tlsSkip,
	})
	if err != nil {
		log.Fatalf("mcp53-client: %v", err)
	}

	if *tool == "" {
		if err := listTools(agent); err != nil {
			log.Fatalf("mcp53-client: %v", err)
		}
		return
	}

	// --args is the raw JSON passed straight to the tool; validate it so a
	// typo surfaces here rather than as an opaque tool error.
	if !json.Valid([]byte(*args)) {
		log.Fatalf("mcp53-client: --args must be valid JSON: %s", *args)
	}
	argBytes, err := parseArgs(*args)
	if err != nil {
		log.Fatalf("mcp53-client: %v", err)
	}

	re, err := agent.Call(context.Background(), *tool, argBytes)
	if err != nil {
		log.Fatalf("mcp53-client: %v", err)
	}

	out, err := renderResult(re)
	if err != nil {
		log.Fatalf("mcp53-client: rendering result: %v", err)
	}
	fmt.Println(out)
}

// agentConfig is the client's transport and security configuration.
type agentConfig struct {
	server, zone string
	timeout      time.Duration
	doh          string
	key, keys    string
	verify       bool
	tsig         string
	tls          bool
	tlsCA        string
	tlsInsecure  bool
}

// buildAgent applies the flags to a new Agent, failing on inconsistent or
// malformed settings before any query is sent.
func buildAgent(c agentConfig) (*mcp.Agent, error) {
	agent := mcp.NewAgent(c.server, c.zone)
	agent.SetTimeout(c.timeout)
	if c.doh != "" {
		agent.WithDoH(c.doh)
	}
	if c.key == "" && (c.keys != "" || c.verify) {
		return nil, fmt.Errorf("--keys and --verify-discovery require --key")
	}
	if c.key != "" {
		reg, err := cli.KeyRegistry(c.key, c.keys)
		if err != nil {
			return nil, err
		}
		agent.WithKeys(reg)
		if c.verify {
			agent.WithDiscoveryKey([]byte(c.key))
		}
	}
	if c.tsig != "" {
		name, secret, err := cli.ParseTSIG(c.tsig)
		if err != nil {
			return nil, err
		}
		agent.WithTSIG(name, secret)
	}
	if !c.tls && (c.tlsCA != "" || c.tlsInsecure) {
		return nil, fmt.Errorf("--tls-ca and --tls-insecure require --tls")
	}
	if c.tls {
		cfg, err := cli.ClientTLS(c.tlsCA)
		if err != nil {
			return nil, err
		}
		agent.WithTLS(cfg)
		if c.tlsInsecure {
			agent.WithInsecureSkipVerify()
		}
	}
	return agent, nil
}

// listTools prints the server's discovery document.
func listTools(agent *mcp.Agent) error {
	doc, err := agent.Discovery()
	if err != nil {
		return err
	}
	fmt.Printf("version %d: %d tool(s)\n\n", doc.Version, len(doc.Tools))
	for _, t := range doc.Tools {
		fmt.Printf("  %-10s %s\n", t.Name, t.Description)
	}
	return nil
}

// renderResult pretty-prints a result envelope. JSON values are re-indented;
// text and binary values are decoded from their base64 form.
func renderResult(re *codec.ResultEnvelope) (string, error) {
	switch re.Kind {
	case codec.KindJSON:
		var v interface{}
		if err := json.Unmarshal([]byte(re.Value), &v); err != nil {
			return "", err
		}
		b, err := json.MarshalIndent(v, "", "  ")
		if err != nil {
			return "", err
		}
		return string(b), nil
	case codec.KindText, codec.KindBase64:
		b, err := base64.StdEncoding.DecodeString(re.Value)
		if err != nil {
			return "", err
		}
		return string(b), nil
	default:
		return re.Value, nil
	}
}

// parseArgs validates the --args flag and returns the raw JSON bytes to send to
// the tool. The bytes are passed straight through, so they must be valid JSON.
func parseArgs(s string) ([]byte, error) {
	if !json.Valid([]byte(s)) {
		return nil, fmt.Errorf("--args must be valid JSON: %s", s)
	}
	return []byte(s), nil
}
