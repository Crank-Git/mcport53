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
		doh     = flag.String("doh", "", "DNS-over-HTTPS endpoint (RFC 8484); when set, queries go here instead of --server (protocol §12)")
	)
	flag.Parse()

	agent := mcp.NewAgent(*server, *zone)
	agent.SetTimeout(*timeout)
	if *doh != "" {
		agent.WithDoH(*doh)
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
