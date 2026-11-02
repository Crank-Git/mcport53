// Command mcp53-server runs an authoritative MCPort53 DNS server that exposes a
// built-in set of MCP tools (protocol §11).
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"

	"github.com/Crank-Git/mcport53/internal/auth"
	"github.com/Crank-Git/mcport53/internal/dns"
	"github.com/Crank-Git/mcport53/pkg/mcp"
	sdkmcp "github.com/modelcontextprotocol/go-sdk/mcp"
)

func main() {
	var (
		zone     = flag.String("zone", "example.", "authoritative base domain (tool zone)")
		addr     = flag.String("addr", "127.0.0.1:5333", "listen address (host:port)")
		secret   = flag.String("secret", "", "optional shared secret for HMAC call signatures (protocol §7)")
		key      = flag.String("key", "", "default HMAC key for per-tool call signatures and signed discovery (protocol §8)")
		keys     = flag.String("keys", "", "optional per-tool key overrides as tool=key,tool=key (protocol §8)")
		discover = flag.String("discover", "127.0.0.1:53", "SRV target advertised in discovery (host:port)")
	)
	flag.Parse()

	discoverHost, discoverPort, err := parseDiscover(*discover)
	if err != nil {
		log.Fatalf("mcp53-server: %v", err)
	}

	registry := registerDefaultTools()
	server := mcp.NewServer(registry)
	switch {
	case *key != "":
		perTool, err := parseKeys(*keys)
		if err != nil {
			log.Fatalf("mcp53-server: %v", err)
		}
		reg := auth.NewKeyRegistry([]byte(*key))
		for tool, secret := range perTool {
			reg.Add(tool, []byte(secret))
		}
		server.WithKeys(reg)
		server.WithDiscoveryKey([]byte(*key))
	case *secret != "":
		server.WithVerify(mcp.HMACVerify([]byte(*secret), 0, 0))
	}

	handlers := server.Handlers()
	dnsSrv := dns.NewServer(*zone, &handlers)
	dnsSrv = dnsSrv.WithDiscovery(discoverHost, discoverPort)

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, os.Interrupt, syscall.SIGTERM)

	go func() {
		log.Printf("mcp53-server: listening on %s for zone %s (%d tools)", *addr, *zone, registry.Len())
		if err := dnsSrv.ListenAndServe(*addr); err != nil {
			log.Fatalf("mcp53-server: %v", err)
		}
	}()

	<-stop
	log.Println("mcp53-server: shutting down")
}

// registerDefaultTools builds a registry with a small set of example MCP tools
// for demonstration and testing.
func registerDefaultTools() *mcp.Registry {
	registry := mcp.NewRegistry()

	_ = registry.AddMCPTool(&sdkmcp.Tool{
		Name:        "add",
		Description: "Add two numbers and return their sum.",
		InputSchema: json.RawMessage(`{"type":"object","properties":{"a":{"type":"number"},"b":{"type":"number"}},"required":["a","b"]}`),
	}, func(ctx context.Context, req *sdkmcp.CallToolRequest) (*sdkmcp.CallToolResult, error) {
		var args struct {
			A float64 `json:"a"`
			B float64 `json:"b"`
		}
		if err := json.Unmarshal(req.Params.Arguments, &args); err != nil {
			return &sdkmcp.CallToolResult{
				Content: []sdkmcp.Content{&sdkmcp.TextContent{Text: "invalid arguments"}},
				IsError: true,
			}, nil
		}
		return textResult(fmt.Sprintf("%g", args.A+args.B)), nil
	})

	_ = registry.AddMCPTool(&sdkmcp.Tool{
		Name:        "echo",
		Description: "Return the supplied text unchanged.",
		InputSchema: json.RawMessage(`{"type":"object","properties":{"text":{"type":"string"}},"required":["text"]}`),
	}, func(ctx context.Context, req *sdkmcp.CallToolRequest) (*sdkmcp.CallToolResult, error) {
		var args struct {
			Text string `json:"text"`
		}
		if err := json.Unmarshal(req.Params.Arguments, &args); err != nil {
			return &sdkmcp.CallToolResult{
				Content: []sdkmcp.Content{&sdkmcp.TextContent{Text: "invalid arguments"}},
				IsError: true,
			}, nil
		}
		return textResult(args.Text), nil
	})

	_ = registry.AddMCPTool(&sdkmcp.Tool{
		Name:        "upper",
		Description: "Return the supplied text in uppercase.",
		InputSchema: json.RawMessage(`{"type":"object","properties":{"text":{"type":"string"}},"required":["text"]}`),
	}, func(ctx context.Context, req *sdkmcp.CallToolRequest) (*sdkmcp.CallToolResult, error) {
		var args struct {
			Text string `json:"text"`
		}
		if err := json.Unmarshal(req.Params.Arguments, &args); err != nil {
			return &sdkmcp.CallToolResult{
				Content: []sdkmcp.Content{&sdkmcp.TextContent{Text: "invalid arguments"}},
				IsError: true,
			}, nil
		}
		return textResult(strings.ToUpper(args.Text)), nil
	})

	return registry
}

// textResult builds a text-only CallToolResult.
func textResult(text string) *sdkmcp.CallToolResult {
	return &sdkmcp.CallToolResult{
		Content: []sdkmcp.Content{&sdkmcp.TextContent{Text: text}},
	}
}

// parseKeys parses a "tool=key,tool=key" string into a map of tool name to
// per-tool secret (protocol §8). An empty string yields a nil map; a malformed
// entry (missing '=') returns an error so a bad --keys value is caught at startup.
func parseKeys(s string) (map[string]string, error) {
	out := map[string]string{}
	s = strings.TrimSpace(s)
	if s == "" {
		return nil, nil
	}
	for _, pair := range strings.Split(s, ",") {
		pair = strings.TrimSpace(pair)
		if pair == "" {
			continue
		}
		tool, secret, ok := strings.Cut(pair, "=")
		if !ok {
			return nil, fmt.Errorf("invalid --keys entry %q: want tool=key", pair)
		}
		out[strings.ToLower(strings.TrimSpace(tool))] = secret
	}
	return out, nil
}

// parseDiscover parses a "host:port" string into the SRV target host and port
// advertised in discovery (protocol §2.1). It errors on a malformed host:port or
// an out-of-range port so a bad --discover fails fast instead of at query time.
func parseDiscover(s string) (string, uint16, error) {
	host, portStr, err := net.SplitHostPort(s)
	if err != nil {
		return "", 0, fmt.Errorf("invalid --discover %q: %w", s, err)
	}
	port, err := strconv.ParseUint(portStr, 10, 16)
	if err != nil {
		return "", 0, fmt.Errorf("invalid --discover port %q: %w", portStr, err)
	}
	return host, uint16(port), nil
}
