// Command mcp53-server runs an authoritative MCPort53 DNS server that exposes a
// built-in set of MCP tools.
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

	"github.com/Crank-Git/mcport53/internal/cli"
	"github.com/Crank-Git/mcport53/internal/dns"
	"github.com/Crank-Git/mcport53/pkg/mcp"
	sdkmcp "github.com/modelcontextprotocol/go-sdk/mcp"
)

func main() {
	var (
		zone     = flag.String("zone", "example.", "authoritative base domain (tool zone)")
		addr     = flag.String("addr", "127.0.0.1:5333", "listen address (host:port)")
		secret   = flag.String("secret", "", "optional shared secret for HMAC call signatures (protocol §7)")
		key      = flag.String("key", "", "default HMAC key for per-tool call signatures and signed discovery (protocol §7.3)")
		keys     = flag.String("keys", "", "optional per-tool key overrides as tool=key,tool=key (protocol §7.3)")
		discover = flag.String("discover", "", "SRV target advertised in discovery (host:port; default --addr)")
		tsig     = flag.String("tsig", "", "require TSIG on every query, as name:secret (protocol §8)")
		tlsCert  = flag.String("tls-cert", "", "serve DNS-over-TLS with this PEM certificate (with --tls-key)")
		tlsKey   = flag.String("tls-key", "", "PEM private key for --tls-cert")
		nsName   = flag.String("nameserver", "", "host name for the zone's NS and SOA records (default ns.<zone>); match the delegation")
	)
	flag.Parse()
	if *discover == "" {
		*discover = *addr
	}

	discoverHost, discoverPort, err := parseDiscover(*discover)
	if err != nil {
		log.Fatalf("mcp53-server: %v", err)
	}

	registry := registerDefaultTools()
	server := mcp.NewServer(registry)
	switch {
	case *key != "":
		reg, err := cli.KeyRegistry(*key, *keys)
		if err != nil {
			log.Fatalf("mcp53-server: %v", err)
		}
		server.WithKeys(reg)
		server.WithDiscoveryKey([]byte(*key))
	case *secret != "":
		server.WithVerify(mcp.HMACVerify([]byte(*secret), 0, 0))
	}

	if *tsig != "" {
		name, secret, err := cli.ParseTSIG(*tsig)
		if err != nil {
			log.Fatalf("mcp53-server: %v", err)
		}
		server.WithTSIG(name, secret)
	}
	if *tlsCert != "" || *tlsKey != "" {
		cfg, err := cli.ServerTLS(*tlsCert, *tlsKey)
		if err != nil {
			log.Fatalf("mcp53-server: %v", err)
		}
		server.WithTLS(cfg)
	}

	handlers := server.Handlers()
	dnsSrv := dns.NewServer(*zone, &handlers)
	dnsSrv = dnsSrv.WithDiscovery(discoverHost, discoverPort)
	if *nsName != "" {
		dnsSrv = dnsSrv.WithNameserver(*nsName)
	}
	dnsSrv = server.ApplyTransport(dnsSrv)

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
