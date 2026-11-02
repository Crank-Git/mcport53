// Command mcp53-server runs an authoritative MCPort53 DNS server that exposes a
// built-in set of MCP tools (protocol §11).
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"github.com/Crank-Git/mcport53/internal/dns"
	"github.com/Crank-Git/mcport53/pkg/mcp"
	sdkmcp "github.com/modelcontextprotocol/go-sdk/mcp"
)

func main() {
	var (
		zone   = flag.String("zone", "example.", "authoritative base domain (tool zone)")
		addr   = flag.String("addr", "127.0.0.1:5333", "listen address (host:port)")
		secret = flag.String("secret", "", "optional shared secret for HMAC call signatures (protocol §7)")
	)
	flag.Parse()

	registry := registerDefaultTools()
	server := mcp.NewServer(registry)
	if *secret != "" {
		server.WithVerify(mcp.HMACVerify([]byte(*secret), 0, 0))
	}

	handlers := server.Handlers()
	dnsSrv := dns.NewServer(*zone, &handlers)
	dnsSrv = dnsSrv.WithDiscovery("127.0.0.1.", 53)

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
