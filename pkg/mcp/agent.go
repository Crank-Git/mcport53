package mcp

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"time"

	"github.com/Crank-Git/mcport53/internal/auth"
	"github.com/Crank-Git/mcport53/internal/codec"
	"github.com/Crank-Git/mcport53/internal/dns"
)

// Agent is a high-level MCP-over-DNS client. It wraps a dns.Client and handles
// the discovery, call, and result-assembly flow (protocol §2 / §4), including
// chunked results.
type Agent struct {
	client *dns.Client
	zone   string
}

// NewAgent builds an Agent for the server at serverAddr on the given zone.
func NewAgent(serverAddr, zone string) *Agent {
	return &Agent{client: dns.NewClient(serverAddr), zone: zone}
}

// SetTimeout sets the underlying query timeout.
func (a *Agent) SetTimeout(d time.Duration) {
	a.client.SetTimeout(d)
}

// WithKeys installs per-tool HMAC keys (protocol §8). Every call is signed with
// the key registered for the called tool (falling back to the registry's default
// key). The server must be configured with a matching registry (Server.WithKeys).
func (a *Agent) WithKeys(reg *auth.KeyRegistry) *Agent {
	a.client.WithSigner(reg.Sign)
	return a
}

// WithDiscoveryKey makes Discovery verify signed discovery documents with key
// (protocol §8). When set, Discovery rejects documents that are unsigned or whose
// signature does not verify.
func (a *Agent) WithDiscoveryKey(key []byte) *Agent {
	a.client.WithDiscoveryKey(key)
	return a
}

// WithDoH configures the agent to reach its server over DNS-over-HTTPS (RFC 8484)
// via endpoint (protocol §12). Every query is sent to the DoH endpoint instead of
// the direct server address, which is how an agent reaches the authoritative
// server through a normal resolver.
func (a *Agent) WithDoH(endpoint string) *Agent {
	a.client.WithDoH(endpoint)
	return a
}

// Discovery queries the discovery document (§2.1).
func (a *Agent) Discovery() (*dns.DiscoveryResponse, error) {
	return a.client.Discovery(a.zone)
}

// Call issues a tool call with raw JSON arguments and returns the assembled
// result envelope (§4 / §5). Large results are fetched chunk by chunk.
func (a *Agent) Call(ctx context.Context, tool string, args []byte) (*codec.ResultEnvelope, error) {
	env, err := a.client.Call(a.zone, tool, args, "")
	if err != nil {
		return nil, fmt.Errorf("mcp: calling %s: %w", tool, err)
	}
	switch env.Status {
	case codec.StatusOK:
		return codec.ParseResultEnvelopeFrom(env)
	case codec.StatusChunked:
		if env.Cursor != "" {
			return a.assembleByCursor(env)
		}
		return a.assembleChunks(env)
	case codec.StatusError:
		return nil, fmt.Errorf("mcp: tool %s: %s", tool, env.Error)
	default:
		return nil, fmt.Errorf("mcp: tool %s: unexpected status %q", tool, env.Status)
	}
}

// assembleChunks concatenates the chunks of a chunked result and parses the
// assembled result envelope (protocol §4.2). Chunk 0 is already in first; the
// remaining chunks are fetched by index and each comes back as a chunked
// envelope carrying the next piece of bytes.
func (a *Agent) assembleChunks(first *codec.Envelope) (*codec.ResultEnvelope, error) {
	var raw []byte
	if first.Total <= 0 {
		return nil, errors.New("mcp: chunked result has no chunks")
	}
	// Chunk 0 is in the initial chunked envelope.
	if first.Result != "" {
		b, err := base64.StdEncoding.DecodeString(first.Result)
		if err != nil {
			return nil, fmt.Errorf("mcp: decoding chunk 0: %w", err)
		}
		raw = append(raw, b...)
	}
	for i := 1; i < first.Total; i++ {
		env, err := a.client.Chunk(a.zone, first.Session, i)
		if err != nil {
			return nil, fmt.Errorf("mcp: fetching chunk %d: %w", i, err)
		}
		if env.Status != codec.StatusChunked {
			return nil, fmt.Errorf("mcp: chunk %d returned status %q", i, env.Status)
		}
		b, err := base64.StdEncoding.DecodeString(env.Result)
		if err != nil {
			return nil, fmt.Errorf("mcp: decoding chunk %d: %w", i, err)
		}
		raw = append(raw, b...)
	}
	return codec.ParseResultEnvelope(string(raw))
}

// assembleByCursor concatenates the chunks of a cursor-paginated result and
// parses the assembled result envelope (protocol §4.4). It follows the opaque
// cursor the server hands out with each chunk instead of requesting fixed
// indices. Chunk 0 is already in first.
func (a *Agent) assembleByCursor(first *codec.Envelope) (*codec.ResultEnvelope, error) {
	var raw []byte
	session := first.Session
	cursor := first.Cursor
	for {
		if first.Result != "" {
			b, err := base64.StdEncoding.DecodeString(first.Result)
			if err != nil {
				return nil, fmt.Errorf("mcp: decoding chunk: %w", err)
			}
			raw = append(raw, b...)
		}
		if !first.More || cursor == "" {
			break
		}
		next, err := a.client.ChunkByCursor(a.zone, session, cursor)
		if err != nil {
			return nil, fmt.Errorf("mcp: fetching next chunk: %w", err)
		}
		if next.Status != codec.StatusChunked {
			return nil, fmt.Errorf("mcp: chunk returned status %q", next.Status)
		}
		first = next
		cursor = next.Cursor
	}
	return codec.ParseResultEnvelope(string(raw))
}
