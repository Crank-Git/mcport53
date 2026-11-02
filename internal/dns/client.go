package dns

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/Crank-Git/mcport53/internal/auth"
	"github.com/Crank-Git/mcport53/internal/codec"
	"github.com/miekg/dns"
)

// Client is a DNS client for an MCPort53 server.
type Client struct {
	server       string // host:port, e.g. "127.0.0.1:53"
	timeout      time.Duration
	dc           *dns.Client
	signer       func(tool, nonce string, args []byte, ts int64) string // optional per-call signer
	discoveryKey []byte                                                 // optional key to verify signed discovery documents (protocol §8)
}

// NewClient builds a Client for the server at serverAddr ("host:port"). The
// default query timeout is 2s.
func NewClient(serverAddr string) *Client {
	return &Client{
		server:  serverAddr,
		timeout: 2 * time.Second,
		// Read large responses (chunked call results exceed the 512-byte UDP
		// minimum) into a bigger buffer so they are not truncated on the wire.
		dc: &dns.Client{Net: "udp", Timeout: 2 * time.Second, UDPSize: dns.MinMsgSize + 4096},
	}
}

// SetTimeout sets the query timeout.
func (c *Client) SetTimeout(d time.Duration) {
	c.timeout = d
	c.dc.Timeout = d
}

// SetNet sets the transport (e.g. "udp", "tcp", "tls", "https").
func (c *Client) SetNet(net string) {
	c.dc.Net = net
}

// Discovery queries SRV + TXT at _mcp._udp.<zone> and returns the discovery
// document (protocol §2.1).
func (c *Client) Discovery(zone string) (*DiscoveryResponse, error) {
	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn("_mcp._udp."+strings.TrimSuffix(zone, ".")), dns.TypeSRV)
	m.RecursionDesired = false

	resp, _, err := c.dc.Exchange(m, c.server)
	if err != nil {
		return nil, err
	}
	if resp.Rcode != dns.RcodeSuccess {
		return nil, fmt.Errorf("dns: discovery NXDOMAIN for _mcp._udp.%s", strings.TrimSuffix(zone, "."))
	}
	txt, err := extractTXT(resp)
	if err != nil {
		return nil, err
	}
	var doc DiscoveryResponse
	if err := json.Unmarshal([]byte(txt), &doc); err != nil {
		return nil, fmt.Errorf("dns: parsing discovery: %w", err)
	}
	if err := verifyDiscovery(c.discoveryKey, &doc); err != nil {
		return nil, err
	}
	return &doc, nil
}

// WithSigner installs a per-call signer. When set, Call signs each call with a
// fresh nonce coordinated with the query (see Call). The signer receives the
// tool, nonce, raw argument bytes, and a Unix-seconds timestamp and returns a
// signature label (for example (*auth.KeyRegistry).Sign).
func (c *Client) WithSigner(signer func(tool, nonce string, args []byte, ts int64) string) *Client {
	c.signer = signer
	return c
}

// WithDiscoveryKey installs the key used to verify signed discovery documents
// (protocol §8). When set, Discovery rejects documents that are unsigned or whose
// signature does not verify.
func (c *Client) WithDiscoveryKey(key []byte) *Client {
	c.discoveryKey = key
	return c
}

// verifyDiscovery checks that doc carries a valid signature over its content.
// It is a no-op when no key is configured. The signature is a pure content
// signature: the document is signed with a fixed nonce and timestamp, so the
// client reproduces the signed bytes by clearing the Sig field and re-marshaling
// (Go marshals struct fields in declaration order, matching the signer).
func verifyDiscovery(key []byte, doc *DiscoveryResponse) error {
	if key == nil {
		return nil
	}
	sig := doc.Sig
	if sig == "" {
		return errors.New("dns: discovery document is not signed")
	}
	// Marshal a copy with the signature cleared so the passed-in doc is not
	// mutated and the caller still observes the signature it received.
	unsigned := *doc
	unsigned.Sig = ""
	b, err := json.Marshal(unsigned)
	if err != nil {
		return fmt.Errorf("dns: re-serializing discovery for verification: %w", err)
	}
	if !auth.Verify(key, sig, "discovery", "", b, 0) {
		return errors.New("dns: discovery document signature invalid")
	}
	return nil
}

// Schema queries <tool>.schema.<zone> and returns the tool input schema
// envelope (protocol §2.2).
func (c *Client) Schema(zone, tool string) (*codec.Envelope, error) {
	name := dns.Fqdn(strings.ToLower(tool) + ".schema." + strings.TrimSuffix(zone, "."))
	return c.queryEnvelope(name, dns.TypeTXT)
}

// Call issues a tool call and returns the result envelope (protocol §2.3).
//
// sig is an optional HMAC signature label; pass "" for an unsigned call. When a
// signer is installed (see WithSigner) and sig is empty, the client signs the
// call itself with a fresh nonce, coordinating the nonce with the query so the
// signature is valid on the wire.
func (c *Client) Call(zone, tool string, args []byte, sig string) (*codec.Envelope, error) {
	nonce, err := codec.RandomNonce()
	if err != nil {
		return nil, err
	}
	if sig == "" && c.signer != nil {
		sig = c.signer(tool, nonce, args, time.Now().Unix())
	}
	labels := codec.BuildCallName(zoneLabels(zone), tool, args, nonce, sig)
	return c.queryEnvelope(LabelsToName(labels), dns.TypeTXT)
}

// Chunk fetches one result chunk by session (protocol §2.4).
func (c *Client) Chunk(zone, session string, idx int) (*codec.Envelope, error) {
	labels := codec.ChunkName(zoneLabels(zone), session, idx)
	return c.queryEnvelope(LabelsToName(labels), dns.TypeTXT)
}

// Job polls the status of a long-running call (protocol §2.4 / §4.3).
func (c *Client) Job(zone, job string) (*codec.Envelope, error) {
	labels := codec.JobName(zoneLabels(zone), job)
	return c.queryEnvelope(LabelsToName(labels), dns.TypeTXT)
}

// Query sends a raw question and returns the response message. It is exposed for
// advanced use and testing.
func (c *Client) Query(name string, qtype uint16) (*dns.Msg, error) {
	m := new(dns.Msg)
	m.SetQuestion(name, qtype)
	m.RecursionDesired = false
	resp, _, err := c.dc.Exchange(m, c.server)
	return resp, err
}

func (c *Client) queryEnvelope(name string, qtype uint16) (*codec.Envelope, error) {
	txt, err := c.queryTXT(name, qtype)
	if err != nil {
		return nil, err
	}
	return codec.ParseEnvelope([]byte(txt))
}

func (c *Client) queryTXT(name string, qtype uint16) (string, error) {
	resp, err := c.Query(name, qtype)
	if err != nil {
		return "", err
	}
	if resp.Rcode != dns.RcodeSuccess {
		return "", fmt.Errorf("dns: %s returned rcode %s", name, dns.RcodeToString[resp.Rcode])
	}
	return extractTXT(resp)
}

func zoneLabels(zone string) []string {
	return NameToLabels(strings.TrimSuffix(zone, "."))
}
