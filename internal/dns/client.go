package dns

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/Crank-Git/mcport53/internal/codec"
	"github.com/miekg/dns"
)

// Client is a DNS client for an MCPort53 server.
type Client struct {
	server  string // host:port, e.g. "127.0.0.1:53"
	timeout time.Duration
	dc      *dns.Client
}

// NewClient builds a Client for the server at serverAddr ("host:port"). The
// default query timeout is 2s.
func NewClient(serverAddr string) *Client {
	return &Client{
		server:  serverAddr,
		timeout: 2 * time.Second,
		dc:      &dns.Client{Net: "udp", Timeout: 2 * time.Second},
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
	return &doc, nil
}

// Schema queries <tool>.schema.<zone> and returns the tool input schema
// envelope (protocol §2.2).
func (c *Client) Schema(zone, tool string) (*codec.Envelope, error) {
	name := dns.Fqdn(strings.ToLower(tool) + ".schema." + strings.TrimSuffix(zone, "."))
	return c.queryEnvelope(name, dns.TypeTXT)
}

// Call issues a tool call and returns the result envelope (protocol §2.3).
//
// sig is an optional HMAC signature label; pass "" for an unsigned call.
func (c *Client) Call(zone, tool string, args []byte, sig string) (*codec.Envelope, error) {
	nonce, err := codec.RandomNonce()
	if err != nil {
		return nil, err
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
