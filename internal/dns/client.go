package dns

import (
	"context"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
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
	dohURL       string                                                 // optional DoH endpoint (RFC 8484); when set, queries go here (protocol §12)
	httpClient   *http.Client                                           // used when dohURL is set
	tsig         *TsigKeys                                              // optional TSIG keys for transport integrity (protocol §11)
	tsigName     string                                                 // canonical TSIG key name used to sign outgoing queries (protocol §11)
	insecureSkip bool                                                   // skip TLS certificate verification (protocol §11)
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
	if c.httpClient != nil {
		c.httpClient.Timeout = d
	}
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

	resp, err := c.exchange(m)
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

// WithTSIG signs every query with a TSIG over the shared secret (protocol §11).
// name is the TSIG key name; the server must hold the same secret for that name.
// The response is verified with the same secret, so the exchange is authenticated
// and integrity-checked at the transport layer, in addition to any application
// HMAC (protocol §7).
func (c *Client) WithTSIG(name string, secret []byte) *Client {
	if c.tsig == nil {
		c.tsig = NewTsigKeys()
	}
	c.tsig.With(name, secret)
	c.tsigName = CanonicalKey(name)
	c.dc.TsigProvider = c.tsig.provider()
	return c
}

// WithTLS makes the client reach the server over DNS-over-TLS (RFC 8483) by
// switching the transport to tcp-tls with cfg. TLS provides confidentiality and
// server authentication; pair it with WithInsecureSkipVerify for self-signed
// certificates (protocol §11). TSIG may be layered on top for message-level
// authentication as well.
func (c *Client) WithTLS(cfg *tls.Config) *Client {
	c.dc.Net = "tcp-tls"
	c.dc.TLSConfig = cfg
	return c
}

// WithInsecureSkipVerify accepts any server certificate (self-signed or
// hostname-mismatched). It weakens TLS to confidentiality + tamper protection
// only; keep it for tests and local deployments, never against a public server
// (protocol §11).
func (c *Client) WithInsecureSkipVerify() *Client {
	if c.dc.TLSConfig == nil {
		c.dc.TLSConfig = &tls.Config{InsecureSkipVerify: true}
	} else {
		c.dc.TLSConfig.InsecureSkipVerify = true
	}
	return c
}

// WithDoH configures the client to reach the server over DNS-over-HTTPS (RFC 8484)
// via endpoint, for example "https://dns.example/dns-query". When set, every query
// is sent to the DoH endpoint instead of the direct --server address (protocol §12),
// which is how an agent reaches the authoritative server through a normal resolver.
func (c *Client) WithDoH(endpoint string) *Client {
	c.dohURL = endpoint
	c.httpClient = &http.Client{Timeout: c.timeout}
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
	if err := codec.CheckName(labels); err != nil {
		// Fail before sending: an over-long name is answered FORMERR (or
		// dropped by a resolver), which tells the caller nothing.
		max := codec.MaxCallArgs(zoneLabels(zone), tool, nonce, sig)
		return nil, fmt.Errorf("dns: %d bytes of arguments for %s do not fit in a DNS name (max %d for this zone and signing): %w",
			len(args), tool, max, err)
	}
	return c.queryEnvelope(LabelsToName(labels), dns.TypeTXT)
}

// Chunk fetches one result chunk by session using a fixed chunk index
// (protocol §2.4).
func (c *Client) Chunk(zone, session string, idx int) (*codec.Envelope, error) {
	labels := codec.ChunkName(zoneLabels(zone), session, idx)
	return c.queryEnvelope(LabelsToName(labels), dns.TypeTXT)
}

// ChunkByCursor fetches the next result chunk by session using an opaque
// pagination cursor assigned by the server (protocol §4.4). The cursor replaces
// the fixed chunk index; the client follows it until the response reports no
// more chunks.
func (c *Client) ChunkByCursor(zone, session, cursor string) (*codec.Envelope, error) {
	labels := codec.CursorName(zoneLabels(zone), session, cursor)
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
	return c.exchange(m)
}

// exchange sends m and returns the response. When the client is configured with a
// DoH endpoint (see WithDoH) the query goes there (protocol §12); otherwise it is
// sent directly to the server address over UDP/TCP. When TSIG is configured
// (protocol §11) the query is signed with the shared secret.
func (c *Client) exchange(m *dns.Msg) (*dns.Msg, error) {
	if c.dohURL != "" {
		return c.dohExchange(m)
	}
	if c.tsig != nil {
		m.SetTsig(c.tsigName, c.tsig.Algorithm(), c.tsig.Fudge(), 0)
	}
	resp, _, err := c.dc.Exchange(m, c.server)
	return resp, err
}

// dohExchange performs a single DNS-over-HTTPS query (RFC 8484) using an HTTP GET
// with a base64url-encoded question. The response body is the raw DNS message.
func (c *Client) dohExchange(m *dns.Msg) (*dns.Msg, error) {
	packed, err := m.Pack()
	if err != nil {
		return nil, fmt.Errorf("dns: packing DoH query: %w", err)
	}
	query := url.Values{}
	query.Set("dns", base64.RawURLEncoding.EncodeToString(packed))
	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, c.dohURL+"?"+query.Encode(), nil)
	if err != nil {
		return nil, fmt.Errorf("dns: building DoH request: %w", err)
	}
	req.Header.Set("Accept", "application/dns-message")
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("dns: DoH request: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("dns: DoH endpoint returned %s", resp.Status)
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("dns: reading DoH response: %w", err)
	}
	out := new(dns.Msg)
	if err := out.Unpack(body); err != nil {
		return nil, fmt.Errorf("dns: unpacking DoH response: %w", err)
	}
	return out, nil
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
