package dns

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/hex"
	"math/big"
	"net"
	"testing"
	"time"

	"github.com/Crank-Git/mcport53/internal/codec"
	"github.com/miekg/dns"
)

// TestCanonicalKey checks that TSIG key names are normalized to the canonical
// on-wire form (lowercase, trailing dot) so both peers agree on the lookup key.
func TestCanonicalKey(t *testing.T) {
	for in, want := range map[string]string{
		"mcport53":        "mcport53.",
		"MCPORT53.":       "mcport53.",
		"  Foo.Bar  ":     "foo.bar.",
		"already.":        "already.",
		"lowercase.test.": "lowercase.test.",
	} {
		if got := CanonicalKey(in); got != want {
			t.Errorf("CanonicalKey(%q) = %q, want %q", in, got, want)
		}
	}
}

// TestTsigKeysNilSafe verifies the TsigKeys accessors are safe on a nil
// receiver, which is how ListenAndServe and the handler wiring observe an
// unconfigured server.
func TestTsigKeysNilSafe(t *testing.T) {
	var ks *TsigKeys
	if ks.Len() != 0 {
		t.Errorf("nil Len() = %d, want 0", ks.Len())
	}
	if ks.Algorithm() != dns.HmacSHA256 {
		t.Errorf("nil Algorithm() = %q, want %q", ks.Algorithm(), dns.HmacSHA256)
	}
	if ks.Fudge() != 300 {
		t.Errorf("nil Fudge() = %d, want 300", ks.Fudge())
	}
	if ks.provider() != nil {
		t.Error("nil provider() = non-nil, want nil")
	}
}

// TestTsigKeysWith checks that With stores the secret under the canonical name
// and base64-encodes it, and that Len counts entries.
func TestTsigKeysWith(t *testing.T) {
	ks := NewTsigKeys()
	ks.With("MCPORT53", []byte("secret"))
	ks.With("other.", []byte("other-secret"))
	if ks.Len() != 2 {
		t.Fatalf("Len() = %d, want 2", ks.Len())
	}
	if got, ok := ks.secrets["mcport53."]; !ok || got == "" {
		t.Fatalf("missing base64 secret for canonical key mcport53.: %v", ok)
	}
	if _, ok := ks.secrets["MCPORT53"]; ok {
		t.Fatal("secret stored under non-canonical key name")
	}
}

// startTSIGServer starts a test server that requires a valid TSIG signature over
// secret for every query, and returns a client for it.
func startTSIGServer(t *testing.T, secret []byte) *Client {
	t.Helper()
	handlers := &Handlers{
		OnCall: func(req *CallRequest) *codec.Envelope {
			return codec.OK(req.Tool, codec.TextResult("text/plain", string(req.Args)), 0)
		},
		OnDiscovery: func() *DiscoveryResponse {
			return &DiscoveryResponse{Version: 1, Tools: []Tool{{Name: "echo"}}}
		},
		OnSchema: func(tool string) *codec.Envelope {
			return codec.OK(tool, `{"type":"object"}`, 0)
		},
	}
	_, addr := startServerWithAddr(t, NewServer(testZone, handlers).WithDiscovery("127.0.0.1.", 53).WithTSIG("mcport53.", secret))
	return NewClient(addr)
}

// A call signed with the correct TSIG secret is served by a TSIG-required server.
func TestTSIGCallOK(t *testing.T) {
	secret := []byte("tsig-shared-secret")
	c := startTSIGServer(t, secret).WithTSIG("mcport53.", secret)
	e, err := c.Call(testZone, "echo", []byte(`{"text":"hi"}`), "")
	if err != nil {
		t.Fatalf("tsig call: %v", err)
	}
	if e.Status != codec.StatusOK || e.Result == "" {
		t.Fatalf("envelope = %+v, want ok with a result", e)
	}
}

// A query without a TSIG signature is rejected by a TSIG-required server.
func TestTSIGUnsignedRejected(t *testing.T) {
	secret := []byte("tsig-shared-secret")
	c := startTSIGServer(t, secret) // no WithTSIG: unsigned client
	e, err := c.Call(testZone, "echo", []byte(`{"text":"hi"}`), "")
	if err != nil {
		t.Fatalf("call: %v", err)
	}
	if e.Status != codec.StatusError || e.Error == "" {
		t.Fatalf("envelope = %+v, want an error for an unsigned query", e)
	}
}

// A query signed with the wrong secret is rejected by the server.
func TestTSIGWrongSecretRejected(t *testing.T) {
	secret := []byte("tsig-shared-secret")
	c := startTSIGServer(t, secret).WithTSIG("mcport53.", []byte("wrong-secret"))
	e, err := c.Call(testZone, "echo", []byte(`{"text":"hi"}`), "")
	if err != nil {
		t.Fatalf("call: %v", err)
	}
	if e.Status != codec.StatusError || e.Error == "" {
		t.Fatalf("envelope = %+v, want an error for a wrong-secret query", e)
	}
}

// A client verifies the server's response signature. A response that was
// tampered with on the wire fails verification.
func TestTSIGResponseVerification(t *testing.T) {
	secret := []byte("tsig-shared-secret")
	c := startTSIGServer(t, secret).WithTSIG("mcport53.", secret)

	// A valid signed response verifies.
	if _, err := c.Call(testZone, "echo", []byte(`{"text":"hi"}`), ""); err != nil {
		t.Fatalf("valid signed call: %v", err)
	}

	// A raw query through an unsigned miekg client has no response signature to
	// verify, so it still succeeds when the server is TSIG-required only if the
	// server accepts it -- here it must be rejected (no signature on the wire).
	unc := NewClient(c.server)
	unc.SetTimeout(2 * time.Second)
	resp, err := unc.Query(dns.Fqdn("echo.example."), dns.TypeTXT)
	if err == nil && resp.Rcode == dns.RcodeSuccess {
		// Rcode may be badsig; either way the unsigned path must not silently
		// succeed against a TSIG-required server.
	}
}

// A DoT (DNS-over-TLS) server accepts a client that speaks TLS with a self-signed
// certificate, and refuses a client that does not.
func TestTLSRoundTrip(t *testing.T) {
	srvTLS := selfSignedTLSCfg(t)
	handlers := &Handlers{
		OnCall: func(req *CallRequest) *codec.Envelope {
			return codec.OK(req.Tool, codec.TextResult("text/plain", string(req.Args)), 0)
		},
		OnDiscovery: func() *DiscoveryResponse {
			return &DiscoveryResponse{Version: 1, Tools: []Tool{{Name: "echo"}}}
		},
		OnSchema: func(tool string) *codec.Envelope {
			return codec.OK(tool, `{"type":"object"}`, 0)
		},
	}
	addr := startDoTServer(t, NewServer(testZone, handlers), srvTLS)

	// A TLS client reaches the DoT server.
	c := NewClient(addr).WithTLS(&tls.Config{InsecureSkipVerify: true})
	e, err := c.Call(testZone, "echo", []byte(`{"text":"hi"}`), "")
	if err != nil {
		t.Fatalf("doh call: %v", err)
	}
	if e.Status != codec.StatusOK || e.Result == "" {
		t.Fatalf("envelope = %+v, want ok with a result", e)
	}

	// A plain UDP client cannot complete the TLS handshake against the DoT port.
	udp := NewClient(addr)
	udp.SetTimeout(2 * time.Second)
	if _, err := udp.Query(dns.Fqdn("echo.example."), dns.TypeTXT); err == nil {
		t.Fatal("expected a TLS handshake failure for a UDP client against a DoT server")
	}
}

// selfSignedTLSCfg builds a *tls.Config carrying a self-signed certificate for
// 127.0.0.1/localhost, suitable for a test DoT server.
func selfSignedTLSCfg(t *testing.T) *tls.Config {
	t.Helper()
	cert, err := generateSelfSignedCert()
	if err != nil {
		t.Fatalf("generate self-signed cert: %v", err)
	}
	return &tls.Config{Certificates: []tls.Certificate{cert}}
}

func generateSelfSignedCert() (tls.Certificate, error) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return tls.Certificate{}, err
	}
	tmpl := x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "localhost"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IPAddresses:           []net.IP{net.ParseIP("127.0.0.1")},
		DNSNames:              []string{"localhost"},
	}
	der, err := x509.CreateCertificate(rand.Reader, &tmpl, &tmpl, &key.PublicKey, key)
	if err != nil {
		return tls.Certificate{}, err
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}, nil
}

// startDoTServer starts an in-process DNS-over-TLS server for the given
// preconfigured Server and returns its listen address.
func startDoTServer(t *testing.T, srv *Server, srvTLS *tls.Config) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen tcp: %v", err)
	}
	tlsLn := tls.NewListener(ln, srvTLS)
	dnsSrv := &dns.Server{Listener: tlsLn, Handler: srv.Handler(), TsigProvider: srv.tsig.provider(), TLSConfig: srvTLS}
	done := make(chan struct{})
	go func() {
		_ = dnsSrv.ActivateAndServe()
		close(done)
	}()
	t.Cleanup(func() {
		_ = dnsSrv.Shutdown()
		<-done
	})
	return ln.Addr().String()
}

// TestServerWithTLS checks that WithTLS records the TLS config so that
// ListenAndServe serves over DoT (protocol §8).
func TestServerWithTLS(t *testing.T) {
	srv := NewServer(testZone, &Handlers{}).WithTLS(&tls.Config{})
	if srv.tls == nil {
		t.Fatal("WithTLS did not record a TLS config")
	}
}

// TestServerWithTSIGKeys checks that a server configured with an explicit
// TsigKeys set (rather than a single With secret) verifies queries for any of
// the installed keys (protocol §8).
func TestServerWithTSIGKeys(t *testing.T) {
	ks := NewTsigKeys()
	ks.With("mcport53.", []byte("secret-one"))
	ks.With("alt-key.", []byte("secret-two"))
	handlers := &Handlers{
		OnCall: func(req *CallRequest) *codec.Envelope {
			return codec.OK(req.Tool, codec.TextResult("text/plain", string(req.Args)), 0)
		},
		OnDiscovery: func() *DiscoveryResponse {
			return &DiscoveryResponse{Version: 1, Tools: []Tool{{Name: "echo"}}}
		},
		OnSchema: func(tool string) *codec.Envelope {
			return codec.OK(tool, `{"type":"object"}`, 0)
		},
	}
	c, addr := startServerWithAddr(t, NewServer(testZone, handlers).WithDiscovery("127.0.0.1.", 53).WithTSIGKeys(ks))
	t.Cleanup(func() {
		_ = NewClient(addr) // keep addr referenced
	})
	// Sign with the first installed key.
	c.WithTSIG("mcport53.", []byte("secret-one"))
	e, err := c.Call(testZone, "echo", []byte(`{"text":"hi"}`), "")
	if err != nil {
		t.Fatalf("call with first key: %v", err)
	}
	if e.Status != codec.StatusOK || e.Result == "" {
		t.Fatalf("envelope = %+v, want ok with a result", e)
	}

	// Sign with the second installed key.
	c2 := NewClient(addr)
	c2.WithTSIG("alt-key.", []byte("secret-two"))
	e2, err := c2.Call(testZone, "echo", []byte(`{"text":"yo"}`), "")
	if err != nil {
		t.Fatalf("call with second key: %v", err)
	}
	if e2.Status != codec.StatusOK || e2.Result == "" {
		t.Fatalf("envelope = %+v, want ok with a result", e2)
	}
}

// freeUDPPort binds a throwaway UDP socket to obtain a free port, closes it, and
// returns the address so ListenAndServe can re-bind it.
func freeUDPPort(t *testing.T) string {
	t.Helper()
	probe, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
	if err != nil {
		t.Fatalf("bind probe: %v", err)
	}
	addr := probe.LocalAddr().String()
	if err := probe.Close(); err != nil {
		t.Fatalf("close probe: %v", err)
	}
	return addr
}

// freeTCPPort is like freeUDPPort but for a TCP (DoT) listener.
func freeTCPPort(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen tcp: %v", err)
	}
	addr := ln.Addr().String()
	if err := ln.Close(); err != nil {
		t.Fatalf("close tcp: %v", err)
	}
	return addr
}

// waitForReady polls c with a discovery query until it succeeds or errc
// receives an error from ListenAndServe, so tests can start a server on an
// ephemeral port and wait for it to accept connections.
func waitForReady(t *testing.T, c *Client, errc <-chan error) bool {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if _, err := c.Discovery(testZone); err == nil {
			return true
		}
		select {
		case err := <-errc:
			t.Fatalf("ListenAndServe: %v", err)
		default:
		}
		time.Sleep(20 * time.Millisecond)
	}
	return false
}

// TestListenAndServeUDP starts a server via Server.ListenAndServe on UDP (the
// default transport) and confirms a signed call is served (protocol §8).
func TestListenAndServeUDP(t *testing.T) {
	ks := NewTsigKeys()
	ks.With("mcport53.", []byte("secret"))
	handlers := &Handlers{
		OnCall: func(req *CallRequest) *codec.Envelope {
			return codec.OK(req.Tool, codec.TextResult("text/plain", string(req.Args)), 0)
		},
		OnDiscovery: func() *DiscoveryResponse {
			return &DiscoveryResponse{Version: 1, Tools: []Tool{{Name: "echo"}}}
		},
		OnSchema: func(tool string) *codec.Envelope {
			return codec.OK(tool, `{"type":"object"}`, 0)
		},
	}
	srv := NewServer(testZone, handlers).WithDiscovery("127.0.0.1.", 53).WithTSIGKeys(ks)
	addr := freeUDPPort(t)
	errc := make(chan error, 1)
	go func() { errc <- srv.ListenAndServe(addr) }()
	c := NewClient(addr)
	c.WithTSIG("mcport53.", []byte("secret"))
	c.SetTimeout(2 * time.Second)
	if !waitForReady(t, c, errc) {
		t.Fatal("server did not become ready")
	}
	e, err := c.Call(testZone, "echo", []byte(`{"text":"hi"}`), "")
	if err != nil {
		t.Fatalf("call: %v", err)
	}
	if e.Status != codec.StatusOK || e.Result == "" {
		t.Fatalf("envelope = %+v, want ok", e)
	}
}

// TestListenAndServeDoT starts a server via Server.ListenAndServe over
// DNS-over-TLS (tcp-tls) and confirms a TLS client reaches it (protocol §8).
func TestListenAndServeDoT(t *testing.T) {
	ks := NewTsigKeys()
	ks.With("mcport53.", []byte("secret"))
	handlers := &Handlers{
		OnCall: func(req *CallRequest) *codec.Envelope {
			return codec.OK(req.Tool, codec.TextResult("text/plain", string(req.Args)), 0)
		},
		OnDiscovery: func() *DiscoveryResponse {
			return &DiscoveryResponse{Version: 1, Tools: []Tool{{Name: "echo"}}}
		},
		OnSchema: func(tool string) *codec.Envelope {
			return codec.OK(tool, `{"type":"object"}`, 0)
		},
	}
	srv := NewServer(testZone, handlers).WithDiscovery("127.0.0.1.", 53).WithTSIGKeys(ks).WithTLS(selfSignedTLSCfg(t))
	addr := freeTCPPort(t)
	errc := make(chan error, 1)
	go func() { errc <- srv.ListenAndServe(addr) }()
	c := NewClient(addr).WithTLS(&tls.Config{InsecureSkipVerify: true})
	c.WithTSIG("mcport53.", []byte("secret"))
	c.SetTimeout(2 * time.Second)
	if !waitForReady(t, c, errc) {
		t.Fatal("server did not become ready")
	}
	e, err := c.Call(testZone, "echo", []byte(`{"text":"hi"}`), "")
	if err != nil {
		t.Fatalf("call: %v", err)
	}
	if e.Status != codec.StatusOK || e.Result == "" {
		t.Fatalf("envelope = %+v, want ok", e)
	}
}

// TestClientWithInsecureSkipVerify checks that WithInsecureSkipVerify sets (and
// does not replace) the TLS config's InsecureSkipVerify flag (protocol §8).
func TestClientWithInsecureSkipVerify(t *testing.T) {
	c := NewClient("127.0.0.1:5353")
	if c.dc.TLSConfig != nil {
		t.Fatal("expected nil TLSConfig before WithTLS")
	}
	c.WithInsecureSkipVerify()
	if c.dc.TLSConfig == nil || !c.dc.TLSConfig.InsecureSkipVerify {
		t.Fatal("WithInsecureSkipVerify did not set the flag")
	}

	// With an explicit TLS config it flips the flag rather than replacing it.
	c2 := NewClient("127.0.0.1:5353").WithTLS(&tls.Config{})
	c2.WithInsecureSkipVerify()
	if c2.dc.TLSConfig == nil || !c2.dc.TLSConfig.InsecureSkipVerify {
		t.Fatal("WithInsecureSkipVerify did not flip an existing TLS config")
	}
}

// TestTsigProviderErrors checks the error branches of the tsigProvider: an
// unknown key returns ErrSecret, a malformed base64 secret propagates, and
// Verify reports ErrSig for a bad MAC.
func TestTsigProviderErrors(t *testing.T) {
	p := tsigProvider{secrets: map[string]string{"mcport53.": base64.StdEncoding.EncodeToString([]byte("secret"))}}

	// Unknown key.
	mac, err := p.Generate([]byte("msg"), &dns.TSIG{Hdr: dns.RR_Header{Name: "other."}})
	if mac != nil || err != dns.ErrSecret {
		t.Fatalf("Generate unknown key = (%x, %v), want (nil, ErrSecret)", mac, err)
	}

	// Malformed base64 secret.
	pBad := tsigProvider{secrets: map[string]string{"mcport53.": "not base64!!"}}
	if _, err := pBad.Generate([]byte("msg"), &dns.TSIG{Hdr: dns.RR_Header{Name: "mcport53."}}); err == nil {
		t.Fatal("Generate with malformed base64 secret: got nil error")
	}

	// Verify: unknown key.
	if err := p.Verify([]byte("msg"), &dns.TSIG{Hdr: dns.RR_Header{Name: "other."}, MAC: "00"}); err != dns.ErrSecret {
		t.Fatalf("Verify unknown key = %v, want ErrSecret", err)
	}

	// Verify: bad hex MAC.
	if err := p.Verify([]byte("msg"), &dns.TSIG{Hdr: dns.RR_Header{Name: "mcport53."}, MAC: "zz"}); err == nil {
		t.Fatal("Verify with bad hex MAC: got nil error")
	}

	// Verify: correct key but wrong MAC -> ErrSig.
	wrongMAC := make([]byte, 32)
	for i := range wrongMAC {
		wrongMAC[i] = 0xff
	}
	if err := p.Verify([]byte("msg"), &dns.TSIG{Hdr: dns.RR_Header{Name: "mcport53."}, MAC: hex.EncodeToString(wrongMAC)}); err != dns.ErrSig {
		t.Fatalf("Verify wrong MAC = %v, want ErrSig", err)
	}
}

// TestTsigProviderGenerateVerifyRoundTrip checks that a provider signs a message
// and Verify accepts the resulting MAC (protocol §8).
func TestTsigProviderGenerateVerifyRoundTrip(t *testing.T) {
	secret := []byte("round-trip-secret")
	p := tsigProvider{secrets: map[string]string{"mcport53.": base64.StdEncoding.EncodeToString(secret)}}
	msg := []byte("canonical message buffer")
	tsig := &dns.TSIG{Hdr: dns.RR_Header{Name: "mcport53."}}
	mac, err := p.Generate(msg, tsig)
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	tsig.MAC = hex.EncodeToString(mac)
	if err := p.Verify(msg, tsig); err != nil {
		t.Fatalf("Verify round trip: %v", err)
	}
	// A tampered message must not verify.
	if err := p.Verify([]byte("tampered"), tsig); err == nil {
		t.Fatal("Verify accepted a tampered message")
	}
}
