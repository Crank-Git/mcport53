package main

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/miekg/dns"
)

// binaries builds mcp53-server and mcp53-client once per test run.
var binDir string

func TestMain(m *testing.M) {
	dir, err := os.MkdirTemp("", "mcp53-e2e")
	if err != nil {
		panic(err)
	}
	for _, name := range []string{"mcp53-server", "mcp53-client"} {
		cmd := exec.Command("go", "build", "-o", filepath.Join(dir, name), "../"+name)
		if out, err := cmd.CombinedOutput(); err != nil {
			panic(string(out))
		}
	}
	binDir = dir
	code := m.Run()
	os.RemoveAll(dir)
	os.Exit(code)
}

// freeAddr returns a 127.0.0.1 port free for both UDP and TCP.
func freeAddr(t *testing.T) string {
	t.Helper()
	for i := 0; i < 20; i++ {
		pc, err := net.ListenPacket("udp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		addr := pc.LocalAddr().String()
		l, err := net.Listen("tcp", addr)
		pc.Close()
		if err == nil {
			l.Close()
			return addr
		}
	}
	t.Fatal("no free port")
	return ""
}

// startServer runs mcp53-server with args and waits until it answers.
func startServer(t *testing.T, ready []string, args ...string) string {
	t.Helper()
	addr := freeAddr(t)
	cmd := exec.Command(filepath.Join(binDir, "mcp53-server"), append([]string{"--addr", addr}, args...)...)
	var logs bytes.Buffer
	cmd.Stdout, cmd.Stderr = &logs, &logs
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = cmd.Process.Kill(); _ = cmd.Wait() })
	deadline := time.Now().Add(10 * time.Second)
	for {
		if out, err := client(addr, append(ready, "--timeout", "300ms")...); err == nil {
			_ = out
			return addr
		}
		if time.Now().After(deadline) {
			t.Fatalf("server did not become ready; logs:\n%s", logs.String())
		}
		time.Sleep(100 * time.Millisecond)
	}
}

// client runs mcp53-client against addr and returns its combined output.
func client(addr string, args ...string) (string, error) {
	cmd := exec.Command(filepath.Join(binDir, "mcp53-client"), append([]string{"--server", addr}, args...)...)
	out, err := cmd.CombinedOutput()
	return string(out), err
}

func expectOK(t *testing.T, addr, want string, args ...string) {
	t.Helper()
	out, err := client(addr, args...)
	if err != nil || !strings.Contains(out, want) {
		t.Fatalf("client %v: err=%v output:\n%s\nwant %q", args, err, out, want)
	}
}

func expectFail(t *testing.T, addr, want string, args ...string) {
	t.Helper()
	out, err := client(addr, args...)
	if err == nil || !strings.Contains(out, want) {
		t.Fatalf("client %v: err=%v output:\n%s\nwant failure mentioning %q", args, err, out, want)
	}
}

var echoHi = []string{"--tool", "echo", "--args", `{"text":"hi-from-e2e"}`}

func TestE2ESignedCalls(t *testing.T) {
	addr := startServer(t, []string{"--key", "k1"}, "--key", "k1")
	expectOK(t, addr, "hi-from-e2e", append(echoHi, "--key", "k1")...)
	expectFail(t, addr, "not signed", echoHi...)
	expectFail(t, addr, "invalid signature", append(echoHi, "--key", "wrong")...)
}

func TestE2ESecretServerAcceptsKeyClient(t *testing.T) {
	addr := startServer(t, []string{"--key", "s1"}, "--secret", "s1")
	expectOK(t, addr, "hi-from-e2e", append(echoHi, "--key", "s1")...)
	expectFail(t, addr, "not signed", echoHi...)
}

func TestE2EPerToolKeys(t *testing.T) {
	addr := startServer(t, []string{"--key", "d"}, "--key", "d", "--keys", "echo=e")
	expectOK(t, addr, "hi-from-e2e", append(echoHi, "--key", "d", "--keys", "echo=e")...)
	expectFail(t, addr, "invalid signature", append(echoHi, "--key", "d")...)
	// add has no override, so the default key signs it.
	expectOK(t, addr, "5", "--tool", "add", "--args", `{"a":2,"b":3}`, "--key", "d")
}

func TestE2ESignedDiscovery(t *testing.T) {
	addr := startServer(t, []string{"--key", "k"}, "--key", "k")
	expectOK(t, addr, "3 tool(s)", "--key", "k", "--verify-discovery")
	expectFail(t, addr, "signature invalid", "--key", "other", "--verify-discovery")

	plain := startServer(t, nil)
	expectFail(t, plain, "not signed", "--key", "k", "--verify-discovery")
	expectOK(t, plain, "3 tool(s)")
}

func TestE2ETSIG(t *testing.T) {
	addr := startServer(t, []string{"--tsig", "mcport53.:ts"}, "--tsig", "mcport53.:ts")
	expectOK(t, addr, "hi-from-e2e", append(echoHi, "--tsig", "mcport53.:ts")...)
	expectOK(t, addr, "3 tool(s)", "--tsig", "mcport53.:ts")
	expectFail(t, addr, "TSIG", append(echoHi, "--timeout", "1s")...)
	expectFail(t, addr, "", append(echoHi, "--tsig", "mcport53.:wrong", "--timeout", "1s")...)
}

func TestE2EDoT(t *testing.T) {
	dir := t.TempDir()
	cert, key := writeCert(t, dir)
	ready := []string{"--tls", "--tls-ca", cert}
	addr := startServer(t, ready, "--tls-cert", cert, "--tls-key", key)
	expectOK(t, addr, "hi-from-e2e", append(echoHi, "--tls", "--tls-ca", cert)...)
	expectOK(t, addr, "hi-from-e2e", append(echoHi, "--tls", "--tls-insecure")...)
	expectFail(t, addr, "certificate", append(echoHi, "--tls", "--timeout", "2s")...)
	expectFail(t, addr, "", append(echoHi, "--timeout", "1s")...) // plain UDP to a DoT-only server
}

func TestE2EFlagValidation(t *testing.T) {
	addr := "127.0.0.1:9" // never contacted: validation fails first
	expectFail(t, addr, "require --key", "--keys", "echo=x")
	expectFail(t, addr, "require --key", "--verify-discovery")
	expectFail(t, addr, "require --tls", "--tls-insecure")
	expectFail(t, addr, "want name:secret", "--tsig", "nocolon")
}

// TestE2EDiscoverDefaultsToAddr: the advertised SRV record points at the
// address the server listens on unless --discover overrides it.
func TestE2EDiscoverDefaultsToAddr(t *testing.T) {
	addr := startServer(t, nil)
	_, port, _ := net.SplitHostPort(addr)
	m := new(dns.Msg)
	m.SetQuestion("_mcp._udp.example.", dns.TypeSRV)
	m.SetEdns0(1232, false)
	resp, _, err := (&dns.Client{Net: "tcp"}).Exchange(m, addr)
	if err != nil {
		t.Fatal(err)
	}
	var srv *dns.SRV
	for _, rr := range resp.Answer {
		if s, ok := rr.(*dns.SRV); ok {
			srv = s
		}
	}
	if srv == nil || srv.Target != "127.0.0.1." || strconv.Itoa(int(srv.Port)) != port {
		t.Fatalf("SRV = %v, want 127.0.0.1.:%s", srv, port)
	}
}

func writeCert(t *testing.T, dir string) (certFile, keyFile string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "mcport53 e2e"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	kb, _ := x509.MarshalECPrivateKey(key)
	certFile, keyFile = filepath.Join(dir, "cert.pem"), filepath.Join(dir, "key.pem")
	_ = os.WriteFile(certFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o600)
	_ = os.WriteFile(keyFile, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: kb}), 0o600)
	return certFile, keyFile
}
