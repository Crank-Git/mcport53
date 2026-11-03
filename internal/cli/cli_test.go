package cli

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"time"
)

func TestParseKeys(t *testing.T) {
	tests := []struct {
		name    string
		in      string
		want    map[string]string
		wantErr bool
	}{
		{"empty", "", nil, false},
		{"single", "echo=secret1", map[string]string{"echo": "secret1"}, false},
		{"multiple", "echo=secret1,upper=secret2", map[string]string{"echo": "secret1", "upper": "secret2"}, false},
		{"lowercases tool", "Echo=secret", map[string]string{"echo": "secret"}, false},
		{"trims spaces", " echo = secret ", map[string]string{"echo": " secret"}, false},
		{"ignores blank", "echo=secret,,upper=secret2", map[string]string{"echo": "secret", "upper": "secret2"}, false},
		{"key may contain =", "echo=a=b", map[string]string{"echo": "a=b"}, false},
		{"missing equals", "echo", nil, true},
		{"empty tool", "=secret", nil, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ParseKeys(tt.in)
			if (err != nil) != tt.wantErr {
				t.Fatalf("ParseKeys(%q) err = %v, wantErr %v", tt.in, err, tt.wantErr)
			}
			if !tt.wantErr && !reflect.DeepEqual(got, tt.want) {
				t.Errorf("ParseKeys(%q) = %#v, want %#v", tt.in, got, tt.want)
			}
		})
	}
}

func TestKeyRegistry(t *testing.T) {
	reg, err := KeyRegistry("def", "echo=e")
	if err != nil {
		t.Fatal(err)
	}
	if string(reg.For("echo")) != "e" || string(reg.For("add")) != "def" {
		t.Fatalf("For(echo)=%q For(add)=%q", reg.For("echo"), reg.For("add"))
	}
	if _, err := KeyRegistry("def", "bad"); err == nil {
		t.Fatal("bad --keys accepted")
	}
}

func TestParseTSIG(t *testing.T) {
	name, secret, err := ParseTSIG("mcport53.:s3:cr3t")
	if err != nil || name != "mcport53." || string(secret) != "s3:cr3t" {
		t.Fatalf("got %q %q %v", name, secret, err)
	}
	for _, bad := range []string{"", "name", "name:", ":secret", "  :secret"} {
		if _, _, err := ParseTSIG(bad); err == nil {
			t.Errorf("ParseTSIG(%q) accepted", bad)
		}
	}
}

// writeTestCert writes a self-signed certificate for 127.0.0.1/localhost and
// its key into dir, returning the two paths.
func writeTestCert(t *testing.T, dir string) (certFile, keyFile string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "mcport53 test"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		DNSNames:     []string{"localhost"},
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

func TestServerAndClientTLS(t *testing.T) {
	dir := t.TempDir()
	cert, key := writeTestCert(t, dir)
	cfg, err := ServerTLS(cert, key)
	if err != nil || len(cfg.Certificates) != 1 {
		t.Fatalf("ServerTLS: %v", err)
	}
	if _, err := ServerTLS(cert, ""); err == nil {
		t.Error("ServerTLS without key accepted")
	}
	if _, err := ServerTLS(filepath.Join(dir, "nope"), key); err == nil {
		t.Error("ServerTLS with missing cert accepted")
	}

	ccfg, err := ClientTLS(cert)
	if err != nil || ccfg.RootCAs == nil {
		t.Fatalf("ClientTLS(ca): %v", err)
	}
	if c, err := ClientTLS(""); err != nil || c.RootCAs != nil {
		t.Fatalf("ClientTLS(\"\") = %+v %v, want system roots", c, err)
	}
	if _, err := ClientTLS(key); err == nil {
		t.Error("ClientTLS accepted a file with no certificates")
	}
	if _, err := ClientTLS(filepath.Join(dir, "nope")); err == nil {
		t.Error("ClientTLS accepted a missing file")
	}
}
