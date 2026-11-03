// Package cli holds flag parsing shared by the mcp53-server and mcp53-client
// binaries, so both sides read keys and TSIG settings the same way.
package cli

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"os"
	"strings"

	"github.com/Crank-Git/mcport53/internal/auth"
)

// ParseKeys parses a "tool=key,tool=key" list of per-tool HMAC keys
// (protocol §7.3). An empty string yields a nil map; an entry without '=' or
// with an empty tool name is an error, so a bad flag fails at startup.
func ParseKeys(s string) (map[string]string, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return nil, nil
	}
	out := map[string]string{}
	for _, pair := range strings.Split(s, ",") {
		pair = strings.TrimSpace(pair)
		if pair == "" {
			continue
		}
		tool, secret, ok := strings.Cut(pair, "=")
		tool = strings.ToLower(strings.TrimSpace(tool))
		if !ok || tool == "" {
			return nil, fmt.Errorf("invalid --keys entry %q: want tool=key", pair)
		}
		out[tool] = secret
	}
	return out, nil
}

// KeyRegistry builds an auth.KeyRegistry from a default key and a --keys list.
func KeyRegistry(def, perTool string) (*auth.KeyRegistry, error) {
	keys, err := ParseKeys(perTool)
	if err != nil {
		return nil, err
	}
	reg := auth.NewKeyRegistry([]byte(def))
	for tool, k := range keys {
		reg.Add(tool, []byte(k))
	}
	return reg, nil
}

// ParseTSIG parses a "name:secret" TSIG spec (protocol §8). The secret is used
// as raw bytes, and both peers must use the same name and secret.
func ParseTSIG(s string) (name string, secret []byte, err error) {
	name, sec, ok := strings.Cut(s, ":")
	if !ok || strings.TrimSpace(name) == "" || sec == "" {
		return "", nil, fmt.Errorf("invalid --tsig %q: want name:secret", s)
	}
	return strings.TrimSpace(name), []byte(sec), nil
}

// ServerTLS loads a certificate and key for a DNS-over-TLS listener.
func ServerTLS(certFile, keyFile string) (*tls.Config, error) {
	if certFile == "" || keyFile == "" {
		return nil, fmt.Errorf("--tls-cert and --tls-key must be given together")
	}
	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return nil, fmt.Errorf("loading TLS certificate: %w", err)
	}
	return &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12}, nil
}

// ClientTLS builds the client's TLS config. caFile, when set, replaces the
// system roots with the certificates in that PEM file (for a private CA or a
// self-signed server certificate).
func ClientTLS(caFile string) (*tls.Config, error) {
	cfg := &tls.Config{MinVersion: tls.VersionTLS12}
	if caFile == "" {
		return cfg, nil
	}
	pem, err := os.ReadFile(caFile)
	if err != nil {
		return nil, fmt.Errorf("reading --tls-ca: %w", err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(pem) {
		return nil, fmt.Errorf("--tls-ca %s holds no PEM certificates", caFile)
	}
	cfg.RootCAs = pool
	return cfg, nil
}
