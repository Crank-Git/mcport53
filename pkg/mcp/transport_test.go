package mcp

import (
	"context"
	"crypto/tls"
	"net"
	"testing"
	"time"

	"github.com/Crank-Git/mcport53/internal/dns"
)

// TestApplyTransportConfigures checks that Server.WithTSIG and WithTLS record
// their settings and that ApplyTransport installs them on a dns.Server (protocol
// §11).
func TestApplyTransportConfigures(t *testing.T) {
	secret := []byte("transport-secret")
	srv := NewServer(echoRegistry(t)).
		WithTLS(&tls.Config{}).
		WithTSIG("mcport53.", secret)
	if srv.tls == nil {
		t.Fatal("WithTLS did not record a TLS config")
	}
	if srv.tsigName != "mcport53." || len(srv.tsigSecret) == 0 {
		t.Fatalf("WithTSIG did not record settings: name=%q secret=%v", srv.tsigName, srv.tsigSecret)
	}
	h := srv.Handlers()
	dnsSrv := dns.NewServer(agentZone, &h)
	if out := srv.ApplyTransport(dnsSrv); out == nil {
		t.Fatal("ApplyTransport returned nil")
	}
}

// TestApplyTransportTSIG exercises Server.WithTSIG + ApplyTransport end to end:
// a signed agent call is accepted by a server that requires TSIG (protocol §11).
func TestApplyTransportTSIG(t *testing.T) {
	secret := []byte("transport-secret")
	srv := NewServer(echoRegistry(t)).WithTSIG("mcport53.", secret)
	h := srv.Handlers()
	dnsSrv := srv.ApplyTransport(dns.NewServer(agentZone, &h))

	// Bind a throwaway UDP socket to obtain a free port, then hand it to
	// ListenAndServe, which re-binds on the same port.
	probe, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
	if err != nil {
		t.Fatalf("bind probe: %v", err)
	}
	addr := probe.LocalAddr().String()
	if err := probe.Close(); err != nil {
		t.Fatalf("close probe: %v", err)
	}
	errc := make(chan error, 1)
	go func() { errc <- dnsSrv.ListenAndServe(addr) }()

	agent := NewAgent(addr, agentZone).WithTSIG("mcport53.", secret)
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if _, err := agent.Call(context.Background(), "echo", []byte(`{"text":"hi"}`)); err == nil {
			return
		}
		select {
		case err := <-errc:
			t.Fatalf("ListenAndServe: %v", err)
		default:
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatal("server did not become ready")
}
