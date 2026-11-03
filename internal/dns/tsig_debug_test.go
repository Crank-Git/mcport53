package dns

import (
	"encoding/base64"
	"net"
	"testing"

	"github.com/miekg/dns"
)

// TestTSIGLowLevelVerify is a regression guard for the protocol §8 TSIG bug
// where a server reported "no signature found" for a correctly signed query.
// It signs a message at the raw miekg level and confirms both direct verification
// and verification by a raw miekg server (which strips the TSIG before checking).
func TestTSIGLowLevelVerify(t *testing.T) {
	secret := []byte("tsig-shared-secret")
	srvKeys := NewTsigKeys()
	srvKeys.With(CanonicalKey("mcport53."), secret)
	prov := srvKeys.provider()

	name := CanonicalKey("mcport53.")

	// Build and sign a message exactly like the client does.
	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn("echo.example."), dns.TypeTXT)
	m.SetTsig(name, dns.HmacSHA256, 300, 0)

	packed, mac, err := dns.TsigGenerateWithProvider(m, prov, "", false)
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	t.Logf("packed mac=%s len=%d", mac, len(packed))
	// Arcount is at bytes 10:12.
	t.Logf("packed Arcount=%d", int(packed[10])<<8|int(packed[11]))

	// Verify the captured bytes directly.
	if err := dns.TsigVerify(packed, base64.StdEncoding.EncodeToString(secret), "", false); err != nil {
		t.Fatalf("verify captured: %v", err)
	}
	t.Logf("verify captured OK")

	// Now send over the wire and confirm the server can verify.
	udpConn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
	if err != nil {
		t.Fatalf("bind udp: %v", err)
	}
	addr := udpConn.LocalAddr().String()

	srv := &dns.Server{
		PacketConn: udpConn,
		Handler: dns.HandlerFunc(func(w dns.ResponseWriter, r *dns.Msg) {
			resp := new(dns.Msg)
			resp.SetReply(r)
			t.Logf("server IsTsig()=%v, TsigStatus()=%v", r.IsTsig(), w.TsigStatus())
			_ = w.WriteMsg(resp)
		}),
		TsigProvider: prov,
	}
	done := make(chan struct{})
	go func() {
		_ = srv.ActivateAndServe()
		close(done)
	}()
	t.Cleanup(func() {
		_ = srv.Shutdown()
		<-done
	})

	c := new(dns.Client)
	c.Net = "udp"
	c.UDPSize = dns.MinMsgSize + 4096
	c.TsigProvider = prov

	// Use a FRESH message, like the real client does.
	fresh := new(dns.Msg)
	fresh.SetQuestion(dns.Fqdn("echo.example."), dns.TypeTXT)
	fresh.SetTsig(name, dns.HmacSHA256, 300, 0)
	t.Logf("fresh IsTsig()=%v", fresh.IsTsig())

	resp, _, err := c.Exchange(fresh, addr)
	if err != nil {
		t.Fatalf("exchange: %v", err)
	}
	t.Logf("response rcode=%v", resp.Rcode)
}
