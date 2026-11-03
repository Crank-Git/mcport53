package dns

import (
	"encoding/base64"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"

	"github.com/Crank-Git/mcport53/internal/auth"
	"github.com/Crank-Git/mcport53/internal/codec"
	"github.com/miekg/dns"
)

// dohServer starts an in-process DNS-over-HTTPS (RFC 8484) test endpoint whose
// replies are produced by reply. The handler speaks the DoH contract: an HTTP
// GET carrying a base64url "dns" query parameter with an Accept header of
// application/dns-message; the response body is the packed DNS message. It
// records the last decoded question so tests can assert on it.
func dohServer(t *testing.T, reply func(req *dns.Msg) *dns.Msg) (*httptest.Server, func() dns.Question) {
	t.Helper()
	var mu sync.Mutex
	var lastQ dns.Question
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get("Accept"); got != "application/dns-message" {
			w.WriteHeader(http.StatusNotAcceptable)
			return
		}
		enc := r.URL.Query().Get("dns")
		if enc == "" {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		raw, err := base64.RawURLEncoding.DecodeString(enc)
		if err != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		var req dns.Msg
		if err := req.Unpack(raw); err != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		mu.Lock()
		if len(req.Question) > 0 {
			lastQ = req.Question[0]
		}
		mu.Unlock()
		resp := reply(&req)
		if resp == nil {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		packed, err := resp.Pack()
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/dns-message")
		if _, err := w.Write(packed); err != nil {
			_ = err
		}
	}))
	t.Cleanup(srv.Close)
	return srv, func() dns.Question {
		mu.Lock()
		defer mu.Unlock()
		return lastQ
	}
}

// dohDiscoveryResponse builds an authoritative SRV + TXT reply to req, where the
// TXT answer carries the base64-encoded discovery document out.
func dohDiscoveryResponse(req *dns.Msg, out string) *dns.Msg {
	resp := reply(req)
	resp.Rcode = dns.RcodeSuccess
	resp.Authoritative = true
	name := req.Question[0].Name
	resp.Answer = []dns.RR{
		&dns.SRV{
			Hdr:    dns.RR_Header{Name: name, Rrtype: dns.TypeSRV, Class: dns.ClassINET, Ttl: 0},
			Target: "127.0.0.1.", Port: 53,
		},
		&dns.TXT{
			Hdr: dns.RR_Header{Name: name, Rrtype: dns.TypeTXT, Class: dns.ClassINET, Ttl: 0},
			Txt: TXTStrings(out),
		},
	}
	return resp
}

// Discovery over DoH returns the advertised document.
func TestDoHDiscoveryRoundTrip(t *testing.T) {
	doc := DiscoveryResponse{
		Version: 1,
		Tools:   []Tool{{Name: "echo", Description: "echo text"}},
	}
	out, _ := json.Marshal(doc)
	srv, qname := dohServer(t, func(req *dns.Msg) *dns.Msg {
		return dohDiscoveryResponse(req, string(out))
	})

	c := NewClient("127.0.0.1:53").WithDoH(srv.URL)
	got, err := c.Discovery(testZone)
	if err != nil {
		t.Fatalf("Discovery over DoH: %v", err)
	}
	if got.Version != 1 || len(got.Tools) != 1 || got.Tools[0].Name != "echo" {
		t.Fatalf("discovery doc = %+v, want one echo tool", got)
	}
	if want := dns.Fqdn("_mcp._udp.example."); qname().Name != want {
		t.Fatalf("DoH question = %q, want %q", qname().Name, want)
	}
}

// A call over DoH returns the ok envelope the endpoint serves.
func TestDoHCallRoundTrip(t *testing.T) {
	env := codec.OK("echo", codec.TextResult("text/plain", "hello"), 0)
	envOut, err := env.Marshal()
	if err != nil {
		t.Fatalf("marshal envelope: %v", err)
	}
	srv, _ := dohServer(t, func(req *dns.Msg) *dns.Msg {
		resp := reply(req)
		resp.Rcode = dns.RcodeSuccess
		resp.Authoritative = true
		resp.Answer = []dns.RR{&dns.TXT{
			Hdr: dns.RR_Header{Name: req.Question[0].Name, Rrtype: dns.TypeTXT, Class: dns.ClassINET, Ttl: 0},
			Txt: TXTStrings(string(envOut)),
		}}
		return resp
	})

	c := NewClient("127.0.0.1:53").WithDoH(srv.URL)
	got, err := c.Call(testZone, "echo", []byte(`{}`), "")
	if err != nil {
		t.Fatalf("Call over DoH: %v", err)
	}
	if got.Status != codec.StatusOK {
		t.Fatalf("status = %q, want ok", got.Status)
	}
}

// A raw query over DoH returns the packed message the endpoint serves.
func TestDoHQueryRaw(t *testing.T) {
	srv, _ := dohServer(t, func(req *dns.Msg) *dns.Msg {
		resp := reply(req)
		resp.Rcode = dns.RcodeSuccess
		resp.Authoritative = true
		resp.Answer = []dns.RR{&dns.A{
			Hdr: dns.RR_Header{Name: req.Question[0].Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 0},
			A:   net.ParseIP("127.0.0.1"),
		}}
		return resp
	})

	c := NewClient("127.0.0.1:53").WithDoH(srv.URL)
	resp, err := c.Query(dns.Fqdn("a.example."), dns.TypeA)
	if err != nil {
		t.Fatalf("Query over DoH: %v", err)
	}
	if len(resp.Answer) != 1 {
		t.Fatalf("answers = %d, want 1", len(resp.Answer))
	}
}

// A signed discovery document verifies over DoH when the client holds the key.
func TestDoHDiscoveryVerifiedOK(t *testing.T) {
	key := []byte("doh-discovery-key")
	doc := DiscoveryResponse{Version: 1, Tools: []Tool{{Name: "echo"}}}
	b, _ := json.Marshal(doc)
	sig := auth.Sign(key, "discovery", "", b, 0)
	doc.Sig = sig
	out, _ := json.Marshal(doc)

	srv, _ := dohServer(t, func(req *dns.Msg) *dns.Msg {
		return dohDiscoveryResponse(req, string(out))
	})

	c := NewClient("127.0.0.1:53").WithDoH(srv.URL).WithDiscoveryKey(key)
	if _, err := c.Discovery(testZone); err != nil {
		t.Fatalf("verified discovery over DoH: %v", err)
	}
}

// An unsigned discovery document is rejected over DoH when a key is configured.
func TestDoHDiscoveryUnsignedRejected(t *testing.T) {
	key := []byte("doh-discovery-key")
	doc := DiscoveryResponse{Version: 1}
	out, _ := json.Marshal(doc) // no Sig field

	srv, _ := dohServer(t, func(req *dns.Msg) *dns.Msg {
		return dohDiscoveryResponse(req, string(out))
	})

	c := NewClient("127.0.0.1:53").WithDoH(srv.URL).WithDiscoveryKey(key)
	if _, err := c.Discovery(testZone); err == nil {
		t.Fatal("expected a verification failure for an unsigned discovery document over DoH")
	}
}

// A non-200 DoH response surfaces as an error.
func TestDoHErrorStatus(t *testing.T) {
	srv, _ := dohServer(t, func(req *dns.Msg) *dns.Msg {
		return nil // handler signals failure with a nil reply -> 500
	})

	c := NewClient("127.0.0.1:53").WithDoH(srv.URL)
	if _, err := c.Discovery(testZone); err == nil {
		t.Fatal("expected an error when the DoH endpoint returns a non-200 status")
	}
}

// A malformed DoH endpoint surfaces a request-build error.
func TestDoHMalformedEndpoint(t *testing.T) {
	c := NewClient("127.0.0.1:53").WithDoH("ht!tp://invalid")
	if _, err := c.Discovery(testZone); err == nil {
		t.Fatal("expected a request-build error for a malformed DoH endpoint")
	}
}

// A DoH endpoint that returns non-DNS bytes surfaces an unpack error.
func TestDoHInvalidResponse(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/dns-message")
		if _, err := w.Write([]byte("not a dns message")); err != nil {
			_ = err
		}
	}))
	t.Cleanup(srv.Close)

	c := NewClient("127.0.0.1:53").WithDoH(srv.URL)
	if _, err := c.Discovery(testZone); err == nil {
		t.Fatal("expected an unpack error for a non-DNS DoH response")
	}
}

// A DoH endpoint that refuses the connection surfaces a request error.
func TestDoHConnectionRefused(t *testing.T) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	addr := l.Addr().String()
	_ = l.Close() // free the port so the dial is refused

	c := NewClient("127.0.0.1:53").WithDoH("https://" + addr + "/dns-query")
	if _, err := c.Discovery(testZone); err == nil {
		t.Fatal("expected a request error when the DoH endpoint refuses the connection")
	}
}
