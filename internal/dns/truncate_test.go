package dns

import (
	"net"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Crank-Git/mcport53/internal/codec"
	"github.com/miekg/dns"
)

// bigHandlers answers every call with a result of n bytes and counts calls.
func bigHandlers(n int, calls *atomic.Int64) *Handlers {
	return &Handlers{
		OnCall: func(req *CallRequest) *codec.Envelope {
			if calls != nil {
				calls.Add(1)
			}
			return codec.OK(req.Tool, strings.Repeat("x", n), 0)
		},
		OnDiscovery: func() *DiscoveryResponse {
			var tools []Tool
			for _, name := range []string{"add", "echo", "upper"} {
				tools = append(tools, Tool{Name: name, Description: "an example tool with a description of ordinary length",
					InputSchema: []byte(`{"type":"object","properties":{"text":{"type":"string"}},"required":["text"]}`)})
			}
			return &DiscoveryResponse{Version: 1, Tools: tools}
		},
	}
}

// serve runs srv.ListenAndServe on an ephemeral port and returns its address.
func serve(t *testing.T, srv *Server) string {
	t.Helper()
	errc := make(chan error, 1)
	go func() { errc <- srv.ListenAndServe("127.0.0.1:0") }()
	deadline := time.Now().Add(3 * time.Second)
	for {
		srv.mu.Lock()
		running := srv.running
		srv.mu.Unlock()
		if len(running) > 0 {
			addr := running[0].PacketConn.LocalAddr().String()
			t.Cleanup(func() {
				srv.Shutdown()
				if err := <-errc; err != nil {
					t.Errorf("ListenAndServe returned %v after Shutdown", err)
				}
			})
			return addr
		}
		select {
		case err := <-errc:
			t.Fatalf("ListenAndServe: %v", err)
		default:
		}
		if time.Now().After(deadline) {
			t.Fatal("server did not start")
		}
		time.Sleep(5 * time.Millisecond)
	}
}

func callQuestion(tool string) *dns.Msg {
	nonce, _ := codec.RandomNonce()
	m := new(dns.Msg)
	m.SetQuestion(LabelsToName(codec.BuildCallName(NameToLabels(testZone), tool, []byte(`{}`), nonce, "")), dns.TypeTXT)
	return m
}

func rawExchange(t *testing.T, network, addr string, m *dns.Msg, provider dns.TsigProvider) (*dns.Msg, int) {
	t.Helper()
	c := &dns.Client{Net: network, Timeout: 2 * time.Second, UDPSize: 65535, TsigProvider: provider}
	resp, _, err := c.Exchange(m, addr)
	if err != nil {
		t.Fatalf("%s exchange: %v", network, err)
	}
	packed, err := resp.Pack()
	if err != nil {
		t.Fatalf("repack: %v", err)
	}
	return resp, len(packed)
}

// TestUDPTruncatesToRequesterSize covers the advertised-size matrix: no EDNS
// (512), EDNS 1232, and an oversized advertisement capped at 4096.
func TestUDPTruncatesToRequesterSize(t *testing.T) {
	addr := serve(t, NewServer(testZone, bigHandlers(3000, nil)))
	for _, tc := range []struct {
		name  string
		edns  uint16 // 0 = no OPT record
		limit int
	}{
		{"no EDNS", 0, 512},
		{"EDNS 1232", 1232, 1232},
		{"EDNS 65000", 65000, 4096},
	} {
		q := callQuestion("big")
		if tc.edns > 0 {
			q.SetEdns0(tc.edns, false)
		}
		resp, size := rawExchange(t, "udp", addr, q, nil)
		if !resp.Truncated {
			t.Errorf("%s: 3000-byte answer not truncated (size %d)", tc.name, size)
		}
		if size > tc.limit {
			t.Errorf("%s: %d-byte UDP answer exceeds %d", tc.name, size, tc.limit)
		}
		if (tc.edns > 0) != (resp.IsEdns0() != nil) {
			t.Errorf("%s: reply EDNS present=%v, want %v", tc.name, resp.IsEdns0() != nil, tc.edns > 0)
		}
	}
}

// TestDiscoveryOver512IsTruncatedWithoutEDNS is the case from the issue: an
// ordinary discovery document no longer goes out as an oversized UDP packet.
func TestDiscoveryOver512IsTruncatedWithoutEDNS(t *testing.T) {
	addr := serve(t, NewServer(testZone, bigHandlers(10, nil)))
	q := new(dns.Msg)
	q.SetQuestion("_mcp._udp."+testZone, dns.TypeTXT)
	full, fullSize := rawExchange(t, "tcp", addr, q.Copy(), nil)
	if fullSize <= 512 || full.Truncated {
		t.Fatalf("fixture: TCP discovery is %d bytes truncated=%v; want > 512 untruncated", fullSize, full.Truncated)
	}
	resp, size := rawExchange(t, "udp", addr, q, nil)
	if !resp.Truncated || size > 512 {
		t.Fatalf("UDP discovery: truncated=%v size=%d, want TC within 512", resp.Truncated, size)
	}
}

// TestSmallAnswerNotTruncated checks answers that fit go out whole over UDP.
func TestSmallAnswerNotTruncated(t *testing.T) {
	addr := serve(t, NewServer(testZone, bigHandlers(100, nil)))
	resp, _ := rawExchange(t, "udp", addr, callQuestion("small"), nil)
	if resp.Truncated {
		t.Fatal("small answer truncated")
	}
	txt, err := extractTXT(resp)
	if err != nil || !strings.Contains(txt, strings.Repeat("x", 100)) {
		t.Fatalf("small answer content: %q err=%v", txt, err)
	}
}

// TestTCPCarriesFullAnswer checks the same large answer arrives whole over the
// TCP listener ListenAndServe now opens on the same port.
func TestTCPCarriesFullAnswer(t *testing.T) {
	addr := serve(t, NewServer(testZone, bigHandlers(3000, nil)))
	resp, size := rawExchange(t, "tcp", addr, callQuestion("big"), nil)
	if resp.Truncated || size < 3000 {
		t.Fatalf("TCP answer truncated=%v size=%d", resp.Truncated, size)
	}
	txt, err := extractTXT(resp)
	if err != nil {
		t.Fatal(err)
	}
	e, err := codec.ParseEnvelope([]byte(txt))
	if err != nil || len(e.Result) != 3000 {
		t.Fatalf("TCP envelope result %d bytes err=%v", len(e.Result), err)
	}
}

// TestClientRetriesTruncatedOverTCP checks Client falls back to TCP on TC=1
// transparently, and only when needed.
func TestClientRetriesTruncatedOverTCP(t *testing.T) {
	var calls atomic.Int64
	addr := serve(t, NewServer(testZone, bigHandlers(3000, &calls)))
	c := NewClient(addr)
	e, err := c.Call(testZone, "big", []byte(`{}`), "")
	if err != nil || e.Status != codec.StatusOK || len(e.Result) != 3000 {
		t.Fatalf("large call: env status=%v len=%d err=%v", e.Status, len(e.Result), err)
	}
	// The TCP retry is a copy of the same call, answered from the call cache:
	// the tool runs once.
	if got := calls.Load(); got != 1 {
		t.Fatalf("large call reached the handler %d times, want 1 (TCP retry served from the call cache)", got)
	}

	var smallCalls atomic.Int64
	addr2 := serve(t, NewServer(testZone, bigHandlers(50, &smallCalls)))
	if _, err := NewClient(addr2).Call(testZone, "small", []byte(`{}`), ""); err != nil {
		t.Fatal(err)
	}
	if got := smallCalls.Load(); got != 1 {
		t.Fatalf("small call reached the handler %d times, want 1 (no retry)", got)
	}
}

// TestClientAdvertisesEDNS checks queries carry an OPT record with the
// default buffer size.
func TestClientAdvertisesEDNS(t *testing.T) {
	seen := make(chan *dns.Msg, 1)
	c := startRawServer(t, func(req *dns.Msg) *dns.Msg {
		select {
		case seen <- req.Copy():
		default:
		}
		resp := reply(req)
		resp.Rcode = dns.RcodeNameError
		return resp
	})
	_, _ = c.Query("x."+testZone, dns.TypeTXT)
	q := <-seen
	opt := q.IsEdns0()
	if opt == nil || opt.UDPSize() != EDNSBufferSize {
		t.Fatalf("query OPT = %v, want UDP size %d", opt, EDNSBufferSize)
	}
}

// TestTSIGTruncationAndRetry checks a truncated UDP answer is still a valid
// TSIG-signed message within the advertised size, and that a TSIG client
// retries over TCP and verifies the full answer.
func TestTSIGTruncationAndRetry(t *testing.T) {
	secret := []byte("tsig-secret")
	ks := NewTsigKeys().With("mcport53.", secret)
	addr := serve(t, NewServer(testZone, bigHandlers(3000, nil)).WithTSIGKeys(ks))

	q := callQuestion("big")
	q.SetEdns0(1232, false)
	q.SetTsig(CanonicalKey("mcport53."), dns.HmacSHA256, 300, time.Now().Unix())
	resp, size := rawExchange(t, "udp", addr, q, ks.provider())
	if !resp.Truncated || size > 1232 {
		t.Fatalf("TSIG UDP answer truncated=%v size=%d, want TC within 1232", resp.Truncated, size)
	}
	if resp.IsTsig() == nil {
		t.Fatal("truncated answer is not TSIG-signed")
	}

	c := NewClient(addr).WithTSIG("mcport53.", secret)
	e, err := c.Call(testZone, "big", []byte(`{}`), "")
	if err != nil || len(e.Result) != 3000 {
		t.Fatalf("TSIG call via TCP retry: len=%d err=%v", len(e.Result), err)
	}
}

// TestListenAndServeBindFailureLeavesNothingRunning: when the UDP port is
// taken, ListenAndServe fails and leaves the TCP port free.
func TestListenAndServeBindFailureLeavesNothingRunning(t *testing.T) {
	taken, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer taken.Close()
	addr := taken.LocalAddr().String()
	if err := NewServer(testZone, &Handlers{}).ListenAndServe(addr); err == nil {
		t.Fatal("ListenAndServe succeeded on a taken UDP port")
	}
	l, err := net.Listen("tcp", addr)
	if err != nil {
		t.Fatalf("TCP port left bound after a failed ListenAndServe: %v", err)
	}
	_ = l.Close()
}

// TestShutdownStopsBothListeners checks UDP and TCP both stop.
func TestShutdownStopsBothListeners(t *testing.T) {
	srv := NewServer(testZone, bigHandlers(10, nil))
	errc := make(chan error, 1)
	go func() { errc <- srv.ListenAndServe("127.0.0.1:0") }()
	var addr string
	for i := 0; i < 300 && addr == ""; i++ {
		srv.mu.Lock()
		if len(srv.running) > 0 {
			addr = srv.running[0].PacketConn.LocalAddr().String()
		}
		srv.mu.Unlock()
		time.Sleep(5 * time.Millisecond)
	}
	if addr == "" {
		t.Fatal("server did not start")
	}
	srv.Shutdown()
	select {
	case err := <-errc:
		if err != nil {
			t.Fatalf("ListenAndServe after Shutdown: %v", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("ListenAndServe did not return after Shutdown")
	}
	// Both ports are free again.
	pc, err := net.ListenPacket("udp", addr)
	if err != nil {
		t.Fatalf("UDP still bound: %v", err)
	}
	pc.Close()
	l, err := net.Listen("tcp", addr)
	if err != nil {
		t.Fatalf("TCP still bound: %v", err)
	}
	l.Close()
}
