// Package testresolver runs a real Unbound recursive resolver in front of a
// test server, so tests can exercise the path a deployed client takes:
// client -> recursive resolver -> authoritative mcport53 server.
//
// Tests skip when Unbound is not installed, unless MCP53_REQUIRE_UNBOUND=1
// (set in CI), in which case they fail. MCP53_UNBOUND overrides the binary.
package testresolver

import (
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/miekg/dns"
)

// Options configures the resolver.
type Options struct {
	// CapsForID enables DNS 0x20: Unbound randomises the case of the names it
	// sends upstream and checks the answer echoes it.
	CapsForID bool
}

// Binary returns the Unbound binary to use, or "" if none is installed.
func Binary() string {
	if p := os.Getenv("MCP53_UNBOUND"); p != "" {
		return p
	}
	if p, err := exec.LookPath("unbound"); err == nil {
		return p
	}
	for _, p := range []string{"/opt/homebrew/sbin/unbound", "/usr/local/sbin/unbound", "/usr/sbin/unbound"} {
		if _, err := os.Stat(p); err == nil {
			return p
		}
	}
	return ""
}

// Start runs Unbound with a stub zone for zone pointing at upstream (an
// authoritative server's host:port, serving UDP and TCP) and returns the
// resolver's address. QNAME minimisation is on, as in Unbound's default.
func Start(t testing.TB, upstream, zone string, opt Options) string {
	t.Helper()
	bin := Binary()
	if bin == "" {
		if os.Getenv("MCP53_REQUIRE_UNBOUND") == "1" {
			t.Fatal("unbound not found and MCP53_REQUIRE_UNBOUND=1")
		}
		t.Skip("unbound not installed")
	}
	host, port, err := net.SplitHostPort(upstream)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	listen := freePort(t)
	caps := "no"
	if opt.CapsForID {
		caps = "yes"
	}
	zone = dns.Fqdn(zone)
	conf := fmt.Sprintf(`server:
  interface: 127.0.0.1
  port: %s
  do-daemonize: no
  username: ""
  chroot: ""
  directory: %q
  pidfile: %q
  logfile: %q
  use-syslog: no
  verbosity: 1
  access-control: 127.0.0.0/8 allow
  do-not-query-localhost: no
  module-config: "iterator"
  qname-minimisation: yes
  use-caps-for-id: %s
  harden-glue: no
  domain-insecure: %q
  local-zone: %q nodefault
  cache-max-ttl: 0
  cache-max-negative-ttl: 0
  infra-host-ttl: 1
stub-zone:
  name: %q
  stub-addr: %s@%s
`, listen, dir, filepath.Join(dir, "unbound.pid"), filepath.Join(dir, "unbound.log"),
		caps, zone, zone, zone, host, port)
	path := filepath.Join(dir, "unbound.conf")
	if err := os.WriteFile(path, []byte(conf), 0o600); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(bin, "-d", "-c", path)
	var out strings.Builder
	cmd.Stdout, cmd.Stderr = &out, &out
	if err := cmd.Start(); err != nil {
		t.Fatalf("start unbound: %v", err)
	}
	t.Cleanup(func() { _ = cmd.Process.Kill(); _ = cmd.Wait() })

	addr := net.JoinHostPort("127.0.0.1", listen)
	deadline := time.Now().Add(10 * time.Second)
	for {
		m := new(dns.Msg)
		m.SetQuestion(zone, dns.TypeSOA)
		if resp, _, err := (&dns.Client{Timeout: 500 * time.Millisecond}).Exchange(m, addr); err == nil && resp.Rcode != dns.RcodeRefused {
			return addr
		}
		if time.Now().After(deadline) {
			log, _ := os.ReadFile(filepath.Join(dir, "unbound.log"))
			t.Fatalf("unbound did not start:\n%s\n%s", out.String(), log)
		}
		time.Sleep(100 * time.Millisecond)
	}
}

func freePort(t testing.TB) string {
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
			_, port, _ := net.SplitHostPort(addr)
			return port
		}
	}
	t.Fatal("no free port")
	return ""
}
