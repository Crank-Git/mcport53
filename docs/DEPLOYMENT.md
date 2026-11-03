# Deploying mcport53

This guide puts an `mcp53-server` on the public DNS so an agent can reach its tools
through whatever resolver its network provides: client → recursive resolver →
your server.

Everything below that says *works through a resolver* is covered by the
end-to-end tests in `pkg/mcp/resolver_test.go`, which run a real Unbound (with
QNAME minimisation and 0x20 case randomisation) in front of the server in CI.

## 1. Choose a zone

Use a subdomain of a domain you control, delegated to the server, for example
`mcp.example.com.`. The server must be the only authority for it: every name
under the zone is a potential call, so nothing else can live there.

## 2. Run the server on port 53

The server listens on UDP and TCP on the same port. Resolvers retry over TCP when
an answer does not fit in UDP, so both must be reachable.

```bash
go build -o mcp53-server ./cmd/mcp53-server

# Binding port 53 needs root or the capability (Linux):
sudo setcap cap_net_bind_service=+ep ./mcp53-server

./mcp53-server \
  --zone mcp.example.com. \
  --addr 0.0.0.0:53 \
  --nameserver ns-mcp.example.com \
  --discover ns-mcp.example.com:53 \
  --key "$MCP53_KEY"
```

- `--nameserver` is the name the zone's NS and SOA records use. Make it match
  the NS record in the parent zone (step 3).
- `--key` turns on HMAC call signing, which is end to end and survives
  resolvers (§7 of the protocol). Use it for anything not meant to be public.
- Open **UDP and TCP 53** inbound in the host and cloud firewalls.

## 3. Delegate the zone

In the parent zone (`example.com`), add an NS record for the subdomain and a glue
address record for the name server:

```
mcp.example.com.      3600  IN  NS  ns-mcp.example.com.
ns-mcp.example.com.   3600  IN  A   203.0.113.10
```

Check the delegation from outside:

```bash
dig +trace mcp.example.com. SOA
dig @1.1.1.1 _mcp._udp.mcp.example.com. TXT    # discovery through a public resolver
```

## 4. Point the client at a resolver

Use the resolver the network hands out, a public resolver, or DNS-over-HTTPS:

```bash
# The network's own resolver (see /etc/resolv.conf)
mcp53-client --server 192.168.1.1:53 --zone mcp.example.com. --key "$MCP53_KEY" \
  --tool echo --args '{"text":"hi"}'

# A public resolver
mcp53-client --server 1.1.1.1:53 --zone mcp.example.com. --key "$MCP53_KEY"

# DNS-over-HTTPS (RFC 8484), when only HTTPS gets out
mcp53-client --doh https://cloudflare-dns.com/dns-query --zone mcp.example.com. --key "$MCP53_KEY"
```

## Private deployments without public DNS

On a network you control, make the local resolver send the zone to the server
instead of delegating it publicly.

**Unbound**

```
server:
  do-not-query-localhost: no   # only if the server runs on the same host
  domain-insecure: "mcp.internal."
stub-zone:
  name: "mcp.internal."
  stub-addr: 10.0.0.53@53
```

**BIND**

```
zone "mcp.internal" {
  type static-stub;
  server-addresses { 10.0.0.53; };
};
```

## What works through a resolver

| feature | through a resolver |
|---|---|
| discovery, schema, calls | yes |
| HMAC-signed calls and per-tool keys (§7) | yes, end to end |
| signed discovery (§7.3) | yes |
| large results: chunks, cursors, gzip (§4.2, §4.4) | yes |
| answers over 1232 bytes (resolver retries over TCP) | yes |
| uploaded arguments up to 64 KiB (§3.1) | yes |
| long-running calls via jobs (§4.3) | yes |
| case-randomising (0x20) and QNAME-minimising resolvers | yes |
| resolver retransmissions (a tool runs once per call) | yes |
| **TSIG** (§8) | **no**: TSIG authenticates one hop, and a resolver does not forward it. Use HMAC signing |
| **DNS-over-TLS to the server** (§8) | **no**: DoT is between the client and the server directly. Use DoH or DoT to the *resolver* instead |

## Things to know

- **Privacy.** Call names carry the arguments (base32) and answers carry the
  results (base64). They are encoded, not encrypted: the resolver, and anyone
  between the resolver and your server, can read them. HMAC signing protects
  integrity, not confidentiality. Using DoH or DoT to the resolver hides the
  traffic from the local network, not from the resolver.
- **Caching.** Every answer has TTL 0 and every call name carries a nonce, so
  call results are not served from resolver caches. Some resolvers raise very low
  TTLs to a minimum; that only affects discovery and immutable chunk answers.
- **Rate limits.** Public resolvers limit queries per client. A large result or
  upload takes one query per 400-byte chunk or ~126-byte part (§3.1, §4.2), so
  very large payloads may be throttled.
- **Tunnel detection.** Many enterprise DNS security products flag long,
  high-entropy query names as DNS tunnelling. On networks you do not operate,
  expect this traffic to be visible and possibly blocked.
- **Timeouts.** The client's per-query timeout must exceed the server's inline
  budget (750 ms by default, `WithInlineBudget`). Longer calls continue as jobs.
