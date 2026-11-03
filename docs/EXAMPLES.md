# MCPort53 examples

End-to-end walkthroughs for the reference `mcp53-server` and `mcp53-client`
clis. Everything below runs against the local server on
`127.0.0.1:5333` (the default listen address).

Prerequisites: Go 1.27+.

## 1. Start the server

The reference server exposes a small built-in tool set (`add`, `echo`, `upper`)
and serves them authoritatively for a zone.

```bash
go run ./cmd/mcp53-server --zone example.
```

```
mcp53-server: listening on 127.0.0.1:5333 for zone example. (3 tools)
```

Flags: `--zone` (authoritative base domain, default `example.`),
`--addr` (listen address, default `127.0.0.1:5333`),
`--secret` / `--key` / `--keys` (HMAC call signing, see [Signing calls](#6-signing-calls)),
`--tsig`, `--tls-cert` / `--tls-key` (transport security, see
[Transport security](#61-transport-security-tsig-and-dns-over-tls)),
`--discover` (SRV target advertised in discovery, default: the `--addr` value).

`--discover` controls what the `_mcp._udp` SRV record points clients at (protocol
§2.1). Leave it at the default for local runs; in a real deployment point it at
the reachable resolver, e.g. `--discover dns.example.com:53`.

## 2. List the tools it serves

Run the client with no `--tool` to print the discovery document.

```bash
go run ./cmd/mcp53-client --server 127.0.0.1:5333 --zone example.
```

```
version 1: 3 tool(s)

  add     Add two numbers and return their sum.
  echo    Return the supplied text unchanged.
  upper   Return the supplied text in uppercase.
```

## 3. Call a tool

Pass `--tool` and JSON `--args`. The assembled result is printed.

```bash
go run ./cmd/mcp53-client --server 127.0.0.1:5333 --zone example. \
  --tool echo --args '{"text":"hi"}'
```

```
{
  "content": [
    {
      "text": "hi",
      "type": "text"
    }
  ]
}
```

Numeric tools work the same way — `--args` is passed straight through as JSON:

```bash
go run ./cmd/mcp53-client --server 127.0.0.1:5333 --zone example. \
  --tool add --args '{"a":2,"b":40}'
```

```
{
  "content": [
    {
      "text": "42",
      "type": "text"
    }
  ]
}
```

`--args` must be valid JSON; invalid JSON is rejected before the query is sent:

```
mcp53-client: --args must be valid JSON: not json
```

## 4. Large results

Results that exceed the DNS TXT size limit are split across multiple queries
and reassembled by the client automatically. You do not pass any extra flags —
the client handles chunking transparently. See
[protocol §4.2](PROTOCOL.md#42-txt-size-limit-chunking) for details.

## 5. Long-running jobs

A tool that is still running after 750 ms is answered `queued` and continues as
a job. The client polls the job and prints the result when it finishes, so slow
tools work through resolvers that would otherwise give up on a long-running
query. See [protocol §4.3](PROTOCOL.md#43-job-polling).

## 6. Signing calls

To protect calls from tampering and replay, start the server with a key and pass
the same key to the client, which signs each call.

```bash
go run ./cmd/mcp53-server --zone example. --key s3cr3t
go run ./cmd/mcp53-client --zone example. --key s3cr3t --tool echo --args '{"text":"hi"}'
```

Unsigned calls and calls signed with another key are rejected by the server.
`--secret` on the server accepts the same client `--key`.

Per-tool keys override the default key for named tools, on both sides:

```bash
go run ./cmd/mcp53-server --key default-key --keys echo=echo-key
go run ./cmd/mcp53-client --key default-key --keys echo=echo-key --tool echo --args '{"text":"hi"}'
```

A server started with `--key` also signs its discovery document. Add
`--verify-discovery` to the client to reject a document that is unsigned or
signed with another key. See
[protocol §7](PROTOCOL.md#7-auth-replay-protection-optional).

### 6.1 Transport security: TSIG and DNS-over-TLS

TSIG signs every query and response at the DNS layer:

```bash
go run ./cmd/mcp53-server --tsig mcport53.:tsig-secret
go run ./cmd/mcp53-client --tsig mcport53.:tsig-secret --tool echo --args '{"text":"hi"}'
```

DNS-over-TLS encrypts the exchange. The client trusts the system roots, or the
certificates in `--tls-ca` (for a private CA or self-signed certificate):

```bash
go run ./cmd/mcp53-server --tls-cert cert.pem --tls-key key.pem
go run ./cmd/mcp53-client --tls --tls-ca cert.pem --tool echo --args '{"text":"hi"}'
```

`--tls-insecure` skips certificate verification; use it only for testing.

## 7. Pointing at a real resolver

The examples above talk to the server directly on `127.0.0.1:5333`. In a real
deployment the zone is delegated to the server and clients query through an
ordinary recursive resolver; [`DEPLOYMENT.md`](DEPLOYMENT.md) covers delegation,
private stub zones, and what does and does not work through a resolver.
Advertise the server's public address in discovery:

```bash
go run ./cmd/mcp53-server --zone example. --discover dns.example.com:53
```

Then query through the resolver:

```bash
go run ./cmd/mcp53-client --server 198.51.100.53:53 --zone example. \
  --tool echo --args '{"text":"hi"}'
```

`--server` is a `host:port` DNS address, not a hostname.

### 7.1. Through DNS-over-HTTPS

The cleanest way to reach the authoritative server through a normal resolver is
DNS-over-HTTPS (`--doh`, RFC 8484). The client sends every query to a DoH
endpoint instead of opening a direct UDP/53 socket, so the resolver at the server
host forwards the query to the authoritative server while the transport stays
encrypted and egress-friendly. Point `--doh` at the endpoint and drop `--server`:

```bash
go run ./cmd/mcp53-client --doh https://dns.example.com/dns-query \
  --zone example. --tool echo --args '{"text":"hi"}'
```

Discovery works the same way: the client's discovery query is sent to the DoH
endpoint, which returns the SRV + TXT records for the zone.

## Related

- [Protocol spec](PROTOCOL.md) — naming, encoding, envelopes, auth.
- [README](../README.md) — overview and branch model.
