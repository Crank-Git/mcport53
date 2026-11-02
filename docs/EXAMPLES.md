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
`--secret` (optional HMAC shared secret, see [Signing calls](#6-signing-calls)),
`--discover` (SRV target advertised in discovery, default `127.0.0.1:53`).

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

Tools that return `queued` are polled via the job API. The client waits for the
result before printing it; the server tracks the job by session. See
[protocol §4.3](PROTOCOL.md#43-job-polling).

## 6. Signing calls

To protect calls from tampering and replay, start the server with a shared
secret and the client will sign each call.

```bash
go run ./cmd/mcp53-server --zone example. --secret s3cr3t
```

Calls made without the matching secret are rejected by the server. See
[protocol §7](PROTOCOL.md#7-auth-replay-protection-optional).

## 7. Pointing at a real resolver

The examples above talk to the server directly on `127.0.0.1:5333`. In a real
deployment you run the server behind a public resolver and point that resolver
(or the client's `--server`) at the authoritative zone. Advertise the resolver
from the server so discovery points clients at the right address:

```bash
go run ./cmd/mcp53-server --zone example. --discover dns.example.com:53
```

Then query through the resolver:

```bash
go run ./cmd/mcp53-client --server 198.51.100.53 --zone example. \
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
