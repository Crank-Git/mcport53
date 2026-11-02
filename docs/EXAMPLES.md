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
`--secret` (optional HMAC shared secret, see [Signing calls](#6-signing-calls)).

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
deployment you run the server on a host reachable over DNS and point a resolver
(or the client's `--server`) at it:

```bash
go run ./cmd/mcp53-client --server 198.51.100.53 --zone example. \
  --tool echo --args '{"text":"hi"}'
```

`--server` is a `host:port` DNS address, not a hostname.

## Related

- [Protocol spec](PROTOCOL.md) — naming, encoding, envelopes, auth.
- [README](../README.md) — overview and branch model.
