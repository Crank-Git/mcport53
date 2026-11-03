# mcport53

**MCP tools reachable over DNS.** An agent whose tools work anywhere port 53 gets
out — behind captive portals, locked-down egress, and network-restricted
environments.

MCPort53 turns MCP tool calls into DNS queries and results into DNS responses.
Because outbound DNS (UDP/TCP **port 53**) is almost always permitted, you can
reach tools in places where HTTP, websockets, or raw TCP cannot.

- **Protocol spec:** [`docs/PROTOCOL.md`](docs/PROTOCOL.md)
- **Deploying behind real resolvers:** [`docs/DEPLOYMENT.md`](docs/DEPLOYMENT.md)
- **Encoding:** DNS-safe base32 labels, chunked to DNS limits
- **Discovery:** SRV + TXT listing tools and schemas
- **Calls:** `<args>.<tool>.call.<zone>` -> TXT result
- **Large/long results:** chunked sessions + job polling
- **Auth:** optional HMAC signature + nonce (replay protection)

## Install

Prebuilt `mcp53-server` and `mcp53-client` binaries for Linux, macOS and Windows
(amd64 and arm64) are attached to each
[release](https://github.com/Crank-Git/mcport53/releases), with a `SHA256SUMS`
file:

```bash
curl -LO https://github.com/Crank-Git/mcport53/releases/download/v0.1.0/mcport53_v0.1.0_linux_amd64.tar.gz
tar -xzf mcport53_v0.1.0_linux_amd64.tar.gz
```

Or build from source with Go:

```bash
go install github.com/Crank-Git/mcport53/cmd/mcp53-server@latest
go install github.com/Crank-Git/mcport53/cmd/mcp53-client@latest
```

## Quick start

```bash
# Run the reference server (exposes example tools over DNS on 127.0.0.1:5333)
go run ./cmd/mcp53-server --zone example.

# List the tools it serves
go run ./cmd/mcp53-client --server 127.0.0.1:5333 --zone example.

# Call a tool and print the result
go run ./cmd/mcp53-client --server 127.0.0.1:5333 --zone example. --tool echo --args '{"text":"hi"}'
```

See [`docs/PROTOCOL.md`](docs/PROTOCOL.md) for the full protocol,
[`docs/EXAMPLES.md`](docs/EXAMPLES.md) for end-to-end walkthroughs, and
[`docs/DEPLOYMENT.md`](docs/DEPLOYMENT.md) for delegating a zone and what works
through a recursive resolver.

## Branch model

- **`dev`** is the primary/default branch.
- **`main`** is the secondary branch.
- All work happens on a feature branch off `dev` and lands via a **Pull Request
  into `dev`**. See [`CONTRIBUTING.md`](CONTRIBUTING.md).

## License

MIT — see [LICENSE](LICENSE).
