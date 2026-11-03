# MCPort53 — MCP over DNS

**Specification v0.1 (draft)**

> An agent whose tools are reachable through DNS. Works anywhere port 53 gets out —
> captive portals, locked-down networks, air-gapped-ish egress allow-lists.

---

## 1. Overview

Model Context Protocol (MCP) exposes tools as RPC calls. MCPort53 adds a **DNS
transport** for those calls: a tool invocation becomes a DNS query, and the result
comes back in a DNS response. Because outbound DNS (UDP/TCP **port 53**) is almost
always permitted — even behind captive portals and restrictive egress lists — an
agent can reach tools in places where HTTP/WS/MCP over TCP cannot.

Two roles:

- **DNS client** (the agent / MCP client): sends standard DNS wire-format queries
  that encode a tool name + arguments, and parses the response.
- **DNS server** (authoritative for a tool zone): receives the query, decodes the
  tool call, invokes the tool, and answers with the result.

The transport is **real DNS** (RFC 1035 message format). The client queries the
server directly (e.g. `dig @server <name>`-style), because recursive public
resolvers will not forward arbitrary names to an arbitrary host. Using a standard
DNS message also lets you piggyback on DoH/DoT/DoQ if you want to disguise the
traffic further.

### Design goals

1. **Standard DNS messages only.** No custom TCP framing, no new ports required.
2. **DNS-safe encoding.** Every label uses the lowercase base32 alphabet
   (`a–z2–7`, RFC 4648),
   which is valid in DNS names and case-insensitive-safe.
3. **Respects DNS limits.** Names ≤ 253 bytes, labels ≤ 63 bytes, TXT ≤ 255 bytes.
4. **Cache-oblivant.** Call queries are never silently served from resolver cache
   (see §6).
5. **Authenticatable.** Optional HMAC signature + nonce for auth and replay
   protection (see §7).

---

## 2. Namespace & naming

The server is **authoritative** for a base domain, called the **zone**, e.g.
`example.` (or `mcp.example.`). All discovery, schema, call, and result names live
under that zone.

Reserved structural labels (lowercase, literal):

| Label    | Meaning                                        |
|----------|------------------------------------------------|
| `call`   | marks the end of the args / start of the zone  |
| `schema` | per-tool input-schema lookup                   |
| `chunk`  | fetch one chunk of a large result              |
| `job`    | poll the status of a long-running call         |
| `result` | (alias) fetch the assembled large result       |

**Tool names** are a single DNS label: `[a-z0-9_-]`, up to 63 characters. They must
not equal a reserved structural label.

### 2.1 Discovery names

- **SRV** — `_mcp._udp.<zone>`
  Points clients at the authoritative server + port.

  ```
  _mcp._udp.example.  IN  SRV  0  0  53 dns.example.
  ```

- **TXT** — `_mcp._udp.<zone>`
  Lists the tools the server offers, as a JSON array of `{name, description,
  inputSchema}` (the MCP `tool` shape). This is the discovery document.

  ```
  _mcp._udp.example.  IN  TXT  "{\"version\":1,\"tools\":[...]}"
  ```

### 2.2 Per-tool schema name

- `<tool>.schema.<zone>` → TXT containing the tool's `inputSchema` (JSON Schema).

### 2.3 Call name

```
<sig>.<arg-labels...>.<tool>.call.<nonce>.<zone>
```

Reading **right-to-left**:

1. `<zone>` — the authoritative base domain (1+ labels).
2. `<nonce>` — a unique random label (see §6). Makes the name uncacheable.
3. literal `call`.
4. `<tool>` — the tool name (single label).
5. `<arg-labels...>` — base32-encoded, chunked arguments, most-significant chunk
   leftmost. Zero or more labels.
6. `<sig>` — optional HMAC signature label (see §7). Absent = unsigned.

The client concatenates the arg labels left-to-right and base32-decodes them to
recover the argument bytes.

### 2.4 Result / chunk / job names

Used by the server's response to instruct the client how to continue for large or
long-running results:

```
<chunk-index>.<session>.chunk.<zone>     # fetch one result chunk
<job>.job.<zone>                          # poll job status
```

- `<session>` — a server-assigned session id for a large result.
- `<chunk-index>` — 0-based index of the chunk.
- `<job>` — a job id returned for long-running calls.

---

## 3. Argument encoding

Arguments are serialized as a single byte string, then **base32-encoded (RFC 4648,
lowercase, no padding)** and **chunked into ≤63-byte labels**.

1. Serialize tool arguments. For structured arguments, use **JSON**. For binary
   results, use **base64** within the JSON envelope (see §5).
2. `b32 = base32_no_pad(json_bytes)` (alphabet `a–z2–7`, RFC 4648).
3. Split `b32` into consecutive substrings of ≤63 chars. Each becomes one DNS
   label, most-significant first.

Example: args `{"q":"hi"}` → JSON `{"q":"hi"}` → 13 bytes → base32
`NBSWY3DPF3SXV53TN2TXQ53J` → labels `nbswy3dpf3sxv53tn2txq53j`.

Full call name:
`nbswy3dpf3sxv53tn2txq53j.tool.call.<nonce>.example`

**Encoding alphabet & charset rule:** only `a–z` and `2–7` are emitted, guaranteeing
DNS-safety and avoiding case/`-`/`_` ambiguity.

---

## 4. Result envelope

Results are returned in a **TXT** record. The TXT carries a single JSON **envelope**:

```json
{
  "v": 1,
  "status": "ok",
  "tool": "tool_name",
  "result": "{ ... serialized tool result ... }",
  "cursor": "<opaque pagination token>",
  "compression": "gzip",
  "ms": 12
}
```

`cursor` is present only for `chunked` results served with cursor pagination
(§4.4). `compression` is present only when `result` is compressed (§4.4).

### 4.1 Statuses

| status   | When                                                            | Client action                          |
|----------|----------------------------------------------------------------|----------------------------------------|
| `ok`     | call succeeded; `result` holds the serialized outcome          | parse `result`, done                   |
| `error`  | tool raised; `error` holds a message                           | raise, done                            |
| `queued` | call accepted, not yet running; `job` holds a job id           | poll `<job>.job.<zone>`                |
| `running`| job in progress                                              | poll again (with fresh nonce)          |
| `chunked`| result is large; `session`+`chunk`+`total`+`more` describe it  | fetch chunks until `more=false`        |
| `done`   | long-running job finished; `session` holds the assembled result| fetch the session result               |

### 4.2 TXT size limit & chunking

A single TXT character-string is ≤255 bytes and a DNS message may carry several,
but resolvers inconsistently handle multi-string/multi-record TXT. To stay safe:

- If the envelope fits in **≤ 200 bytes**, return it directly in one TXT record.
- If it is larger **but complete**, return `chunked`:
  ```json
  {"v":1,"status":"chunked","session":"s1","chunk":0,"total":3,"more":true,
   "chunk":"<base64 of this chunk's bytes>"}
  ```
  The client fetches `<chunk>.<session>.chunk.<zone>` for `chunk = 1..total-1`,
  concatenating the `chunk` bytes. Final chunk has `more=false`.
- If the tool is **long-running**, return `queued` with a `job` id. The server
  runs the tool in the background and stores the outcome under a `session`. The
  client polls `<job>.job.<zone>` until it gets `done` (with a `session`), then
  fetches the assembled result as above.

### 4.3 Job polling

```
<job>.job.<zone>  ->  TXT  {"v":1,"status":"running","job":"j1"}
<job>.job.<zone>  ->  TXT  {"v":1,"status":"done","job":"j1","session":"s1"}
```

On `done`, fetch the result by the session-chunk protocol (§4.2) using `session`.

### 4.4 Compression & cursor pagination

Two optional refinements, both independent of the base protocol.

#### Compression

When a result is large, the `result` field may be a gzip-compressed, base64-
encoded blob instead of the plain serialized tool result:

```json
{"v":1,"status":"ok","tool":"big","result":"<base64 of gzip(payload)>",
 "compression":"gzip"}
```

The `compression` marker (`gzip` is the only value in this implementation; `zstd`
is reserved for a future standard-library-free build) tells the client to
decompress `result` before parsing it. Compression wraps the *inner* serialized
tool result, so the `kind`/`mime`/`value` structure inside is preserved. The
server applies it automatically when it would otherwise exceed the TXT size limit.

#### Cursor pagination

Fixed chunk indices (`chunk`/`total`) are the default. When the server enables
cursor pagination it tags the first `chunked` envelope with an opaque `cursor`
token:

```json
{"v":1,"status":"chunked","session":"s1","chunk":0,"total":3,"more":true,
 "chunk":"<base64>","cursor":"<opaque token>"}
```

The client then fetches subsequent chunks by presenting that cursor instead of
requesting a fixed index:

```
<cursor>.<session>.chunk.<zone>  ->  chunk N bytes + next cursor
```

Each response carries the next `cursor` (or omits it on the final chunk). The
token is unguessable and session-bound, so a cursor cannot be replayed against a
different session. If `cursor` is absent the client falls back to fixed-index
fetching (§4.2). The two modes are mutually exclusive per result; the server
chooses one.

---

## 5. Result serialization

- Structured tool results are returned as a **JSON string** in `result` (a string,
  not a nested object, so the envelope stays flat and size-predictable).
- Binary results are **base64**-encoded inside that JSON, with a marker:
  ```json
  {"kind":"json","value":{ ... }}      // structured
  {"kind":"base64","mime":"image/png","value":"...."}  // binary
  {"kind":"text","mime":"text/plain","value":"...."}
  ```

The client deserializes `result` according to `kind`.

---

## 6. Resolver caching & the nonce

Recursive resolvers cache TXT/A/SRV answers. If a call query were cacheable, a
stale or spoofed result could be returned to the agent. **Every call query is made
uncacheable** by embedding a fresh random `<nonce>` label, so the exact name is
never seen twice.

- **Nonce:** 8–16 lowercase-base32 chars (`[a-z2-7]`), cryptographically random.
- Included in the call name (§2.3) so the full name is unique per call.
- Also used for replay protection (§7).

Discovery (`_mcp._udp`) and schema queries are *not* nonced — they are safe to
cache and *should* be, for latency.

---

## 7. Auth & replay protection (optional)

Calls may be **signed** to authenticate the caller and protect against tampering
and replay.

### 7.1 Signature

`sig = HMAC_SHA256(secret, tool || "\x00" || argBytes || "\x00" || nonce || "\x00" || ts)`

- `secret` — shared key pre-provisioned on client and server.
- `ts` — Unix seconds (bounds the replay window).
- `sig` is base32-encoded (32 bytes → 53 chars, fits in one ≤63 label) and placed
  as the **leftmost** label of the call name (§2.3).

### 7.2 Replay protection

The server remembers every nonce whose call signature verified, and rejects a
nonce it has already seen. Replay protection keys on the **nonce alone**: the nonce
is covered by the signature, whereas the source address is not an identity (UDP
sources can be spoofed, and behind a recursive resolver every client shares the
resolver's address).

- A nonce is remembered for at least **2 × window**. Timestamps are accepted within
  ±window of the server clock, so a call signed at `now + window` stays valid until
  `now + 2 × window`.
- The set is bounded. When it is full of unexpired nonces the server refuses new
  calls rather than forgetting a live nonce, which would re-open it for replay.
- Forged or malformed calls never consume a nonce: the signature is checked first.

Nonces also defeat caching (§6) because every name is unique.

### 7.3 Auth model

- Shared-secret (HMAC) is the default — simple, no PKI, fits the DNS world.
- The secret can be distributed out-of-band or, for a first step, per-tool via an
  authenticated discovery extension (future work).

---

## 8. Transport details

- **Transport:** UDP (and TCP fallback for oversized messages, per RFC 1035 §4.2.1).
  Query messages stay small (args are chunked into labels), so UDP almost always
  suffices.
- **Port:** client → server on UDP/53 (or a custom port advertised in SRV). Using
  53 is what lets traffic traverse restrictive egress.
- **Message format:** standard DNS `QUERY` with `RD=1`, and `ANSWER` RRsets. No
  TSIG required (HMAC is applied at the application layer per §7), though TSIG can
  be layered on for transport integrity.
- **Over DoH (resolver path):** the same query names work over encrypted DNS,
  giving privacy + the same egress-friendly footprint. In a real deployment the
  client reaches the authoritative server through a normal resolver rather than
  opening a direct UDP/53 socket. Point the client at a DNS-over-HTTPS endpoint
  (RFC 8484) with `--doh`:

  ```bash
  go run ./cmd/mcp53-client --doh https://dns.example.com/dns-query \
    --zone example. --tool echo --args '{"text":"hi"}'
  ```

  `--doh` replaces `--server`: every query is sent to the DoH endpoint instead of
  a direct socket. This is the cleanest forwarding path — the resolver at the
  server host answers/forwards the `_mcp._udp.example.` query to the authoritative
  server, and the client receives an encrypted, egress-friendly response. The
  `--server` UDP/TCP address is still used when `--doh` is not set.

**Transport-layer integrity (TLS / TSIG).** The base protocol applies HMAC at the
application layer (§7). For defense in depth, the transport can additionally be
protected:

- **DNS-over-TLS (RFC 8483).** Serve over `tcp-tls` instead of UDP. The client
  switches to the `tcp-tls` net via `Client.WithTLS(&tls.Config{})` (or the
  `pkg/mcp` server's `WithTLS` + `ApplyTransport`); pair with
  `WithInsecureSkipVerify` for self-signed certificates. This gives
  confidentiality and server authentication.
- **TSIG (RFC 2845).** Sign every query with a shared HMAC-SHA256 secret. The
  server verifies each query's signature *before* any handler runs (an unsigned
  or wrong-secret query is rejected) and signs its responses with the same key, so
  the client can confirm the answer's origin and integrity. Configure the server
  with `Server.WithTSIG(name, secret)` (or `WithTSIGKeys` for multiple keys) and
  the client with `Client.WithTSIG(name, secret)`. TSIG complements — does not
  replace — the application HMAC of §7.

Both are optional and independent; either or both may be enabled. See `pkg/mcp`
`Server.WithTSIG`/`WithTLS`/`ApplyTransport` and `internal/dns` `Client.WithTSIG`
`/WithTLS`/`WithInsecureSkipVerify`.

---

## 9. Worked example

**Discovery.** Client queries SRV + TXT at `_mcp._udp.example.`:

```
_txt._mcp._udp.example.  SRV  0 0 53 dns.example.
_txt._mcp._udp.example.  TXT  "{\"version\":1,\"tools\":[\n  {\"name\":\"echo\",..."
```

**Call.** Client wants to call tool `echo` with `{"text":"hi"}`:

1. JSON: `{"text":"hi"}` → base32 `4XH233NPORRGY43J3BS3Q43NFZZSS43JN2` (illustrative).
2. Chunk into ≤63 labels, pick nonce `abcd1234`, sign → `sig=...`.
3. Query: `siglabel.xxxxxxxx.echo.call.abcd1234.example`.
4. Answer: `TXT "{\"v\":1,\"status\":\"ok\",\"tool\":\"echo\",\"result\":\"{\\\"ok\\\":true,\\\"value\\\":\\\"hi\\\"}\",\"ms\":1}"`.

**Large result.** Server returns `chunked` with `session=abc`, `chunk=0`, `total=2`, `more=true`.
Client fetches `0.abc.chunk.example`, then `1.abc.chunk.example`, concatenates.

**Long-running.** Server returns `queued`/`job=j1`. Client polls `j1.job.example`
until `done`/`session=s2`, then fetches the session result.

---

## 10. Open issues / future work

- **Secret distribution & identity.** Move beyond shared secret: per-tool keys,
  delegated discovery with auth (e.g. signed discovery documents).
- **Compression.** zstd/gzip inside `result` for very large payloads.
- **Pagination cursor** vs. fixed chunk indices for streaming results. Cursors are
  now implemented (see §4.4); fixed indices remain supported.

---

## 11. Repository layout

```
docs/            protocol & design docs
internal/codec/  base32 label encoding, chunking, envelopes
internal/dns/    DNS server (authoritative) + client (miekg/dns)
internal/proto/  discovery, call routing, job/session protocol
internal/auth/   HMAC signing, nonce, replay protection
pkg/mcp/         tool registry + MCP SDK adapter
cmd/             mcp53-server, mcp53-client binaries
```
