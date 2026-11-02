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
2. **DNS-safe encoding.** Every label uses the lowercase base32 alphabet (`a–v`),
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
2. `b32 = base32_no_pad(json_bytes)` (alphabet `a–v`).
3. Split `b32` into consecutive substrings of ≤63 chars. Each becomes one DNS
   label, most-significant first.

Example: args `{"q":"hi"}` → JSON `{"q":"hi"}` → 13 bytes → base32
`NBSWY3DPF3SXV53TN2TXQ53J` → labels `nbswy3dpf3sxv53tn2txq53j`.

Full call name:
`nbswy3dpf3sxv53tn2txq53j.tool.call.<nonce>.example`

**Encoding alphabet & charset rule:** only `a–v0-2` are emitted, guaranteeing
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
  "ms": 12
}
```

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

- **Nonce:** 8–16 lowercase-base32 chars (`[a-v0-2]`), cryptographically random.
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

The server keeps a short-lived set of used `(caller, nonce)` pairs (TTL ~5 min,
LRU-bounded). A reused nonce is rejected. Combined with the timestamp window, this
prevents replay. Nonces also defeat caching (§6) because every name is unique.

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
- **Over DoH/DoT/DoQ:** the same query names work over encrypted DNS, giving
  privacy + the same egress-friendly footprint.

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
- **Forwarding/resolver path.** Document how to reach the authoritative server
  through a normal resolver (DNS-over-HTTPS to the server host is the cleanest).
- **Compression.** zstd/gzip inside `result` for very large payloads.
- **Pagination cursor** vs. fixed chunk indices for streaming results.
- **TLS/TSIG** for transport-layer integrity as a complement to application HMAC.

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
