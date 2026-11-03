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
unsigned:  <arg-labels...>.<tool>.call.<nonce>.<zone>
signed:    <sig>.<arg-labels...>.<tool>.call.signed.<nonce>.<zone>
```

Reading **right-to-left**:

1. `<zone>` — the authoritative base domain (1+ labels).
2. `<nonce>` — a unique random 16-character label (see §6). Makes the name
   uncacheable.
3. literal `signed` — present only on signed calls; marks the leftmost label as the
   signature.
4. literal `call`.
5. `<tool>` — the tool name (single label).
6. `<arg-labels...>` — base32-encoded, chunked arguments, most-significant chunk
   leftmost. Zero or more labels.
7. `<sig>` — the 34-character HMAC signature label (see §7.1), signed calls only.

The server concatenates the arg labels left-to-right and base32-decodes them to
recover the argument bytes.

The whole name must fit the 255-byte DNS limit (RFC 1035 §2.3.4), which bounds the
argument size: on the zone `example.` a call can carry about 134 bytes of
arguments unsigned and 108 signed. The client checks the length before sending and
reports the limit for its zone.

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

Example: args `{"q":"hi"}` → 10 bytes → base32 `pmrhcir2ejugsit5` → one label.

Full call name:
`pmrhcir2ejugsit5.tool.call.<nonce>.example`

**Encoding alphabet & charset rule:** only `a–z` and `2–7` are emitted, guaranteeing
DNS-safety and avoiding case/`-`/`_` ambiguity.

---

## 4. Result envelope

Results are returned in a **TXT** record carrying a single JSON **envelope**. On
the wire the envelope JSON is **base64-encoded** and split into consecutive TXT
character-strings of at most 252 bytes (a multiple of 4, so each string decodes on
its own); the client decodes each string and concatenates the bytes. Base64 keeps
the payload in a character set every DNS library and resolver passes through
unchanged.

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

Every response must fit a 1232-byte EDNS0 UDP message (DNS Flag Day 2020), with
room for a question name of up to 255 bytes and a TSIG record. The envelope JSON is
base64-encoded on the wire and split across ≤255-byte TXT character-strings, so the
server bounds the marshaled envelope at **600 bytes** and result chunks at **240
bytes** of payload:

- If the marshaled envelope fits in **≤ 600 bytes**, return it directly.
- If it is larger **but complete**, return `chunked`. `result` carries this chunk's
  bytes, base64-encoded (`chunk` is omitted when it is 0):
  ```json
  {"v":1,"status":"chunked","tool":"big","session":"s1","total":3,"more":true,
   "result":"<base64 of chunk 0's bytes>"}
  ```
  The first chunk arrives with the call. The client fetches
  `<chunk>.<session>.chunk.<zone>` for `chunk = 1..total-1` and concatenates the
  decoded `result` bytes. The final chunk has `more=false`.
  Sessions are short-lived: the server keeps them for a bounded time (default
  5 minutes) and within bounded memory, dropping the oldest first. A chunk query
  for an expired or dropped session returns an `error` envelope; the client
  repeats the call.
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
tool result, so the `kind`/`mime`/`value` structure inside is preserved.

When enabled, the server compresses a result that does not fit one envelope
*before* chunking it, and keeps the compressed form only if it is smaller. If the
compressed result fits one envelope it is returned as `ok` as above; otherwise
the compressed bytes are chunked (§4.2) and the **first** `chunked` envelope
carries `"compression":"gzip"`. The client assembles the chunks, then
decompresses.

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

```
mac   = HMAC_SHA256(secret, tool || "\x00" || argBytes || "\x00" || nonce || "\x00" || ts)
label = base32( ts as 5-byte big-endian || mac[0:16] )
```

- `secret` — shared key pre-provisioned on client and server.
- `ts` — Unix seconds, written in decimal inside the MAC input. It bounds the
  replay window: the server accepts `|now - ts| <= window` (default 5 minutes).
- The label carries the timestamp, so the server verifies with **one** HMAC and
  rejects a stale timestamp before computing any. The MAC is truncated to 128 bits
  (RFC 2104 allows truncation to at least half the hash output).
- 21 bytes encode to a **34-character** label, placed as the **leftmost** label of
  the call name (§2.3).

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
  Secrets are distributed out-of-band.
- **Per-tool keys.** A server may hold a key per tool, falling back to a default
  key; the client signs each call with the key for the tool it calls. A key for one
  tool cannot authorize another.
- **Signed discovery.** A server with a default key signs its discovery document:
  `sig` in the document is the §7.1 label over the JSON document (with `sig`
  removed), tool `discovery`, an empty nonce and timestamp 0. A client holding the
  key rejects a document that is unsigned or does not verify.

---

## 8. Transport details

- **Transport:** UDP, with TCP on the same port for answers that do not fit
  (RFC 1035 §4.2.1, RFC 7766). The server answers a UDP query within the size the
  requester advertises in EDNS0 (RFC 6891), or 512 bytes without EDNS, and sets
  `TC=1` when it has to drop the answer; the requester retries over TCP. Clients
  advertise EDNS0 with a 1232-byte buffer (the DNS Flag Day 2020 default) and
  retry truncated answers over TCP automatically.
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

- **DNS-over-TLS (RFC 7858).** Serve over `tcp-tls` instead of UDP. The client
  switches to the `tcp-tls` net via `Client.WithTLS(&tls.Config{})` (or the
  `pkg/mcp` server's `WithTLS` + `ApplyTransport`); pair with
  `WithInsecureSkipVerify` for self-signed certificates. This gives
  confidentiality and server authentication.
- **TSIG (RFC 8945).** Sign every query with a shared HMAC-SHA256 secret. The
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
_mcp._udp.example.  SRV  0 0 53 dns.example.
_mcp._udp.example.  TXT  "<base64 of {\"version\":1,\"tools\":[{\"name\":\"echo\",...}]}>"
```

**Call.** Client wants to call tool `echo` with `{"text":"hi"}`:

1. JSON `{"text":"hi"}` (13 bytes) → base32 `pmrhizlyoqrduitinerh2`.
2. Pick a nonce, e.g. `k3v7q2m4x6z8a2b4`, and, for a signed call, compute the
   34-character signature label (§7.1).
3. Query (TXT):
   `<sig>.pmrhizlyoqrduitinerh2.echo.call.signed.k3v7q2m4x6z8a2b4.example.`
4. Answer: one TXT record whose strings base64-decode to
   `{"v":1,"status":"ok","tool":"echo","result":"{\"kind\":\"json\",\"value\":...}","ms":1}`.

**Large result.** The call is answered `chunked` with `session=abc`, `total=3`,
`more=true` and chunk 0 in `result`. The client fetches `1.abc.chunk.example.` and
`2.abc.chunk.example.` and concatenates the three chunks.

**Long-running.** Server returns `queued`/`job=j1`. Client polls `j1.job.example`
until `done`/`session=s2`, then fetches the session result.

---

## 10. Open issues / future work

- **Identity beyond shared secrets.** Per-tool keys and signed discovery (§7.3) are
  implemented; public-key signatures would remove the need to share secrets.
- **zstd.** Reserved as a compression kind (§4.4); only gzip is implemented.

---

## 11. Repository layout

```
docs/            protocol & design docs
internal/codec/  base32 label encoding, chunking, envelopes
internal/dns/    DNS server (authoritative) + client (miekg/dns)
internal/auth/   HMAC signing, per-tool keys, replay protection
internal/cli/    flag parsing shared by the binaries
pkg/mcp/         tool registry, MCP SDK adapter, result store, agent
cmd/             mcp53-server, mcp53-client binaries
```
