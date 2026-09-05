# Protocol and integration

Protocol identifier: `cgw/1`. JSON binary fields use standard base64. No unencrypted request field may contain a prompt, provider credential, route path or content-bearing error.

## HTTP surface

| Endpoint | Access | Result |
|---|---|---|
| `POST /v1/session` | Public, concurrency and capacity bounded | Fresh session key and TDX evidence |
| `POST /v1/relay` | Gateway bearer token | Encrypted NDJSON response frames |
| `GET /healthz` | Public | Process liveness |
| `GET /readyz` | Public | Startup attestation probe result |
| `GET /metrics` | Gateway bearer token | Aggregate counters without request labels |

The CheapGPT edge authenticates users, applies quotas and rate-limits session creation. A session endpoint exposed without an edge remains susceptible to availability attacks; it accepts at most two concurrent quotes and stores at most 256 sessions.

## Session proof

Request: `{"challenge":"<32 random bytes, base64>"}`.

The response contains `id`, `public_key`, `expires_at`, `policy_hash`, `quote`, and `event_log`. The quote binds the SHA-512 of the exact JSON encoding produced by `protocol.ReportData`: protocol version, session ID, public key, expiry, compiled egress policy hash and client challenge. The expiry is at most five minutes ahead. Sessions are consumed once and cannot migrate between replicas.

The server uses the frozen dstack `/GetQuote` RPC on the local Unix socket. This release deliberately targets bare-metal Intel TDX deployments such as Phala; it does not claim verification of GCP, AWS or AMD evidence. The RPC is retained by dstack's newer guest agent alongside its v1 API.

## Two request envelopes

The client encrypts `protocol.Payload` with HPKE to the verified session key. It contains a destination host, upstream-native JSON body and a fresh random 32-byte response secret. An optional `tokenize` operation replaces the upstream request.

CheapGPT encrypts `protocol.Route` separately to the same verified key. This contains the exact destination path, approved headers, the SHA-256 of the encrypted payload and an optional accounting receipt key. The route host must equal the host selected inside the client's encrypted payload. Routing metadata stays confidential without requiring provider operation names in the transport implementation.

Outer relay request:

```json
{
  "session_id": "<64 hex characters>",
  "payload": "<HPKE ciphertext, base64>",
  "route": "<HPKE ciphertext, base64>"
}
```

HPKE suite: DHKEM(X25519, HKDF-SHA256), HKDF-SHA256, AES-256-GCM. Domain-separated `info` values bind each envelope to the protocol, session and purpose. Go's standard HPKE serialization includes the encapsulated key in one-shot ciphertexts.

## Response stream

Each NDJSON line contains a `ciphertext` field. The TEE encrypts with the client's fresh response secret using AES-256-GCM. Nonces are a zero 32-bit prefix followed by a big-endian 64-bit sequence, starting at zero. Keys are used for exactly one response; sequence numbers cannot be reused. Associated data binds the protocol, session and encrypted payload hash.

Decrypted frame sequence:

1. `head`: upstream HTTP status and a normalized content type.
2. `data`: zero or more byte chunks, preserving the provider stream exactly.
3. `end`: authenticated total byte count. Alternatively, `error` terminates the stream unsuccessfully.

Errors after opening the client payload are encrypted and use fixed codes. Transport and provider error bodies never become public diagnostics. Before decryption succeeds, only fixed HTTP error codes are returned. EOF without a valid end frame is an error; a consumer must read through the terminal frame to verify completion. Already displayed streaming content cannot be withdrawn after a later failure.

## Accounting

`Session.PrepareRoute` generates an independent receipt secret for CheapGPT. When present, the terminal wire frame also contains `receipt`: an authenticated encrypted record of status, response bytes and available token counters. `Routing.OpenReceipt` verifies it once. The client stream remains opaque to CheapGPT.

Receipt authentication uses a separate random key and a distinct associated-data domain. The receipt is not a public signature or transferable billing proof. Only a completed response produces a receipt; on interruption, accounting must treat the request as incomplete and reconcile it separately.

The parser accepts known usage fields at the root or under `response` / `message`. It does not scan generated text for counters. JSON and SSE accounting records are capped at 1 MiB. Unknown or incomplete usage is explicitly unavailable. Cached token semantics differ by provider; pricing interpretation stays in CheapGPT.

## Go SDK roles

Client:

```go
client, err := sdk.New(gatewayURL, approvedPolicy)
if err != nil { return err }
defer client.Close()
session, err := client.Session(ctx)
if err != nil { return err }
prepared, err := session.Prepare(protocol.Payload{
    Host: "api.anthropic.com",
    Body: upstreamJSON,
})
if err != nil { return err }
```

The client sends `session.Proof()`, `prepared.Request.SessionID` and `.Payload` through CheapGPT, retains `prepared`, then calls `prepared.OpenResponse` on the returned encrypted stream. The end user's application never needs the upstream credential or the gateway service token.

The router must independently verify the same evidence with the original challenge before sending credentials. `sdk.VerifySession` reconstructs a verified session for this purpose; `Session.PrepareRoute` seals the route and creates its receipt reader. CheapGPT authenticates `/v1/relay`, relays each raw wire frame to the client and reads only the encrypted receipt using its own key. Request transport must preserve the session and ciphertext without JSON rewriting.

## Bounds

| Resource | Limit |
|---|---:|
| Session lifetime | 5 minutes |
| Stored sessions | 256 per process |
| Concurrent quotes | 2 |
| Concurrent relays | 32 |
| Upstream-native body | 2 MiB |
| Outer relay JSON | 4 MiB |
| Total response | 64 MiB |
| Response chunk | 32 KiB |
| Upstream request duration | 3 minutes |
| Outbound dial / TLS handshake | 10 seconds each |
| Upstream response headers | 45 seconds |
| Client write deadline | 15 seconds per frame |
| Local tokenizer input | 64 KiB, 2 concurrent calls |

Limits are compiled into the reviewed application. Local tokenizer counts apply to text only and do not substitute for provider usage on structured or multimodal requests.
