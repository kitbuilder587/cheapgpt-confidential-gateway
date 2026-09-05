# Trust model

## The boundary

The gateway protects request and response content from the CheapGPT application tier and from host operators, subject to Intel TDX, dstack, the measured application and the client verifier behaving correctly. It does not prove that no machine anywhere stores a request.

The selected upstream provider sees plaintext. OpenRouter may forward it to another provider; Vercel receives it for token counting. Provider storage, abuse monitoring and downstream routing are outside this attestation. A client explicitly commits to the recipient host before encryption.

The client application is trusted: it sees plaintext before encryption and after decryption. A web application served by an operator can be replaced by that operator. Users requiring independent verification should use a reviewed, pinned client build.

## What the client verifies

- Intel's signature chain, certificate validity, signed TCB collateral and revocation information using `google/go-tdx-guest`. Only Intel collateral hosts are contacted by the verifier.
- An approved `MRTD` and `RTMR0–2` for the expected boot environment. Debug TDX instances are rejected.
- Replayed RTMR3 events with verified digests. Exactly one approved `compose-hash` must precede exactly one `boot-mr-done` marker. Runtime event formats v1 and v2 are supported; unknown formats fail closed.
- A fresh client challenge bound to the session key, expiry, protocol and compiled egress policy hash. The key pair is generated in process memory for one session.

The approved Compose must refer to immutable image digests and must contain only reviewed services and mounts. A matching container tag, a Git commit printed by a server, an Info response or a green UI badge is not evidence that reviewed code is running.

There is no automatic trust-on-first-use, simulator acceptance or fallback verifier. Empty policy files, unavailable Intel collateral, stale sessions and measurement mismatches stop the client before encryption. The dstack socket response is evidence, not a trusted verdict.

## Content and routing isolation

Request content and route metadata use separate HPKE envelopes. Route metadata includes upstream credentials and is encrypted to the verified session key. The encrypted client payload binds the selected host. The encrypted route binds the payload ciphertext hash.

This limits disclosure to the chosen host; it does not let the client approve a hidden operation individually. The broad host policy for Kiro authorizes any allowed POST path on that exact host. That is a deliberate trust boundary: a client approving the host also accepts the router's choice of operation there.

The gateway is a byte-preserving relay for upstream-native request JSON. It does not run a closed-source plugin inside the TEE. Any future provider-specific content conversion must be included in a reviewed measured build, or performed on the trusted client. Ordinary CheapGPT services must not decrypt content to prepare it.

## Egress controls

Destinations and approved header names are compiled into the binary. URLs are canonicalized conservatively; alternate hosts, ports, userinfo, traversal, ambiguous escaping and unapproved query parameters are rejected. HTTP redirects are rejected rather than followed.

DNS results are validated, and the transport dials the validated IP directly while TLS still authenticates the original hostname. Loopback, private, link-local, shared, documentation and translation networks are denied. Environment HTTP proxies and cookies are not used. This release does not include account proxy support.

No arbitrary URL is fetched from a body or response. Remote media URLs, tool definitions and other fields are forwarded as supplied to the chosen provider; whether the provider dereferences or persists them is outside this gateway.

## Memory and diagnostics

The server does not write content, credentials or session keys to files, caches, logs or traces. It has no persistent request queue, database, debug endpoint or heap profile endpoint. Metrics expose only aggregate counts. Upstream error bodies remain in the encrypted response or are replaced by fixed encrypted errors.

Sessions expire after five minutes and are removed by request handling or a janitor running every 30 seconds. Successful consumption removes the session immediately. A process restart loses all session keys. The Compose template disables container logs, core dumps, swap allocation and writable root filesystems.

Go manages memory and uses immutable strings in places; clearing accessible byte buffers is best effort, not a proof of immediate physical erasure of every copy. Content necessarily exists in TEE memory during processing. Confidentiality after processing continues to depend on TEE isolation, the absence of memory-exporting code and the reviewed host/guest configuration.

## Availability and resource bounds

Operators can deny service, stop a VM or block Intel collateral. The gateway bounds sessions, concurrency, body sizes, stream sizes and deadlines. Client disconnects cancel upstream HTTP work. It does not retry automatically because generation and billing may not be idempotent.

The public session endpoint still needs CheapGPT edge authentication and rate limiting. These checks operate on metadata and encrypted bytes. The service token protects relaying and metrics; it is not the content-encryption key. Rate-limiting metadata must not be advertised as anonymous traffic.

## Supply chain and release status

The repository pins its Go dependencies, builder image and CI actions. `make reproducible` checks deterministic Linux binary output for the selected toolchain; this is not a proof that a deployed image matches source without the build and attestation review.

The Intel verifier dependency is pinned to a reviewed revision containing newer quote and context support beyond its last tagged release. dstack's wire contract was checked against revision `4fd93de0a1bb5da43cb6e422a30071dbe0be1229`. Neither pin replaces an independent audit.

Release gates still requiring a deployment:

1. Verify a real Phala quote with the client against independently established measurements.
2. Verify the actual deployment has no extra services, writable content storage or debug access.
3. Exercise authorized provider routes, streaming, cancellations and usage receipts with production-compatible credentials.
4. Measure capacity, memory, tokenization time and latency on the selected 2-vCPU instance.
5. Obtain independent review of the complete client, protocol, verifier, gateway and deployment.

References: [dstack security model](https://github.com/Dstack-TEE/dstack/blob/next/docs/security/security-model.md), [dstack verification](https://github.com/Dstack-TEE/dstack/blob/next/docs/verification.md), [Intel TDX verifier](https://github.com/google/go-tdx-guest), [HPKE RFC 9180](https://www.rfc-editor.org/rfc/rfc9180).
