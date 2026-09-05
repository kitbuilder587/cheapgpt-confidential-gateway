# Contributing

Keep the gateway small enough to review. Use Go's standard cryptography and explicit types. New dependencies need a concrete reason.

Before submitting a change, run `make check fuzz audit`. For build or dependency changes, also run `make reproducible image`.

Use synthetic data in tests. Never add real tokens, prompts, account identifiers or deployment-specific routing details. Do not add request logging, body capture, persistent caches, arbitrary outbound URLs, a verification bypass or automatic fallback to plaintext transport.

Document changes to the protocol and the egress policy. Deployment and client policy must be reviewed together when the trust boundary changes.
