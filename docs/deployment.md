# Deploy to Phala Cloud

Target: one Intel TDX CVM with 2 vCPU / 4 GB RAM. This guide prepares a deployment; it does not contain live measurements or credentials. The project is not yet deployed to Phala.

## 1. Validate the source

```sh
make check fuzz audit reproducible
make image
docker run --rm confidential-gateway:local -policy-hash
```

The Dockerfile builds a static Linux binary with Go 1.26.8 and a pinned builder image. The runtime image contains only the binary and CA roots, runs as UID 65532 and has no shell. The supplied Phala Compose template uses a read-only root filesystem and binds only the dstack socket.

The image targets Linux AMD64 for Intel TDX. Local unit and integration tests can run on macOS or Linux without a TEE. Starting the production server without dstack must fail.

## 2. Publish an immutable image

Push the image to a registry accessible to your Phala deployment and obtain its repository digest. Keep registry access private while the repository is private. No workflow in this repository automatically publishes a container or deploys infrastructure.

```sh
export GATEWAY_IMAGE='your-registry.example/gateway@sha256:<actual-64-character-digest>'
python3 scripts/render-compose.py > deploy/compose.rendered.yaml
```

The renderer refuses mutable tags. It leaves the gateway token reference intact; it never reads or prints the token. Do not use a shell expansion tool that writes secret values into committed Compose files.

## 3. Create the CVM

Use the rendered Compose in Phala Cloud and supply `GATEWAY_AUTH_TOKEN` through Phala's encrypted secret mechanism. Generate at least 32 random bytes of token material. Keep the same service token only in the authorized CheapGPT routing service.

The CVM needs `/var/run/dstack.sock` with access for UID 65532. The current dstack socket is world-accessible inside the guest; confirm this for the selected OS release. Use a deployment with only this reviewed application. Do not grant unrelated containers access to its process memory or sockets.

Expose port 8080 through the Phala HTTPS endpoint. Content remains encrypted at the application layer through ingress. CheapGPT's outbound service-token connection must terminate through the reviewed Phala ingress path. Client verification does not rely on that ingress for content confidentiality.

Health probes:

- `/healthz`: process liveness.
- `/readyz`: a successful startup call to the local attestation agent. This is not an independently verified hardware verdict and is not a continuous collateral check.
- `/metrics`: requires the service token; restrict scraping to your operations network.

## 4. Establish client policy independently

Review the source, deterministic binary/image build, actual rendered app Compose, dstack OS and runtime configuration. The Compose must pin image digests and disable debugging or extra runtime services.

Using dstack/Phala's published verification procedure, establish approved boot measurements and the actual app Compose hash. The latter is the dstack app-compose document hash, not a hash of the Docker Compose YAML alone. Review environment and startup configuration as part of that process.

Fill `deploy/policy.example.json` with these values and distribute the reviewed policy to clients through your release process. The template intentionally cannot pass validation. Do not generate trust policy automatically from the first server response.

The current policy represents one approved deployment configuration. For multiple approved OS builds or replicas with differing measurements, select the appropriate reviewed policy explicitly; do not skip a comparison to make a quote pass.

## 5. Acceptance checks

- The SDK verifies a real quote and sends a small authorized upstream request.
- Modified boot/app policy, key, challenge or expired session is rejected.
- Requests, credentials, paths and responses never appear in ingress, container or CheapGPT logs as plaintext.
- A dropped connection cancels upstream work; a truncated encrypted response is rejected by the client.
- An upstream redirect is rejected; errors remain encrypted or generic.
- Local tokenization works offline, and provider usage receipts match an independently observed authorized test request. Unknown usage remains unavailable.
- Capacity and latency fit the expected traffic with enough headroom on 2 vCPU / 4 GB.

Do these checks before making claims of production readiness. Provider-specific protocol compatibility, OAuth/account refresh and the surrounding CheapGPT integration need their own acceptance tests.

## Updates and scaling

Every code, image or measured-configuration change requires a new review and client policy approval. Never fall back to an older unapproved build or plaintext path when verification fails.

Sessions are intentionally in memory and single use. A relay must reach the instance that issued its session; configure affinity at the CheapGPT edge. A replacement instance gets new keys. Failed requests require a new attested session, with retry decisions handled by CheapGPT and the client.

Graceful shutdown allows 20 seconds for active connections before force-closing them. Longer upstream calls may be interrupted during rolling replacement; clients must treat them as incomplete. Session capacity and service readiness should be considered before draining a replica.

At the planning price, one 2-vCPU instance with a 20-GB disk is approximately $90/month; two instances approximately double the compute/storage baseline. Model fees, extra bandwidth and tax are additional. Check [current Phala rates](https://phala.com/pricing) before provisioning.
