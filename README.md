# kxco-pq-cli

[![npm](https://img.shields.io/npm/v/kxco-pq-cli?label=npm&color=b0964f)](https://www.npmjs.com/package/kxco-pq-cli)
[![Socket](https://socket.dev/api/badge/npm/package/kxco-pq-cli)](https://socket.dev/npm/package/kxco-pq-cli)
[![license](https://img.shields.io/badge/license-Apache--2.0-blue)](./LICENSE)
[![node](https://img.shields.io/node/v/kxco-pq-cli.svg)](https://nodejs.org)

CLI for KXCO post-quantum institution key management. Generates ML-DSA-65 keypairs, rotates institution keys with optional on-chain anchoring, signs files, and verifies signatures — without writing any code.

## Release integrity

Every release of this package is checkable without asking us for anything.

- **Provenance.** Each release carries a SLSA provenance attestation tying the
  published tarball to the commit and workflow that built it. Verify with
  `npm audit signatures`, or read it directly from
  `registry.npmjs.org/-/npm/v1/attestations/kxco-pq-cli@<version>`.
- **Bill of materials.** A CycloneDX SBOM is published as a GitHub Release asset
  at `releases/download/v<version>/sbom.cyclonedx.json`, a permanent
  unauthenticated URL. Not an expiring build artifact.
- **Pinned where it matters.** Third-party dependencies are pinned to exact
  versions, never ranges, so the code that performs the cryptography cannot
  change without a release. Sibling `kxco-*` packages sit on caret ranges
  deliberately: it means a correctness fix in the base package reaches you
  without a release of every package above it. That is not theoretical. When
  `@noble/post-quantum` 0.7.1 was found to fail NIST SLH-DSA verification
  vectors, the revert in the base package propagated here on the next install.
  Every GitHub Action is pinned by 40-character commit SHA.
- **Conformance underneath.** The cryptography comes from
  [`kxco-post-quantum`](https://www.npmjs.com/package/kxco-post-quantum), which
  is run against **2,103 NIST ACVP vectors (0 failed)** and a **225-check
  cross-implementation interoperability matrix** against liboqs, Bouncy Castle
  and two pure-Python implementations, in both directions and with negative
  controls. Its published tarball also rebuilds bit-for-bit from its own tag,
  verified in CI on every run.

## When to use this

- Institutions managing their post-quantum identity from the command line
- DevOps and infra teams who need key rotation without writing Node.js
- Scripting identity operations in CI/CD pipelines

If you need to do any of this programmatically in your own application, use [`kxco-post-quantum`](https://www.npmjs.com/package/kxco-post-quantum) or [`kxco-post-quantum-webhook`](https://www.npmjs.com/package/kxco-post-quantum-webhook) instead.

## Install

```bash
npm install -g kxco-pq-cli
kxco-pq --help
```

You also need `kxco-post-quantum` available as a peer dependency:

```bash
npm install -g kxco-post-quantum
```

## Commands

### `kxco-pq keygen`

Generate a deterministic ML-DSA-65 keypair from a 32-byte master secret and an info label. Writes hex files to `--out-dir`.

```bash
kxco-pq keygen \
  --master 'ab83...64 hex chars...e7' \
  --info   'my-institution-v1' \
  --out-dir ./keys
```

Outputs:
- `keys/secret-key.hex` — 4032-byte secret key, hex-encoded. Store in a secrets manager, `chmod 600`. Never commit.
- `keys/public-key.hex` — 1952-byte public key, hex-encoded.
- `keys/kid.txt` — 16-character hex fingerprint. This is what receivers pin.

The keypair is deterministic: same `--master` + same `--info` always produces the same kid. Restore from master; never lose a key.

---

### `kxco-pq fingerprint`

Compute the kid for a public key without spinning up any application code.

```bash
kxco-pq fingerprint @./keys/public-key.hex
```

Accepts a hex string directly or a `@file` reference. Prints the 16-char hex kid.

---

### `kxco-pq rotate`

Rotate to a new keypair. Derives the new keypair, builds a signed rotation manifest (signed by the outgoing key so existing receivers can verify the handoff), and produces an updated `.well-known/kxco-pq-pubkey` document.

```bash
kxco-pq rotate \
  --old-secret @./current-keys/secret-key.hex \
  --old-kid    a1b2c3d4e5f60718 \
  --new-master '<32-byte master for the new key, hex>' \
  --info       'my-institution-v2' \
  --issuer     'chain.kxco.ai' \
  --out-dir    ./rotated-keys
```

Outputs (in `--out-dir`):
- `secret-key.hex`, `public-key.hex`, `kid.txt` — new keypair
- `manifest.json` — RFC 8785 JCS-canonical rotation manifest, signed by the old kid
- `well-known.json` — ready to publish at `https://<issuer>/.well-known/kxco-pq-pubkey`

After running:
1. Publish `well-known.json` at the well-known URL.
2. Publish `manifest.json` at `https://<issuer>/.well-known/kxco-pq-rotation/<new-kid>.json`.
3. Tell receivers to add the new kid to their `pinnedKids[]` alongside the old one.
4. After the drain window, retire the old kid and discard its secret key.

---

### `kxco-pq attest sign`

Sign any file with ML-DSA-65 and emit a self-contained JSON attestation envelope.

```bash
kxco-pq attest sign \
  --secret-key @./keys/secret-key.hex \
  --public-key @./keys/public-key.hex \
  --file       payload.json \
  --out        payload.attestation.json
```

The envelope contains `algorithm`, `signerKid`, `issuedAt`, `payload` (base64url), and `signature` (base64url ML-DSA-65). Any counterparty can verify it without trust delegation.

---

### `kxco-pq attest verify`

Verify an attestation envelope against a known public key.

```bash
kxco-pq attest verify \
  --public-key  @./keys/public-key.hex \
  --attestation payload.attestation.json
```

Prints `VALID` with signer kid, issue timestamp, and payload size — or `INVALID` with a reason and exits 1.

---

## Key rotation on-chain

Pass `--relay` and `--identity-file` to anchor the rotation to the KXCO chain in the same operation:

```bash
kxco-pq rotate \
  --old-secret    @./current-keys/secret-key.hex \
  --old-kid       a1b2c3d4e5f60718 \
  --new-master    '<new master hex>' \
  --info          'my-institution-v2' \
  --issuer        'chain.kxco.ai' \
  --out-dir       ./rotated-keys \
  --relay         https://relay.kxco.ai \
  --identity-file ./identity.json
```

`--identity-file` must be a JSON file containing `{ "kid": "<hex>", "secretKey": "<hex>" }` — the institution identity used to sign the chain transaction. On success the command prints the transaction hash and block number alongside the standard rotation output.

## Where this fits

An operator's tool: keys, rotation, signing and verification from a terminal,
with no application code.

**It holds no assets.** Keys and signatures only, which is why it is safe to run
on an operator's machine.

- [`kxco-pq-sdk`](https://www.npmjs.com/package/kxco-pq-sdk) to issue and verify user credentials programmatically
- [`kxco-pq-hsm`](https://www.npmjs.com/package/kxco-pq-hsm) to keep the key behind a hardware boundary

## Part of the KXCO stack

| Package | Purpose |
|---------|---------|
| [`kxco-post-quantum`](https://www.npmjs.com/package/kxco-post-quantum) | Core ML-DSA-65 primitives (keygen, sign, verify, fingerprint) |
| [`kxco-post-quantum-webhook`](https://www.npmjs.com/package/kxco-post-quantum-webhook) | Runtime webhook signing and verification for Node.js frameworks |
| `kxco-pq-cli` | Operator CLI — keygen, rotation, attestation; no application code required |

All cryptographic operations delegate to `kxco-post-quantum`, which wraps [`@noble/post-quantum`](https://github.com/paulmillr/noble-post-quantum). Private key bytes are never echoed to stdout.

All cryptographic operations delegate to [`kxco-post-quantum`](https://www.npmjs.com/package/kxco-post-quantum), which is held to published evidence rather than assertion: **2,103 NIST ACVP vectors across FIPS 203, 204 and 205 and 225 cross-implementation interop checks against OpenSSL 3.5, liboqs, Bouncy Castle and two Python implementations, 0 failed**, every dependency pinned to an exact version, with SLSA provenance and a published SBOM on every release. The full dependency provenance, including the audit history of every upstream library, is recorded in [`AUDIT.md`](https://github.com/KnightsbridgeAIQ/kxco-post-quantum/blob/main/AUDIT.md).

To report a vulnerability, open a [private security advisory](https://github.com/KnightsbridgeAIQ/kxco-pq-cli/security/advisories/new) or email **security@kxco.ai**.

## License

Apache 2.0. See [LICENSE](./LICENSE).

## Maintainers

Shayne Heffernan and John Heffernan — [KXCO by Knightsbridge](https://kxco.ai)

[Knightsbridge Law](https://knightsbridge.law) · [target150.com](https://target150.com) · [livetradingnews.com](https://livetradingnews.com)
