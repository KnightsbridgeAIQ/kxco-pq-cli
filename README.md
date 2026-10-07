# kxco-pq-cli

**Post-quantum key management from a terminal: deterministic ML-DSA-87 and ML-DSA-65 keys, signed rotation and verifiable attestations, with no code to write.**

[![npm](https://img.shields.io/npm/v/kxco-pq-cli?label=npm&color=b0964f)](https://www.npmjs.com/package/kxco-pq-cli)
[![downloads](https://img.shields.io/npm/dm/kxco-pq-cli?label=downloads&color=b0964f)](https://www.npmjs.com/package/kxco-pq-cli)
[![NIST ACVP](https://img.shields.io/badge/NIST_ACVP-1,793_passed,_0_failed-2ea44f)](https://github.com/KnightsbridgeAIQ/kxco-post-quantum/blob/main/CONFORMANCE.md)
[![npm provenance](https://img.shields.io/badge/npm-provenance-2ea44f)](https://www.npmjs.com/package/kxco-pq-cli)
[![Socket](https://socket.dev/api/badge/npm/package/kxco-pq-cli)](https://socket.dev/npm/package/kxco-pq-cli)
[![license](https://img.shields.io/badge/license-Apache--2.0-blue)](./LICENSE)
[![node](https://img.shields.io/node/v/kxco-pq-cli.svg)](https://nodejs.org)

CLI for KXCO post-quantum institution key management. Generates ML-DSA-87 and ML-DSA-65 keypairs, rotates institution keys with optional on-chain anchoring, signs files and verifies signatures, all without writing any code.

- **Keys you can always recover.** A keypair derives from a 32-byte master and an info label through HKDF, so the same inputs always give the same kid. A key regenerates on a clean machine without a backup of the key itself.
- **Rotation in one command.** `rotate` derives the new key, signs a rotation manifest with the outgoing key so existing receivers can verify the handoff, and writes the updated well-known document. Add `--relay` and it anchors the rotation on chain and prints the transaction hash and block number.
- **Air-gapped by default.** `keygen`, `fingerprint`, `attest sign` and `attest verify` run offline, and nothing leaves the machine unless you pass `--relay`.
- **Secrets stay out of shell history.** Every hex flag reads `@path` from a file, and a secret typed on the command line is flagged with a warning that says why.
- **Standard formats.** Rotation manifests are RFC 8785 JCS-canonical, and attestations are `kxco-pq-attest` version 2 envelopes any counterparty can verify.
- **Proven underneath.** 1,793 NIST ACVP vectors passed, 0 failed, and 225 interoperability checks against liboqs, Bouncy Castle and the Python reference implementations, 0 failed, in [`kxco-post-quantum`](https://github.com/KnightsbridgeAIQ/kxco-post-quantum/blob/main/CONFORMANCE.md).
- **A supply chain you can check.** SLSA provenance and a CycloneDX SBOM on every release since 1.2.5, and every GitHub Action pinned by commit SHA.

**The migration has dates.**

- **NIST** published [FIPS 203](https://csrc.nist.gov/pubs/fips/203/final), [FIPS 204](https://csrc.nist.gov/pubs/fips/204/final) and [FIPS 205](https://csrc.nist.gov/pubs/fips/205/final) in August 2024.
- **United States:** [Executive Order 14412](https://www.federalregister.gov/documents/2026/06/25/2026-12909/securing-the-nation-against-advanced-cryptographic-attacks), signed on 22 June 2026, moves federal high-value and high-impact systems to post-quantum key establishment by 31 December 2030 and to post-quantum signatures by 31 December 2031. [OMB M-26-15](https://www.whitehouse.gov/wp-content/uploads/2026/06/M-26-15-Execution-of-the-Migration-to-Post-Quantum-Cryptography.pdf) requires PQC-agile libraries for all new applications.
- **United Kingdom:** the [NCSC](https://www.ncsc.gov.uk/guidance/pqc-migration-timelines) sets 2028, 2031 and 2035 as its migration milestones.

[Quick start](#quick-start) · [Commands](#commands) · [For institutions](#for-institutions) · [Assessment notes](./ASSESSMENT.md) · [Changelog](./CHANGELOG.md) · [kxco.ai](https://kxco.ai)

## When to use this

- Institutions managing their post-quantum identity from the command line
- DevOps and infra teams who need key rotation without writing Node.js
- Scripting identity operations in CI/CD pipelines

To do the same from your own application code, use [`kxco-post-quantum`](https://www.npmjs.com/package/kxco-post-quantum), or [`kxco-post-quantum-webhook`](https://www.npmjs.com/package/kxco-post-quantum-webhook) for webhooks.

## Install

```bash
npm install -g kxco-pq-cli
kxco-pq --help
```

You also need `kxco-post-quantum` available as a peer dependency:

```bash
npm install -g kxco-post-quantum
```

## Quick start

From a fresh install to a verified attestation, with `payload.json` standing for
any file you want to sign:

```bash
node -e "require('node:fs').writeFileSync('master.hex', require('node:crypto').randomBytes(32).toString('hex'))"
kxco-pq keygen --master @./master.hex --info 'my-institution-v1' --out-dir ./keys
kxco-pq attest sign --secret-key @./keys/secret-key.hex --public-key @./keys/public-key.hex --file payload.json --out payload.attestation.json
kxco-pq attest verify --public-key @./keys/public-key.hex --attestation payload.attestation.json
```

```
kxco-pq attest verify: VALID
  signer kid:  9067c1cfad2573df
  issued at:   2026-09-29T12:19:02.269Z
  payload:     28 bytes
```

`master.hex` regenerates every key derived from it, so it belongs in your
secrets manager.

## For institutions

The cryptography is free under Apache-2.0, works offline and needs nothing from
KXCO, now or in ten years. What KXCO sells is the part that has to be operated:
an answer about the present.

| Service | What you get |
|---|---|
| Hosted key registry | Whether a key is active, revoked or rotated, answered at verification time |
| Meta-transaction relay | KXCO validates your signed intent, pays the gas and submits it, so you never hold a token or run a node |
| On-chain anchoring | A timestamp on Armature L1 that the chain itself has verified |
| Live revocation | `anchored+live` verification, which confirms the signing key is still trusted now |
| Support and SLA | Availability commitments, an escalation path and a named contact |

Priced in USD, per seat, per year. No tokens, no nodes and no wallets. The line
between free and paid is set out in
[LICENCE-PRODUCT.md](https://github.com/KnightsbridgeAIQ/kxco-post-quantum/blob/main/LICENCE-PRODUCT.md).

**Talk to us: [admin@kxco.ai](mailto:admin@kxco.ai)** · [kxco.ai](https://kxco.ai)

## Commands

### `kxco-pq keygen`

Generate a deterministic ML-DSA-87 keypair from a 32-byte master secret and an info label. Writes hex files to `--out-dir`.

```bash
kxco-pq keygen \
  --master @./master.hex \
  --info   'my-institution-v1' \
  --out-dir ./keys
```

Every flag that takes hex accepts `@path` and reads the value from the file. Use
it for anything secret: a value typed on the command line is recorded in your
shell history and is readable from the process table by every other user on the
machine for as long as the command runs. Pass a secret literally and the tool
says so:

```
KxcoSecretOnCommandLine: master was given on the command line. It is now in your
shell history and was readable from the process table while this ran. Pass
--master @/path/to/file instead.
```

Outputs:
- `keys/secret-key.hex`: 4896-byte ML-DSA-87 secret key, hex-encoded. Store in a secrets manager, `chmod 600`. Never commit.
- `keys/public-key.hex`: 2592-byte ML-DSA-87 public key, hex-encoded.
- `keys/kid.txt`: 16-character hex fingerprint. This is what receivers pin.

The keypair is deterministic: same `--master` + same `--info` always produces the same kid. Restore from master; never lose a key.

ML-DSA-87 is the default from 2.3.0. `--algorithm ml-dsa-65` derives an ML-DSA-65 keypair instead (4032-byte secret key, 1952-byte public key), as `keygen` did by default before 2.3.0. Key files already on disk keep working with every command, because a key's length decides its set.

### `kxco-pq fingerprint`

Compute the kid for a public key without spinning up any application code.

```bash
kxco-pq fingerprint @./keys/public-key.hex
```

Accepts a hex string directly or a `@file` reference, for an ML-DSA-87 (2592-byte) or ML-DSA-65 (1952-byte) public key. Prints the 16-char hex kid.

### `kxco-pq rotate`

Rotate to a new keypair. Derives the new keypair, builds a signed rotation manifest (signed by the outgoing key so existing receivers can verify the handoff), and produces an updated `.well-known/kxco-pq-pubkey` document.

```bash
kxco-pq rotate \
  --old-secret @./keys/secret-key.hex \
  --old-kid    "$(cat keys/kid.txt)" \
  --new-master @./new-master.hex \
  --info       'my-institution-v2' \
  --issuer     'example.com' \
  --out-dir    ./rotated-keys
```

`--old-kid` is the kid of the outgoing key, as written to `keys/kid.txt`, and
`new-master.hex` is a fresh 32-byte master made the same way as the first.
`--issuer` is the domain that publishes your keys.

The outgoing key's secret decides its parameter set (4896 bytes ML-DSA-87, 4032
bytes ML-DSA-65), and the manifest's `signature.alg`, which is inside the signed
bytes, names it. The new key keeps the same set unless `--algorithm ml-dsa-87`
or `--algorithm ml-dsa-65` names one, so `--algorithm ml-dsa-87` on an ML-DSA-65
key rotates to ML-DSA-87 with the handoff still signed by the old key. The
well-known document's `algorithm` names the new key's set; where a rotation
changes it, the retiring key's entry carries its own `algorithm`. A manifest is
checked under the set its key belongs to, and one whose `signature.alg` names
the other set is refused.

Outputs (in `--out-dir`):
- `secret-key.hex`, `public-key.hex`, `kid.txt`: the new keypair
- `manifest.json`: RFC 8785 JCS-canonical rotation manifest, signed by the old kid
- `well-known.json`: ready to publish at `https://<issuer>/.well-known/kxco-pq-pubkey`

After running:
1. Publish `well-known.json` at the well-known URL.
2. Publish `manifest.json` at `https://<issuer>/.well-known/kxco-pq-rotation/<new-kid>.json`.
3. Tell receivers to add the new kid to their `pinnedKids[]` alongside the old one.
4. After the drain window, retire the old kid and discard its secret key.

### `kxco-pq attest sign`

Sign any file and emit a self-contained JSON attestation envelope. The secret key decides the set: ML-DSA-87 for a key `keygen` makes by default, and ML-DSA-65 for an ML-DSA-65 key.

```bash
kxco-pq attest sign \
  --secret-key @./keys/secret-key.hex \
  --public-key @./keys/public-key.hex \
  --file       payload.json \
  --out        payload.attestation.json
```

The output is a `kxco-pq-attest` version 2 envelope: `kxco-attest` (the format version), `payload` (base64url), `alg` (`ML-DSA-87` or `ML-DSA-65`), `kid`, `sig` (base64url, in the set `alg` names), `issuedAt` and `verifyModeHint`. Any counterparty can verify it without trust delegation.

### `kxco-pq attest verify`

Verify an attestation envelope against a known public key.

```bash
kxco-pq attest verify \
  --public-key  @./keys/public-key.hex \
  --attestation payload.attestation.json
```

Prints `VALID` with the signer kid, issue time and payload size, or `INVALID` with a reason and exit code 1. It reads version 1 and version 2 envelopes, so every envelope this CLI has produced keeps verifying.

## Key rotation on-chain

Pass `--relay` and `--identity-file` to anchor the rotation to the KXCO chain in
the same operation. Install [`kxco-pq-chain`](https://www.npmjs.com/package/kxco-pq-chain)
alongside the CLI, and set `KXCO_LICENCE_KEY` to your licence for the hosted
relay:

```bash
npm install -g kxco-pq-chain
```

```bash
kxco-pq rotate \
  --old-secret    @./keys/secret-key.hex \
  --old-kid       "$(cat keys/kid.txt)" \
  --new-master    @./new-master.hex \
  --info          'my-institution-v2' \
  --issuer        'example.com' \
  --out-dir       ./rotated-keys \
  --relay         https://relay.kxco.ai \
  --identity-file ./identity.json
```

`--identity-file` must be a JSON file containing `{ "kid": "<hex>", "secretKey": "<hex>" }`: the institution identity used to sign the chain transaction. On success the command prints the transaction hash and block number alongside the standard rotation output.

## The KXCO post-quantum family

An operator's tool: keys, rotation, signing and verification from a terminal,
with no application code. It handles keys and signatures only, which is what
makes it safe to run on an operator's machine. The rest of the family covers
the jobs around it:

| You need to | Install |
|---|---|
| Put the whole stack in one install | [`kxco-pq`](https://www.npmjs.com/package/kxco-pq) |
| Use ML-DSA, ML-KEM and SLH-DSA directly | [`kxco-post-quantum`](https://www.npmjs.com/package/kxco-post-quantum) |
| Keep signing keys on the HSM you already run | [`kxco-pq-hsm`](https://www.npmjs.com/package/kxco-pq-hsm) |
| Sign a document or record anyone can verify offline | [`kxco-pq-attest`](https://www.npmjs.com/package/kxco-pq-attest) |
| Keep a tamper-evident audit trail | [`kxco-pq-audit`](https://www.npmjs.com/package/kxco-pq-audit) |
| Verify a signature in a browser, with no server | [`kxco-verify`](https://www.npmjs.com/package/kxco-verify) |
| Issue institution identity credentials | [`kxco-pq-sdk`](https://www.npmjs.com/package/kxco-pq-sdk) |
| Encrypt files and payloads to one or many recipients | [`kxco-pq-vault`](https://www.npmjs.com/package/kxco-pq-vault) |
| Encrypt Node streams and WebSockets | [`kxco-pq-tls`](https://www.npmjs.com/package/kxco-pq-tls) |
| Sign and verify webhooks | [`kxco-post-quantum-webhook`](https://www.npmjs.com/package/kxco-post-quantum-webhook) |
| Give an AI agent an identity a verified institution sponsors | [`kxco-pq-agent`](https://www.npmjs.com/package/kxco-pq-agent) |
| Have Armature L1 verify a signature in consensus | [`kxco-pq-chain`](https://www.npmjs.com/package/kxco-pq-chain) |
| Prove an envelope at three levels, offline to on-chain | [`kxco-pq-network`](https://www.npmjs.com/package/kxco-pq-network) |
| Generate and rotate keys from a terminal | [`kxco-pq-cli`](https://www.npmjs.com/package/kxco-pq-cli) |
| Find quantum-vulnerable cryptography in a dependency tree | [`kxco-pq-scan`](https://www.npmjs.com/package/kxco-pq-scan) |
| Fail the build when code reaches past the wrapper | [`eslint-plugin-kxco-pq`](https://www.npmjs.com/package/eslint-plugin-kxco-pq) |

## Release integrity

Every release since 1.2.5 carries a SLSA provenance attestation tying the published tarball to
the commit and workflow that built it: verify with `npm audit signatures`, or read
it from `registry.npmjs.org/-/npm/v1/attestations/kxco-pq-cli@<version>`. A CycloneDX
SBOM is published, from v1.2.5, as a GitHub Release asset at
`releases/download/v<version>/sbom.cyclonedx.json`, a permanent unauthenticated
URL. Sibling `kxco-*` packages sit on caret ranges so a correctness fix in the
base package reaches you on the next install, with no release of every package
above it.

## Security

**ML-DSA-87** and **ML-DSA-65** (NIST FIPS 204) via [`kxco-post-quantum`](https://www.npmjs.com/package/kxco-post-quantum), running on the OpenSSL 3.5 primitives where the runtime provides them. No custom cryptography. Private key bytes are never echoed to stdout.

Evidenced, and reproducible on your own machine:

- **1,793 NIST ACVP vectors passed, 0 failed** across FIPS 203, 204 and 205, pinned by digest, per [CONFORMANCE.md](https://github.com/KnightsbridgeAIQ/kxco-post-quantum/blob/main/CONFORMANCE.md). The other 310 are pairings the library refuses as weaker than the parameter set
- **225 interoperability checks passed, 0 failed**, against OpenSSL 3.5, liboqs, Bouncy Castle and dilithium-py/kyber-py, in both directions
- **SLSA provenance** on every release since 1.2.5: verify with `npm audit signatures`
- **CycloneDX SBOM** published with every release since 1.2.5
- `npm run evidence` regenerates this package's evidence bundle from source

Dependency audit history is recorded in [AUDIT.md](https://github.com/KnightsbridgeAIQ/kxco-post-quantum/blob/main/AUDIT.md).

To report a vulnerability, open a [private security advisory](https://github.com/KnightsbridgeAIQ/kxco-pq-cli/security/advisories/new) or email **security@kxco.ai**.

## License

Apache-2.0 © 2026 Knightsbridge Financial Ltd, trading as KXCO. See [LICENSE](./LICENSE) and [NOTICE](./NOTICE).

## Maintainers

Shayne Heffernan and John Heffernan, [KXCO by Knightsbridge](https://kxco.ai)

[Knightsbridge Law](https://knightsbridgelaw.com) · [target150.com](https://target150.com) · [livetradingnews.com](https://livetradingnews.com)
