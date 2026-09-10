# Assessment notes

The answers a buyer's readiness assessment asks for: what this package does,
how it moves when algorithms move, and what it takes to run it.

Algorithm conformance belongs to
[`kxco-post-quantum`](https://www.npmjs.com/package/kxco-post-quantum), which
runs 2,103 NIST ACVP vectors and a cross-implementation interoperability matrix
and publishes the lot. Cited here, proven there.

## What this package is

`kxco-pq`: post-quantum key management from a terminal. Generate keys,
fingerprint them, sign and verify attestations, rotate a key with an optional
on-chain anchor.

**Keys are deterministic, which makes them recoverable.** A keypair is derived
from `(master, info)` through HKDF, so the same inputs always produce the same
kid. A key is never lost while the master survives, and it can be regenerated on
a clean machine without restoring a backup of the key itself. That turns key
custody into master-secret custody, which is one secret to protect properly
instead of many.

**Secrets stay off the command line.** Every hex flag accepts `@path` and reads
the value from a file. Pass a secret literally and the tool tells you why not
to:

```
KxcoSecretOnCommandLine: master was given on the command line. It is now in your
shell history and was readable from the process table while this ran. Pass
--master @/path/to/file instead.
```

An argument is recorded in shell history and readable from the process table by
every other user on the machine while the command runs. The safe form is the
documented one, and the unsafe one is not silent.

**Rotation is a first-class operation, not a runbook.** `rotate` derives the new
keypair, writes the new files and, with `--relay` and `--identity-file`, anchors
the rotation on chain in the same command, printing the transaction hash and
block number. Key rotation is where identity systems usually leak procedure into
a wiki; here it is one command with a receipt.

**Offline unless asked otherwise.** Without `--relay` nothing leaves the
machine. `keygen`, `fingerprint`, `attest sign` and `attest verify` all run
air-gapped.

## Scope

This package handles key material as files, which is what a command-line tool
for key management has to do, and it is explicit about the consequences: the
README says `chmod 600` and store the master in a secrets manager, and the tool
warns when a secret would land in shell history.

The master is the asset. Everything derived from it can be regenerated, so
protecting one secret well protects all of them. That is the trade deterministic
derivation makes, and it is the right one for an institution that already has a
secrets manager.

Envelope format belongs to
[`kxco-pq-attest`](https://www.npmjs.com/package/kxco-pq-attest); on-chain
operations to [`kxco-pq-chain`](https://www.npmjs.com/package/kxco-pq-chain).

## Agility

**Inherited.** Primitives belong to `kxco-post-quantum`; envelope format to
`kxco-pq-attest`.

**`info` is a rotation mechanism the operator controls.** `my-institution-v1` to
`my-institution-v2` derives a different keypair from the same master, so a
routine rotation needs no new secret and no new backup, only a new label. The
`rotate` command exists to make that a single auditable step.

## Running it

**Release integrity.** Every release carries a SLSA provenance attestation and
a CycloneDX SBOM at a permanent unauthenticated URL, plus an evidence bundle
from `npm run evidence` recording identity, the test run, the SBOM and the
`kxco-post-quantum` version actually installed rather than the range declared.

**Supported versions.** One line moving forward. Fixes land in the next release.
A CLI is often installed globally rather than pinned in a project lockfile, so
`kxco-pq --version` is worth recording alongside anything it produced.

**Cost.** No hardware or runtime ceiling. `keygen` is one derivation and
`rotate` one signature.

**Connection.** Only with `--relay`: `relay.kxco.ai`, which negotiates the
hybrid key exchange group `X25519MLKEM768` under TLS 1.3, measured 7 September
2026 with OpenSSL 3.5.6. The rotation intent is signed before it is sent and
verified on chain after it arrives.

## Correcting this document

Every claim here is checkable against `src/` and the README. If one does not
match, that is a defect worth reporting through the repository's issues.
