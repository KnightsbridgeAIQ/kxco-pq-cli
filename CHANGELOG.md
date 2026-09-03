# Changelog

## 1.2.7

### Corrected

The README claimed `@noble/post-quantum` was audited by Cure53 in 2024.
**It was not, by Cure53 or anyone else.** It is self-audited by its maintainer
(v0.6.1, April 2026), and this package has had no third-party assessment
either.

The other Noble packages were audited separately and at different dates, and
none of those engagements reached the post-quantum package:

| Package | Audited by |
|---|---|
| `@noble/post-quantum` | **nobody** |
| `@noble/hashes` | Cure53, Jan 2022, v1.0.0 |
| `@noble/curves` | Trail of Bits Feb 2023; Kudelski Sep 2023; Cure53 Sep 2024 |
| `@noble/ciphers` | Cure53, Sep 2024, v1.0.0 |

Dates from `kxco-post-quantum/audit/dependency-review.json`, which is generated
by `audit/run-audit.mjs` rather than written by hand.

Documentation only. No code changed and no behaviour changed.

## 1.2.5

Released to carry an npm provenance attestation. **No functional change**: no
source file is touched and the dependency set is identical to the previous
version.

Earlier releases of this package have no attestation, and provenance attaches to
a version rather than to a package, so it cannot be applied retroactively. The
publish workflow now declares `id-token: write`, publishes with `--provenance`
instead of `--no-provenance`, and authenticates through an npm Trusted Publisher
binding. Verify with `npm view kxco-pq-cli dist.attestations`.

## 1.0.0 — 2026-05-24

Stable release.



## 0.1.5 — 2026-05-24

Maintenance release. No breaking changes.



## 0.1.4 — 2026-05-24

Maintenance release. No breaking changes.



## 0.1.3 — 2026-05-24

Maintenance release. No breaking changes.



## 0.1.2 â€” 2026-05-24

Fix bin entry that was being stripped during publish (removed `./` prefix).

## 0.1.1 â€” 2026-05-24

Maintenance release. No breaking changes.

## 0.1.0 â€” 2026-05-22

Initial release.

### Added
- `kxco-pq keygen` â€” derive ML-DSA-65 keypair from master secret + label via HKDF
- `kxco-pq fingerprint` â€” compute 16-hex KID from a public key hex string or file
- `kxco-pq rotate` â€” generate signed rotation manifest + well-known JSON for key transitions
- RFC 8785 JCS-canonical signing of rotation manifests using the old identity key
- `--master` / `--new-master` / `--old-secret` accept inline 64-hex or `@/path/to/file`
- Output: `secret-key.hex`, `public-key.hex`, `kid.txt` (keygen + rotate)
- Output: `well-known.json`, `manifest.json` (rotate only)
- Deterministic keygen matches `kxco-post-quantum` library derivation pattern
- 20+ tests: JCS canonicalisation, manifest signing, keygen, fingerprint, rotate
