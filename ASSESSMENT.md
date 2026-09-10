# Assessment notes

Where this package's boundary falls, what agility it has, and what constrains
its lifecycle.

Algorithm conformance belongs to
[`kxco-post-quantum`](https://www.npmjs.com/package/kxco-post-quantum) and is
published in that package's evidence bundle. It is referenced here, never
restated.

## Boundary

**What the assessed thing is.** A command-line tool, `kxco-pq`, that generates
keys, fingerprints them, signs and verifies attestations, and rotates keys with
an optional on-chain anchor.

**This is the only package in the family that handles secret key material as
files on disk, and that is its defining boundary.** `keygen` writes
`secret-key.hex` to an output directory. `rotate` reads an old secret and takes
an `--identity-file` that contains a secret key in JSON. Everything else in the
family either keeps keys in memory the caller manages or pushes them onto a
token.

The consequences an assessment needs:

- *File permissions are the control, and they are the operator's.* The README
  says `chmod 600` and to store it in a secrets manager. Nothing in the tool
  enforces that.
- *A secret passed as a literal argument is exposed twice over.* Command-line
  arguments appear in shell history and are readable from the process table by
  other users on the machine while the command runs.

  **The safe form exists and the documentation demonstrates the unsafe one.**
  `readHexInput` in `src/util.js` accepts an `@path` prefix for any hex input,
  so `--master @./master.hex` reads from a file and keeps the secret off
  `argv`. The README's `keygen` example shows a literal instead. Use the `@`
  form. This is worth fixing in the documentation and is recorded here until it
  is.

**Deterministic keys make the master secret the single point of failure.** A
keypair is derived from `(master, info)` through HKDF, so the same inputs always
produce the same kid and a lost key can be restored from the master. The
converse is the security statement: whoever holds the master holds every key
ever derived from it, including ones they have not seen, and rotation by
changing `info` does not help against an attacker who has the master. Treat the
master as the asset.

**Operate: one optional outbound connection.** `rotate` contacts the relay only
when `--relay` is passed. `relay.kxco.ai` negotiates the hybrid key exchange
group `X25519MLKEM768` under TLS 1.3, measured 7 September 2026 with OpenSSL
3.5.6; its certificate is ECDSA P-384, so endpoint authentication is classical.
The rotation intent is signed with ML-DSA-65 before it is sent and verified on
chain after it arrives, so the transport carries it rather than securing it.

Without `--relay` the tool is entirely offline.

**Retain history.** Nothing is stored beyond the files the operator asks for.
The kid file exists so receivers have something stable to pin.

**Start and update.** Every release carries a SLSA provenance attestation,
tying the published tarball to the commit and workflow that built it, and a
CycloneDX SBOM as a GitHub Release asset at a permanent unauthenticated URL
rather than an expiring build artifact. Both are checkable without asking us
for anything.

What this package does not have is release-asset signing with ML-DSA-65
against a committed public key. That is the primitives package, it is the
stronger control, and it should not be read across to this one. Note that a CLI is often installed globally and run outside a
project's lockfile, so the version in use is easier to lose track of here than
in a library.

## Agility

**Inherited.** Primitives belong to `kxco-post-quantum`; envelope format to
`kxco-pq-attest`. See those packages' notes.

**The addition: `info` is a domain-separation label the operator controls.**
`my-institution-v1` to `my-institution-v2` derives a different keypair from the
same master. That is a rotation mechanism exposed as an argument, and it is
useful. It is not a defence against master compromise, as above.

**The limit: the tool implements one parameter set.** `keygen` produces
ML-DSA-65 and validates that the master decodes to exactly 32 bytes. Another
parameter set is a release of this package.

## Lifecycle

**Assess `origin/main`, and know that this working tree is ahead of it.**
Verified 8 September 2026: `origin/main`, this checkout and npm all read 2.0.0,
so the published artefact does correspond to `origin/main`.

The local working branch `feat/verification-modes-and-registry` carries 6
commits that have never been pushed, and is 1 behind `origin/main`. A clone
from GitHub is not what sits on the maintainer's machine. The evidence bundle
records the branch it was built from in `01-identity.json`.

**Supported versions.** One line moving forward. At 2.x while much of the
family is at 1.x; major numbers are per package.

**Pins, and this one has drifted furthest.** `kxco-post-quantum` is declared
`^1.3.0`, and the tree the evidence bundle was last built from resolved it to
**1.6.0**. Declared floor and installed version differ by three minor versions,
and the current release is 1.7.2. That is the clearest illustration in the
family of why the range matters: nothing about the declaration tells you what
ran. `02-primitives.json` records what did.

**Stale organisation references.** Links in this repository still point at the
`JackKXCO` GitHub organisation, which the repositories moved away from to
`KnightsbridgeAIQ`. They resolve because GitHub redirects renamed
organisations. Depending on a redirect from a name we no longer control is
worth correcting rather than relying on.

**Ceiling.** No hardware or runtime ceiling. `keygen` is one derivation and
`rotate` is a signature; neither is a performance question.

**Blocking dependencies.** The upstream library, `kxco-pq-attest`, and the
relay when `--relay` is used.

**Roadmap.** No external audit of this package, no bug bounty.

## Correcting this document

Every claim here is checkable against `src/` and the README. If one does not
match, that is a defect worth reporting through the repository's issues.
