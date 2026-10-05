// Rotation manifest construction + verification.
//
// Spec: kxco-post-quantum-webhook/docs/webhook-contract.md §"Key rotation and history".
//
// A rotation manifest is a JSON document signed by the OUTGOING (previous-active)
// key, attesting that a new key is taking over. The signature covers the manifest
// with `signature.value` set to "" and the rest of `signature` populated, then
// canonicalized via RFC 8785 JCS.
//
// Why JCS instead of just a hash-of-JSON.stringify: any receiver re-implementing
// this in Rust/Go/Python must produce byte-identical input to ML-DSA-65 verify.
// Without a defined canonicalization, key order, whitespace, and number format
// drift across languages and signatures stop verifying.

import { canonicalize } from './jcs.js'
import { DSA, dsaForPublicKey, dsaForSecretKey } from './util.js'

const MANIFEST_VERSION = '1.0'
const MANIFEST_TYPE    = 'rotation'

/**
 * @typedef {Object} BuildRotationManifestOpts
 * @property {string} issuer        — publisher domain, e.g. "chain.kxco.ai"
 * @property {string} previousKid   — 16-hex kid of the outgoing key
 * @property {Uint8Array|Buffer} previousSecretKey  outgoing ML-DSA-65 (4032-byte) or ML-DSA-87
 *                                                   (4896-byte) secret key; its set is the manifest's alg
 * @property {string} newKid        — 16-hex kid of the incoming key
 * @property {Uint8Array|Buffer} newPublicKey       incoming ML-DSA-65 (1952-byte) or ML-DSA-87
 *                                                   (2592-byte) public key
 * @property {string} [effectiveAt] — ISO 8601; default = now
 */

/**
 * Build a signed rotation manifest. The returned object is ready to JSON.stringify
 * and publish. Anyone holding `previousKid`'s public key can verify it.
 *
 * @param {BuildRotationManifestOpts} opts
 * @returns {object}
 */
export function buildRotationManifest(opts) {
  const { issuer, previousKid, previousSecretKey, newKid, newPublicKey } = opts
  if (!issuer || typeof issuer !== 'string')           throw new TypeError('issuer is required')
  if (!previousKid || typeof previousKid !== 'string') throw new TypeError('previousKid is required')
  if (!newKid || typeof newKid !== 'string')           throw new TypeError('newKid is required')
  if (!previousSecretKey)                              throw new TypeError('previousSecretKey is required')
  if (!newPublicKey)                                   throw new TypeError('newPublicKey is required')

  // The outgoing key decides the signature algorithm, and the algorithm is
  // recorded in signature.alg, which is inside the signed bytes.
  const alg = dsaForSecretKey(previousSecretKey)
  if (alg === null) {
    throw new TypeError('previousSecretKey must be an ML-DSA-65 (4032-byte) or ML-DSA-87 (4896-byte) secret key')
  }

  const effectiveAt = opts.effectiveAt || new Date().toISOString()
  const newPublicKeyHex = Buffer.isBuffer(newPublicKey) || newPublicKey instanceof Uint8Array
    ? Buffer.from(newPublicKey).toString('hex')
    : String(newPublicKey)

  // 1. Build the manifest with signature.value = "" (empty), all other fields populated.
  const unsigned = {
    version:      MANIFEST_VERSION,
    manifestType: MANIFEST_TYPE,
    issuer,
    previousKid,
    newKid,
    newPublicKey: newPublicKeyHex,
    effectiveAt,
    signature: {
      alg,
      kid:   previousKid,
      value: '',
    },
  }

  // 2. Canonicalize per RFC 8785 → bytes-to-sign
  const canonicalBytes = Buffer.from(canonicalize(unsigned), 'utf-8')

  // 3. Sign with the outgoing secret key. mlDsa.sign() returns hex directly.
  const sigHex = DSA[alg].module.sign(previousSecretKey, canonicalBytes)

  // 4. Populate signature.value
  return { ...unsigned, signature: { ...unsigned.signature, value: sigHex } }
}

/**
 * Verify a rotation manifest's signature against a known public key for
 * `signature.kid`. Returns { ok, reason? }. Does NOT decide trust policy —
 * the caller must already have decided to trust `signature.kid`.
 *
 * @param {object} manifest
 * @param {Uint8Array|Buffer|string} previousPublicKey  — pubkey for signature.kid
 * @returns {{ ok: boolean, reason?: string }}
 */
export function verifyRotationManifest(manifest, previousPublicKey) {
  if (!manifest || typeof manifest !== 'object')      return { ok: false, reason: 'malformed' }
  if (manifest.version !== MANIFEST_VERSION)          return { ok: false, reason: 'unsupported_version' }
  if (manifest.manifestType !== MANIFEST_TYPE)        return { ok: false, reason: 'wrong_type' }
  if (!manifest.signature || !Object.hasOwn(DSA, manifest.signature.alg)) return { ok: false, reason: 'wrong_alg' }
  if (typeof manifest.signature.value !== 'string' || manifest.signature.value.length === 0) {
    return { ok: false, reason: 'no_signature' }
  }
  if (manifest.signature.kid !== manifest.previousKid) return { ok: false, reason: 'signature_kid_mismatch' }

  const pubBytes = Buffer.isBuffer(previousPublicKey) || previousPublicKey instanceof Uint8Array
    ? Buffer.from(previousPublicKey)
    : Buffer.from(String(previousPublicKey), 'hex')

  // The key decides the algorithm. A key of neither set verifies nothing, as
  // before; a manifest whose signature.alg names the other set from the key is
  // refused rather than tried. A manifest with no signature.alg never verified
  // and still does not.
  const keyAlg = dsaForPublicKey(pubBytes)
  if (keyAlg === null) return { ok: false, reason: 'bad_signature' }
  if (keyAlg !== manifest.signature.alg) return { ok: false, reason: 'wrong_alg' }

  // Reconstruct the canonical bytes by emptying out signature.value
  const unsigned = { ...manifest, signature: { ...manifest.signature, value: '' } }
  const canonicalBytes = Buffer.from(canonicalize(unsigned), 'utf-8')

  // mlDsa.verify() takes a hex-encoded signature string directly.
  const ok = DSA[keyAlg].module.verify(pubBytes, canonicalBytes, manifest.signature.value)
  return ok ? { ok: true } : { ok: false, reason: 'bad_signature' }
}
