// RFC 8785 JSON Canonicalization Scheme (JCS), subset.
//
// What we implement:
//   - Recursive sort of object keys by UTF-16 code-unit order (matches the
//     default Array.prototype.sort() comparison, which is what RFC 8785
//     specifies in §3.2.3 — JSON.stringify then emits keys in iteration order)
//   - No insignificant whitespace
//   - Strings via JSON.stringify (RFC 8259-compliant escapes; RFC 8785 §3.2.2.2
//     defers to RFC 8259 for string escaping)
//   - Integers up to Number.MAX_SAFE_INTEGER via JSON.stringify
//
// What we do NOT implement:
//   - Non-integer Numbers (IEEE-754 shortest round-trip per §3.2.2.3). We
//     throw on floats so a future caller doesn't accidentally produce a
//     manifest that's signature-incompatible with a different language's JCS.
//   - BigInt (JSON.stringify throws on these already; not silently lossy)
//
// Why a subset is sufficient: the rotation manifest schema (see webhook-contract.md
// §"Key rotation and history") contains only strings, arrays, and objects.
// Zero numbers. We still walk numbers correctly if a future schema adds them,
// but only integers — floats are an explicit error.

/**
 * Canonicalize a JSON-serializable value per (a subset of) RFC 8785.
 * Returns a UTF-8-safe string suitable for hashing/signing.
 *
 * @param {unknown} value
 * @returns {string}
 */
export function canonicalize(value) {
  return JSON.stringify(walk(value))
}

function walk(v) {
  if (v === null) return null
  if (typeof v === 'boolean') return v
  if (typeof v === 'string')  return v
  if (typeof v === 'number') {
    if (!Number.isFinite(v)) throw new TypeError('JCS: non-finite numbers are not representable in JSON')
    if (!Number.isInteger(v)) throw new TypeError('JCS subset: floats are not supported (RFC 8785 §3.2.2.3 not implemented)')
    return v
  }
  if (Array.isArray(v)) return v.map(walk)
  if (v && typeof v === 'object') {
    const out = {}
    for (const k of Object.keys(v).sort()) {
      const child = walk(v[k])
      if (child === undefined) continue   // RFC 8259: undefined is not a JSON value; drop the key
      out[k] = child
    }
    return out
  }
  if (v === undefined) return undefined
  throw new TypeError(`JCS: unsupported value of type ${typeof v}`)
}
