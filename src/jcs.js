// RFC 8785 JSON Canonicalization Scheme (JCS), subset.
//
// What we implement:
//   - Recursive sort of object keys by UTF-16 code-unit order (the default
//     Array.prototype.sort() comparison, which is what RFC 8785 specifies in
//     §3.2.3). Members are written out by hand in that order, because a
//     JavaScript object would put integer-like keys first and would take a
//     "__proto__" key as its prototype rather than as a member.
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
  return serialize(value)
}

function serialize(v) {
  if (v === null) return 'null'
  if (typeof v === 'boolean') return v ? 'true' : 'false'
  if (typeof v === 'string')  return JSON.stringify(v)
  if (typeof v === 'number') {
    if (!Number.isFinite(v)) throw new TypeError('JCS: non-finite numbers are not representable in JSON')
    if (!Number.isInteger(v)) throw new TypeError('JCS subset: floats are not supported (RFC 8785 §3.2.2.3 not implemented)')
    return JSON.stringify(v)
  }
  if (Array.isArray(v)) {
    const items = []
    for (let i = 0; i < v.length; i++) {
      const item = serialize(v[i])
      items.push(item === undefined ? 'null' : item)   // as JSON.stringify writes an undefined array slot
    }
    return `[${items.join(',')}]`
  }
  if (v && typeof v === 'object') {
    const members = []
    for (const k of Object.keys(v).sort()) {
      const child = serialize(v[k])
      if (child === undefined) continue   // RFC 8259: undefined is not a JSON value; drop the key
      members.push(`${JSON.stringify(k)}:${child}`)
    }
    return `{${members.join(',')}}`
  }
  if (v === undefined) return undefined
  throw new TypeError(`JCS: unsupported value of type ${typeof v}`)
}
