// Property-based tests with fast-check.
//
// This package is a command line and exports no library, so the keygen and
// attest properties run the real `kxco-pq` binary as a child process against
// files in a temporary directory, as a user would, and read back what it wrote
// and how it exited. Every run starts Node processes, so those properties keep
// to a handful of runs. The rotation manifest that `rotate` signs, and the JCS
// canonicaliser under it, are pure functions and run in process, many times.
//
// fast-check generates the inputs and, when a property breaks, shrinks the
// failing case to the smallest one that still breaks it.
//
// Nothing here passes --relay, so nothing reaches a network.

import { test, after } from 'node:test'
import assert from 'node:assert/strict'
import { execFile } from 'node:child_process'
import { promisify, isDeepStrictEqual } from 'node:util'
import { mkdtempSync, mkdirSync, readFileSync, writeFileSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { fileURLToPath } from 'node:url'
import fc from 'fast-check'
import { mlDsa, mlDsa87, fingerprint } from 'kxco-post-quantum'

import { canonicalize } from '../src/jcs.js'
import { buildRotationManifest, verifyRotationManifest } from '../src/manifest.js'

const BIN = fileURLToPath(new URL('../bin/kxco-pq.js', import.meta.url))
const TMP = mkdtempSync(join(tmpdir(), 'kxco-pq-prop-'))
after(() => rmSync(TMP, { recursive: true, force: true }))

const exec = promisify(execFile)

// Run the binary; resolve with its exit code and output whatever the code.
async function kxcoPq(args) {
  try {
    const { stdout, stderr } = await exec(process.execPath, [BIN, ...args])
    return { code: 0, stdout, stderr }
  } catch (e) {
    if (typeof e.code !== 'number') throw e
    return { code: e.code, stdout: e.stdout, stderr: e.stderr }
  }
}

let runs = 0
function freshDir(label) {
  const dir = join(TMP, `${label}-${runs++}`)
  mkdirSync(dir, { recursive: true })
  return dir
}

const hex = (bytes) => Buffer.from(bytes).toString('hex')
const read = (dir, name) => readFileSync(join(dir, name), 'utf8')

// A process per case: a handful of runs, with the two independent processes
// in each run started side by side.
const PROCESS_RUNS = { numRuns: 4 }
const SIGNING_RUNS = { numRuns: 30 }

// Any label a command line can carry: not empty, which keygen refuses as
// missing, and no NUL, which no operating system will pass as an argument.
const info = fc.string({ minLength: 1, maxLength: 40, unit: 'grapheme' }).filter((s) => !s.includes('\0'))

// One key for the attest and rotation properties; those are about payloads
// and manifests, not keys.
const OLD = mlDsa.keypairFromMaster(new Uint8Array(32).fill(3), 'kxco-pq-cli-property-tests-old')
const NEW = mlDsa.keypairFromMaster(new Uint8Array(32).fill(4), 'kxco-pq-cli-property-tests-new')

test('the harness fails a property that is false', () => {
  assert.throws(() => fc.assert(fc.property(fc.integer(), (n) => n + 1 === n), { numRuns: 10 }))
})

test('keygen: the same master and info always write the same keypair, the one kxco-post-quantum derives', async () => {
  await fc.assert(fc.asyncProperty(fc.uint8Array({ minLength: 32, maxLength: 32 }), info, async (master, label) => {
    const dir = freshDir('keygen')
    // The @file form, which keeps the master out of the process table.
    writeFileSync(join(dir, 'master.hex'), hex(master) + '\n')
    const args = (out) => ['keygen', '--master', '@' + join(dir, 'master.hex'), '--info', label, '--out-dir', join(dir, out)]
    const [a, b] = await Promise.all([kxcoPq(args('a')), kxcoPq(args('b'))])
    assert.equal(a.code, 0, a.stderr)
    assert.equal(b.code, 0, b.stderr)
    for (const file of ['secret-key.hex', 'public-key.hex', 'kid.txt']) {
      assert.equal(read(join(dir, 'a'), file), read(join(dir, 'b'), file), `${file} differs between two runs`)
    }
    // keygen makes an ML-DSA-87 key unless --algorithm names another set.
    const expected = mlDsa87.keypairFromMaster(master, label)
    assert.equal(read(join(dir, 'a'), 'secret-key.hex'), hex(expected.secretKey) + '\n')
    assert.equal(read(join(dir, 'a'), 'public-key.hex'), hex(expected.publicKey) + '\n')
    assert.equal(read(join(dir, 'a'), 'kid.txt'), fingerprint(expected.publicKey) + '\n')
    return true
  }), PROCESS_RUNS)
})

test('attest: sign then verify round-trips any non-empty file, and a tampered payload is INVALID with exit 1', async () => {
  const keys = freshDir('keys')
  writeFileSync(join(keys, 'secret-key.hex'), hex(OLD.secretKey) + '\n')
  writeFileSync(join(keys, 'public-key.hex'), hex(OLD.publicKey) + '\n')
  const secretKey = '@' + join(keys, 'secret-key.hex')
  const publicKey = '@' + join(keys, 'public-key.hex')

  await fc.assert(fc.asyncProperty(fc.uint8Array({ minLength: 1, maxLength: 4096, size: 'max' }), fc.nat(), fc.nat(7), async (payload, at, bit) => {
    const dir = freshDir('attest')
    writeFileSync(join(dir, 'payload.bin'), payload)
    const signed = await kxcoPq(['attest', 'sign', '--secret-key', secretKey, '--public-key', publicKey,
      '--file', join(dir, 'payload.bin'), '--out', join(dir, 'attestation.json')])
    assert.equal(signed.code, 0, signed.stderr)

    const envelope = JSON.parse(read(dir, 'attestation.json'))
    assert.ok(Buffer.from(envelope.payload, 'base64url').equals(Buffer.from(payload)), 'the envelope carries the file')
    const changed = Buffer.from(payload)
    changed[at % changed.length] ^= 1 << bit
    writeFileSync(join(dir, 'tampered.json'), JSON.stringify({ ...envelope, payload: changed.toString('base64url') }))

    const [good, bad] = await Promise.all([
      kxcoPq(['attest', 'verify', '--public-key', publicKey, '--attestation', join(dir, 'attestation.json')]),
      kxcoPq(['attest', 'verify', '--public-key', publicKey, '--attestation', join(dir, 'tampered.json')]),
    ])
    assert.equal(good.code, 0, good.stderr)
    assert.match(good.stdout, /VALID/)
    assert.match(good.stdout, new RegExp(`payload:\\s+${payload.length} bytes`))
    assert.match(good.stdout, new RegExp(`signer kid:\\s+${fingerprint(OLD.publicKey)}`))
    assert.equal(bad.code, 1)
    assert.match(bad.stderr, /INVALID/)
    return true
  }), PROCESS_RUNS)
})

// JSON values for the canonicaliser. Keys are any text, integer-like names and
// `__proto__` among them, and numbers are integers, which is the subset jcs.js
// implements. Objects are built with Object.fromEntries, so every key is an
// own member, `__proto__` included.
const key = fc.oneof(
  { weight: 6, arbitrary: fc.string({ maxLength: 12, unit: 'binary' }) },
  { weight: 3, arbitrary: fc.nat(1000).map(String) },
  { weight: 1, arbitrary: fc.constant('__proto__') },
)
const { json } = fc.letrec((tie) => ({
  json: fc.oneof({ depthSize: 'small' },
    fc.constant(null), fc.boolean(), fc.integer(), fc.string({ maxLength: 20, unit: 'binary' }),
    fc.array(tie('json'), { maxLength: 4 }),
    fc.uniqueArray(fc.tuple(key, tie('json')), { maxLength: 5, selector: ([k]) => k }).map(Object.fromEntries),
  ),
}))

// The same value with every object's keys in reverse insertion order.
function reversed(v) {
  if (Array.isArray(v)) return v.map(reversed)
  if (v && typeof v === 'object') return Object.fromEntries(Object.entries(v).reverse().map(([k, x]) => [k, reversed(x)]))
  return v
}

// The keys of every object in JSON text, in the order the text gives them.
// JSON.parse cannot answer this: a JavaScript object lists integer-like keys
// first, whatever order the text had them in.
function keyOrders(text) {
  const orders = []
  const open = []   // one entry per open object (its key list) or array (null)
  let expectKey = false
  for (let i = 0; i < text.length; i++) {
    const ch = text[i]
    if (ch === '"') {
      let j = i + 1
      while (text[j] !== '"') j += text[j] === '\\' ? 2 : 1
      if (expectKey) open[open.length - 1].push(JSON.parse(text.slice(i, j + 1)))
      expectKey = false
      i = j
    } else if (ch === '{') {
      const keys = []
      orders.push(keys)
      open.push(keys)
      expectKey = true
    } else if (ch === '[') {
      open.push(null)
    } else if (ch === '}' || ch === ']') {
      open.pop()
      expectKey = false
    } else if (ch === ',') {
      expectKey = open[open.length - 1] !== null
    }
  }
  return orders
}

function keyCount(v) {
  if (Array.isArray(v)) return v.reduce((n, x) => n + keyCount(x), 0)
  if (v && typeof v === 'object') return Object.keys(v).length + Object.values(v).reduce((n, x) => n + keyCount(x), 0)
  return 0
}

test('JCS: the canonical form ignores key order, is idempotent, keeps every member, and sorts keys at every depth', () => {
  fc.assert(fc.property(json, (value) => {
    const c = canonicalize(value)
    const back = JSON.parse(c)
    const orders = keyOrders(c)
    return canonicalize(reversed(value)) === c &&
      canonicalize(back) === c &&
      isDeepStrictEqual(back, value) &&
      orders.flat().length === keyCount(value) &&
      orders.every((keys) => keys.every((k, i) => i === 0 || keys[i - 1] < k))
  }), { numRuns: 500 })
})

test('JCS: a non-integer or non-finite number anywhere is refused with a TypeError', () => {
  const bad = fc.oneof(
    fc.double({ noNaN: true, noDefaultInfinity: true }).filter((x) => !Number.isInteger(x)),
    fc.constantFrom(NaN, Infinity, -Infinity),
  )
  fc.assert(fc.property(json, bad, fc.nat(), (value, number, at) => {
    // Put the number somewhere inside the value: into any array or object in
    // it, or beside it in the wrapper at the top.
    const holder = [value]
    const containers = [holder]
    for (let i = 0; i < containers.length; i++) {
      for (const x of Object.values(containers[i])) if (x && typeof x === 'object') containers.push(x)
    }
    const target = containers[at % containers.length]
    if (Array.isArray(target)) target.push(number)
    else target.k_number = number
    assert.throws(() => canonicalize(holder), TypeError)
    return true
  }), { numRuns: 300 })
})

const issuer = fc.string({ minLength: 1, maxLength: 60, unit: 'grapheme' })
const effectiveAt = fc.date({ min: new Date('2000-01-01'), max: new Date('2100-01-01'), noInvalidDate: true }).map((d) => d.toISOString())

function manifestFor(iss, at) {
  return buildRotationManifest({
    issuer: iss,
    previousKid: fingerprint(OLD.publicKey),
    previousSecretKey: OLD.secretKey,
    newKid: fingerprint(NEW.publicKey),
    newPublicKey: NEW.publicKey,
    effectiveAt: at,
  })
}

test('rotation manifest: build then verify round-trips, including through JSON, and only under the outgoing key', () => {
  fc.assert(fc.property(issuer, effectiveAt, (iss, at) => {
    const m = manifestFor(iss, at)
    return verifyRotationManifest(m, OLD.publicKey).ok === true &&
      verifyRotationManifest(JSON.parse(JSON.stringify(m)), hex(OLD.publicKey)).ok === true &&
      verifyRotationManifest(m, NEW.publicKey).reason === 'bad_signature' &&
      m.newPublicKey === hex(NEW.publicKey) && m.effectiveAt === at && m.issuer === iss
  }), SIGNING_RUNS)
})

test('rotation manifest: any changed or added field is refused', () => {
  // Every kind of change is tried on every generated manifest.
  const FIELDS = [
    'issuer', 'newKid', 'newPublicKey', 'effectiveAt', 'version', 'manifestType',
    'previousKid', 'bothKids', 'signature.alg', 'signature.value', 'added', 'added __proto__',
  ]
  const change = fc.record({
    text: fc.string({ minLength: 1, maxLength: 12 }),
    name: key.filter((k) => !['version', 'manifestType', 'issuer', 'previousKid', 'newKid', 'newPublicKey', 'effectiveAt', 'signature'].includes(k)),
    at: fc.nat(),
    bit: fc.nat(7),
  })
  fc.assert(fc.property(issuer, effectiveAt, change, (iss, at, { text, name, at: pos, bit }) => {
    const signed = JSON.stringify(manifestFor(iss, at))
    const flip = (h) => {
      const b = Buffer.from(h, 'hex')
      b[pos % b.length] ^= 1 << bit
      return b.toString('hex')
    }
    // As JSON.parse would leave it: an own member, even when it is named __proto__.
    const add = (m, k, value) => Object.defineProperty(m, k, { value, enumerable: true, writable: true, configurable: true })
    return FIELDS.every((field) => {
      const m = JSON.parse(signed)
      switch (field) {
        case 'issuer': m.issuer += text; break
        case 'newKid': m.newKid = flip(m.newKid); break
        case 'newPublicKey': m.newPublicKey = flip(m.newPublicKey); break
        case 'effectiveAt': m.effectiveAt += text; break
        case 'version': m.version += text; break
        case 'manifestType': m.manifestType += text; break
        case 'previousKid': m.previousKid = flip(m.previousKid); break
        case 'bothKids': m.previousKid = flip(m.previousKid); m.signature.kid = m.previousKid; break
        case 'signature.alg': m.signature.alg += text; break
        case 'signature.value': m.signature.value = flip(m.signature.value); break
        case 'added': add(m, name, text); break
        case 'added __proto__': add(m, '__proto__', { newKid: text }); break
      }
      const r = verifyRotationManifest(m, OLD.publicKey)
      return r.ok === false && typeof r.reason === 'string'
    })
  }), SIGNING_RUNS)
})
