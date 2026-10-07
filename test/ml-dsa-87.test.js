// ML-DSA-87 through every command, with keygen making ML-DSA-87 by default,
// the key deciding the parameter set everywhere else, cross-set presentation
// refused, and ML-DSA-65 behaving exactly as before.

import { test }   from 'node:test'
import assert      from 'node:assert/strict'
import { mkdtempSync, mkdirSync, readFileSync, writeFileSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { mlDsa, mlDsa87, fingerprint as fp } from 'kxco-post-quantum'

import { keygen } from '../src/commands/keygen.js'
import { fingerprint } from '../src/commands/fingerprint.js'
import { rotate } from '../src/commands/rotate.js'
import { attest } from '../src/commands/attest.js'
import { buildRotationManifest, verifyRotationManifest } from '../src/manifest.js'

const LEGACY = JSON.parse(readFileSync(new URL('./fixtures/legacy-65-manifest.json', import.meta.url), 'utf-8'))

function captureStdout(fn) {
  const chunks = []
  const orig = process.stdout.write.bind(process.stdout)
  process.stdout.write = (chunk) => { chunks.push(String(chunk)); return true }
  return Promise.resolve(fn()).finally(() => { process.stdout.write = orig })
    .then((rc) => ({ rc, out: chunks.join('') }))
}

function withDir(fn) {
  const dir = mkdtempSync(join(tmpdir(), 'kxco-pq-87-'))
  return Promise.resolve(fn(dir)).finally(() => rmSync(dir, { recursive: true, force: true }))
}

const O65 = mlDsa.keypairFromMaster(Buffer.alloc(32, 1), 'cli-87-test-old')
const O87 = mlDsa87.keypairFromMaster(Buffer.alloc(32, 1), 'cli-87-test-old')
const N87 = mlDsa87.keypairFromMaster(Buffer.alloc(32, 2), 'cli-87-test-new')

test('keygen --algorithm ml-dsa-87: writes the ML-DSA-87 keypair the wrapper derives', () => withDir(async (dir) => {
  const { rc, out } = await captureStdout(() => keygen([
    '--master', '00'.repeat(32), '--info', 'kxco-keygen-87', '--out-dir', dir, '--algorithm', 'ml-dsa-87',
  ]))
  assert.equal(rc, 0)
  assert.match(out, /algorithm: {3}ml-dsa-87/)
  const want = mlDsa87.keypairFromMaster(Buffer.alloc(32), 'kxco-keygen-87')
  const pub = readFileSync(join(dir, 'public-key.hex'), 'utf-8').trim()
  const sec = readFileSync(join(dir, 'secret-key.hex'), 'utf-8').trim()
  assert.equal(pub.length, 2592 * 2)
  assert.equal(sec.length, 4896 * 2)
  assert.equal(pub, Buffer.from(want.publicKey).toString('hex'))
  assert.equal(readFileSync(join(dir, 'kid.txt'), 'utf-8').trim(), fp(want.publicKey))
}))

// keygen into dir, then attest sign a file with the keys it wrote and verify
// the envelope against the public key it wrote.
async function keygenThenAttest(dir, extra = []) {
  const { out } = await captureStdout(() => keygen(['--master', '00'.repeat(32), '--info', 'x', '--out-dir', dir, ...extra]))
  const file = join(dir, 'payload.txt')
  writeFileSync(file, 'signed with the default key')
  const envPath = join(dir, 'payload.attestation.json')
  const signed = await captureStdout(() => attest([
    'sign', '--secret-key', '@' + join(dir, 'secret-key.hex'), '--public-key', '@' + join(dir, 'public-key.hex'),
    '--file', file, '--out', envPath,
  ]))
  assert.equal(signed.rc, 0)
  const verified = await captureStdout(() => attest([
    'verify', '--public-key', '@' + join(dir, 'public-key.hex'), '--attestation', envPath,
  ]))
  return {
    out,
    publicHex: readFileSync(join(dir, 'public-key.hex'), 'utf-8').trim(),
    secretHex: readFileSync(join(dir, 'secret-key.hex'), 'utf-8').trim(),
    envelope: JSON.parse(readFileSync(envPath, 'utf-8')),
    verified,
  }
}

test('keygen: ML-DSA-87 is the default, sized as FIPS 204 sets it, and attest sign signs with it', () => withDir(async (dir) => {
  const r = await keygenThenAttest(dir)
  assert.match(r.out, /algorithm: {3}ml-dsa-87/)
  assert.equal(r.publicHex.length, 2592 * 2)
  assert.equal(r.secretHex.length, 4896 * 2)
  assert.equal(r.publicHex, Buffer.from(mlDsa87.keypairFromMaster(Buffer.alloc(32), 'x').publicKey).toString('hex'))
  assert.equal(r.envelope.alg, 'ML-DSA-87')
  assert.equal(Buffer.from(r.envelope.sig, 'base64url').length, 4627)
  assert.equal(r.verified.rc, 0)
  assert.match(r.verified.out, /VALID/)
}))

test('keygen --algorithm ml-dsa-65: the old default on request, and attest sign signs as ML-DSA-65', () => withDir(async (dir) => {
  const r = await keygenThenAttest(dir, ['--algorithm', 'ml-dsa-65'])
  assert.match(r.out, /algorithm: {3}ml-dsa-65/)
  assert.equal(r.publicHex.length, 1952 * 2)
  assert.equal(r.secretHex.length, 4032 * 2)
  assert.equal(r.publicHex, Buffer.from(mlDsa.keypairFromMaster(Buffer.alloc(32), 'x').publicKey).toString('hex'))
  assert.equal(r.envelope.alg, 'ML-DSA-65')
  assert.equal(Buffer.from(r.envelope.sig, 'base64url').length, 3309)
  assert.equal(r.verified.rc, 0)
}))

test('an ML-DSA-65 key already on disk still signs, verifies and rotates as ML-DSA-65', () => withDir(async (dir) => {
  // The files keygen wrote before 2.3.0, when ML-DSA-65 was the default.
  writeFileSync(join(dir, 'secret-key.hex'), Buffer.from(O65.secretKey).toString('hex') + '\n')
  writeFileSync(join(dir, 'public-key.hex'), Buffer.from(O65.publicKey).toString('hex') + '\n')
  const file = join(dir, 'payload.txt')
  writeFileSync(file, 'signed with an existing key')
  const envPath = join(dir, 'existing.attestation.json')
  const signed = await captureStdout(() => attest([
    'sign', '--secret-key', '@' + join(dir, 'secret-key.hex'), '--public-key', '@' + join(dir, 'public-key.hex'),
    '--file', file, '--out', envPath,
  ]))
  assert.equal(signed.rc, 0)
  const envelope = JSON.parse(readFileSync(envPath, 'utf-8'))
  assert.equal(envelope.alg, 'ML-DSA-65')
  assert.equal(Buffer.from(envelope.sig, 'base64url').length, 3309)
  const verified = await captureStdout(() => attest(['verify', '--public-key', '@' + join(dir, 'public-key.hex'), '--attestation', envPath]))
  assert.equal(verified.rc, 0)
  // Rotation from it, with no --algorithm, keeps the old key's set.
  mkdirSync(join(dir, 'rotated'))
  const r = await rotateFrom(join(dir, 'rotated'), O65)
  assert.equal(r.publicHex.length, 1952 * 2)
  assert.equal(r.manifest.signature.alg, 'ml-dsa-65')
  assert.deepEqual(verifyRotationManifest(r.manifest, O65.publicKey), { ok: true })
}))

test('keygen: an unknown --algorithm is refused', async () => {
  await assert.rejects(
    keygen(['--master', '00'.repeat(32), '--info', 'x', '--out-dir', '.', '--algorithm', 'ml-dsa-44']),
    /--algorithm must be ml-dsa-65 or ml-dsa-87/,
  )
})

test('fingerprint: an ML-DSA-87 public key gives the wrapper fingerprint', async () => {
  const { rc, out } = await captureStdout(() => fingerprint([Buffer.from(N87.publicKey).toString('hex')]))
  assert.equal(rc, 0)
  assert.equal(out.trim(), fp(N87.publicKey))
})

test('fingerprint: a length of neither set is refused', async () => {
  await assert.rejects(fingerprint(['aa'.repeat(2593)]), /1952 bytes \(ML-DSA-65\) or 2592 bytes \(ML-DSA-87\)/)
})

test('manifest: an ML-DSA-87 outgoing key signs with ml-dsa-87, and only its own key verifies it', () => {
  const m = buildRotationManifest({
    issuer: 'example.test', previousKid: fp(O87.publicKey), previousSecretKey: O87.secretKey,
    newKid: fp(N87.publicKey), newPublicKey: N87.publicKey,
  })
  assert.equal(m.signature.alg, 'ml-dsa-87')
  assert.equal(m.signature.value.length, 4627 * 2)
  assert.deepEqual(verifyRotationManifest(m, O87.publicKey), { ok: true })
  // An ML-DSA-65 key presented for an ML-DSA-87 manifest is refused, not tried.
  assert.deepEqual(verifyRotationManifest(m, O65.publicKey), { ok: false, reason: 'wrong_alg' })
})

test('manifest: signature.alg is inside the signed bytes, so relabelling it fails', () => {
  const m = buildRotationManifest({
    issuer: 'example.test', previousKid: fp(O65.publicKey), previousSecretKey: O65.secretKey,
    newKid: fp(N87.publicKey), newPublicKey: N87.publicKey,
  })
  assert.equal(m.signature.alg, 'ml-dsa-65')
  const relabelled = { ...m, signature: { ...m.signature, alg: 'ml-dsa-87' } }
  // Against the -65 key: the stated set disagrees with the key.
  assert.deepEqual(verifyRotationManifest(relabelled, O65.publicKey), { ok: false, reason: 'wrong_alg' })
  // Against an -87 key: the set agrees, but the -65 signature over the
  // relabelled bytes cannot verify.
  assert.deepEqual(verifyRotationManifest(relabelled, O87.publicKey), { ok: false, reason: 'bad_signature' })
})

test('manifest: an unknown signature.alg is refused', () => {
  const m = buildRotationManifest({
    issuer: 'example.test', previousKid: fp(O87.publicKey), previousSecretKey: O87.secretKey,
    newKid: fp(N87.publicKey), newPublicKey: N87.publicKey,
  })
  for (const alg of ['ml-dsa-44', 'ML-DSA-87', '__proto__', undefined]) {
    assert.deepEqual(verifyRotationManifest({ ...m, signature: { ...m.signature, alg } }, O87.publicKey),
      { ok: false, reason: 'wrong_alg' }, String(alg))
  }
})

test('manifest: a secret key of neither set is refused at build time', () => {
  assert.throws(() => buildRotationManifest({
    issuer: 'example.test', previousKid: 'aa'.repeat(8), previousSecretKey: Buffer.alloc(4033),
    newKid: 'bb'.repeat(8), newPublicKey: N87.publicKey,
  }), /ML-DSA-65 \(4032-byte\) or ML-DSA-87 \(4896-byte\)/)
})

test('manifest: one built by 2.1.3 before ML-DSA-87 still verifies', () => {
  const pub = Buffer.from(LEGACY.previousPublicKey, 'hex')
  assert.equal(LEGACY.manifest.signature.alg, 'ml-dsa-65')
  assert.deepEqual(verifyRotationManifest(LEGACY.manifest, pub), { ok: true })
  assert.deepEqual(verifyRotationManifest(LEGACY.manifest, O87.publicKey), { ok: false, reason: 'wrong_alg' })
})

async function rotateFrom(dir, oldKp, extra = []) {
  const oldSecretPath = join(dir, 'old-secret.hex')
  writeFileSync(oldSecretPath, Buffer.from(oldKp.secretKey).toString('hex'))
  const { out } = await captureStdout(() => rotate([
    '--old-secret', '@' + oldSecretPath, '--old-kid', fp(oldKp.publicKey),
    '--new-master', 'cd'.repeat(32), '--info', 'rotate-87-new',
    '--issuer', 'example.test', '--out-dir', dir, ...extra,
  ]))
  return {
    out,
    publicHex: readFileSync(join(dir, 'public-key.hex'), 'utf-8').trim(),
    manifest: JSON.parse(readFileSync(join(dir, 'manifest.json'), 'utf-8')),
    wellKnown: JSON.parse(readFileSync(join(dir, 'well-known.json'), 'utf-8')),
  }
}

test('rotate: an ML-DSA-87 old key rotates to an ML-DSA-87 new key by default', () => withDir(async (dir) => {
  const r = await rotateFrom(dir, O87)
  assert.equal(r.publicHex.length, 2592 * 2)
  assert.equal(r.manifest.signature.alg, 'ml-dsa-87')
  assert.deepEqual(verifyRotationManifest(r.manifest, O87.publicKey), { ok: true })
  assert.equal(r.wellKnown.algorithm, 'ml-dsa-87')
  assert.equal(r.wellKnown.keys[1].algorithm, undefined, 'same set: nothing extra on the retiring key')
  assert.match(r.out, /manifest signed by previous kid: yes \(ml-dsa-87\)/)
}))

test('rotate --algorithm ml-dsa-87 from an ML-DSA-65 key: the old key signs, the well-known names both sets', () => withDir(async (dir) => {
  const r = await rotateFrom(dir, O65, ['--algorithm', 'ml-dsa-87'])
  assert.equal(r.publicHex.length, 2592 * 2)
  assert.equal(r.manifest.signature.alg, 'ml-dsa-65')
  assert.deepEqual(verifyRotationManifest(r.manifest, O65.publicKey), { ok: true })
  assert.equal(r.wellKnown.algorithm, 'ml-dsa-87')
  assert.equal(r.wellKnown.keys[1].algorithm, 'ml-dsa-65')
  // The new key signs as ML-DSA-87 and verifies against the published key.
  const sk = readFileSync(join(dir, 'secret-key.hex'), 'utf-8').trim()
  const sig = mlDsa87.sign(Buffer.from(sk, 'hex'), 'after rotation')
  assert.equal(mlDsa87.verify(Buffer.from(r.wellKnown.publicKey, 'hex'), 'after rotation', sig), true)
}))

test('rotate: an ML-DSA-65 old key still rotates to ML-DSA-65 with the same well-known shape', () => withDir(async (dir) => {
  const r = await rotateFrom(dir, O65)
  assert.equal(r.publicHex.length, 1952 * 2)
  assert.equal(r.manifest.signature.alg, 'ml-dsa-65')
  assert.equal(r.wellKnown.algorithm, 'ml-dsa-65')
  assert.deepEqual(Object.keys(r.wellKnown.keys[1]).sort(), ['activeUntil', 'kid', 'status', 'supersededBy'])
}))

test('rotate: an old secret of neither set is refused', () => withDir(async (dir) => {
  const p = join(dir, 's.hex')
  writeFileSync(p, '00'.repeat(4500))
  await assert.rejects(rotate([
    '--old-secret', '@' + p, '--old-kid', 'aa'.repeat(8), '--new-master', 'cd'.repeat(32),
    '--info', 'x', '--issuer', 'example.test', '--out-dir', dir,
  ]), /4032 bytes \(ML-DSA-65 secret key\) or 4896 bytes \(ML-DSA-87 secret key; got 4500\)/)
}))
