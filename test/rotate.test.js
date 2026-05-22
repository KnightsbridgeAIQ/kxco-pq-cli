// End-to-end rotate test: derive old key, run `rotate`, then verify the
// emitted manifest with the OLD pubkey (proves the bridge works) AND
// verify a webhook-style signature made with the NEW key against the
// new well-known.json doc.

import { test }   from 'node:test'
import assert      from 'node:assert/strict'
import { mkdtempSync, readFileSync, writeFileSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { mlDsa, fingerprint } from 'kxco-post-quantum'

import { rotate } from '../src/commands/rotate.js'
import { verifyRotationManifest } from '../src/manifest.js'

function captureStdout(fn) {
  const chunks = []
  const orig = process.stdout.write.bind(process.stdout)
  process.stdout.write = (chunk) => { chunks.push(String(chunk)); return true }
  return Promise.resolve(fn()).finally(() => { process.stdout.write = orig })
}

test('rotate: produces files; manifest verifies with the OLD pubkey; well-known has both kids', async () => {
  const dir = mkdtempSync(join(tmpdir(), 'kxco-pq-rotate-'))
  try {
    // Build OLD keypair
    const oldMaster = Buffer.from('aa'.repeat(32), 'hex')
    const oldKp     = mlDsa.keypairFromMaster(oldMaster, 'rotate-test-old')
    const oldKid    = fingerprint(oldKp.publicKey)
    const oldSecretPath = join(dir, 'old-secret.hex')
    writeFileSync(oldSecretPath, Buffer.from(oldKp.secretKey).toString('hex'))

    // Run rotate
    await captureStdout(() => rotate([
      '--old-secret', '@' + oldSecretPath,
      '--old-kid',    oldKid,
      '--new-master', 'bb'.repeat(32),
      '--info',       'rotate-test-new',
      '--issuer',     'example.test',
      '--out-dir',    dir,
    ]))

    // Assert files exist
    const newPublicHex = readFileSync(join(dir, 'public-key.hex'), 'utf-8').trim()
    const newKid       = readFileSync(join(dir, 'kid.txt'),        'utf-8').trim()
    const manifest     = JSON.parse(readFileSync(join(dir, 'manifest.json'),   'utf-8'))
    const wellKnown    = JSON.parse(readFileSync(join(dir, 'well-known.json'), 'utf-8'))

    // Manifest must verify against the OLD pubkey
    const r = verifyRotationManifest(manifest, oldKp.publicKey)
    assert.equal(r.ok, true)

    // Manifest fields look right
    assert.equal(manifest.previousKid, oldKid)
    assert.equal(manifest.newKid, newKid)
    assert.equal(manifest.newPublicKey, newPublicHex)
    assert.equal(manifest.issuer, 'example.test')
    assert.equal(manifest.signature.alg, 'ml-dsa-65')
    assert.equal(manifest.signature.kid, oldKid)

    // Well-known has both kids; new is active, old is retiring
    assert.equal(wellKnown.kid, newKid)
    assert.equal(wellKnown.publicKey, newPublicHex)
    assert.equal(wellKnown.issuer, 'example.test')
    assert.equal(wellKnown.keys.length, 2)
    assert.equal(wellKnown.keys[0].status, 'active')
    assert.equal(wellKnown.keys[0].kid,    newKid)
    assert.equal(wellKnown.keys[1].status, 'retiring')
    assert.equal(wellKnown.keys[1].kid,    oldKid)
  } finally {
    rmSync(dir, { recursive: true, force: true })
  }
})

test('rotate: refuses when new kid equals old kid (same master + same info)', async () => {
  const dir = mkdtempSync(join(tmpdir(), 'kxco-pq-rotate-same-'))
  try {
    const master = Buffer.from('cc'.repeat(32), 'hex')
    const kp     = mlDsa.keypairFromMaster(master, 'same-key-test')
    const kid    = fingerprint(kp.publicKey)
    const secretPath = join(dir, 'old-secret.hex')
    writeFileSync(secretPath, Buffer.from(kp.secretKey).toString('hex'))

    await assert.rejects(
      rotate([
        '--old-secret', '@' + secretPath,
        '--old-kid',    kid,
        '--new-master', 'cc'.repeat(32),    // same master
        '--info',       'same-key-test',     // same info → same kid
        '--issuer',     'example.test',
        '--out-dir',    dir,
      ]),
      /new kid equals old kid/,
    )
  } finally {
    rmSync(dir, { recursive: true, force: true })
  }
})

test('rotate: rejects --old-kid not 16 hex chars', async () => {
  const dir = mkdtempSync(join(tmpdir(), 'kxco-pq-rotate-bad-'))
  try {
    // We don't even need a real secret file; arg validation fires first
    const fakeSecret = join(dir, 'fake.hex')
    writeFileSync(fakeSecret, '00'.repeat(4032))   // length-correct, content arbitrary
    await assert.rejects(
      rotate([
        '--old-secret', '@' + fakeSecret,
        '--old-kid',    'not-hex',
        '--new-master', 'dd'.repeat(32),
        '--info',       'x',
        '--issuer',     'example.test',
        '--out-dir',    dir,
      ]),
      /must be 16 hex chars/,
    )
  } finally {
    rmSync(dir, { recursive: true, force: true })
  }
})
