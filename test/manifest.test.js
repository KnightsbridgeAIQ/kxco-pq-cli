import { test }   from 'node:test'
import assert      from 'node:assert/strict'
import { mlDsa, fingerprint } from 'kxco-post-quantum'
import { buildRotationManifest, verifyRotationManifest } from '../src/manifest.js'

const OLD = mlDsa.keypairFromMaster(Buffer.from('00'.repeat(32), 'hex'), 'cli-test-old')
const NEW = mlDsa.keypairFromMaster(Buffer.from('11'.repeat(32), 'hex'), 'cli-test-new')
const OLD_KID = fingerprint(OLD.publicKey)
const NEW_KID = fingerprint(NEW.publicKey)

test('build/verify round trip: signed by old kid, verifies with old pubkey', () => {
  const m = buildRotationManifest({
    issuer:            'example.test',
    previousKid:       OLD_KID,
    previousSecretKey: OLD.secretKey,
    newKid:            NEW_KID,
    newPublicKey:      NEW.publicKey,
  })
  const r = verifyRotationManifest(m, OLD.publicKey)
  assert.equal(r.ok, true)
})

test('verify fails when verifying against the WRONG public key', () => {
  const m = buildRotationManifest({
    issuer:            'example.test',
    previousKid:       OLD_KID,
    previousSecretKey: OLD.secretKey,
    newKid:            NEW_KID,
    newPublicKey:      NEW.publicKey,
  })
  // Try verifying against the NEW pubkey (wrong — manifest was signed by OLD secret)
  const r = verifyRotationManifest(m, NEW.publicKey)
  assert.equal(r.ok, false)
  assert.equal(r.reason, 'bad_signature')
})

test('verify fails when manifest is tampered after signing', () => {
  const m = buildRotationManifest({
    issuer:            'example.test',
    previousKid:       OLD_KID,
    previousSecretKey: OLD.secretKey,
    newKid:            NEW_KID,
    newPublicKey:      NEW.publicKey,
  })
  m.issuer = 'attacker.test'   // tamper
  const r = verifyRotationManifest(m, OLD.publicKey)
  assert.equal(r.ok, false)
  assert.equal(r.reason, 'bad_signature')
})

test('verify fails on missing/empty signature value', () => {
  const m = buildRotationManifest({
    issuer:            'example.test',
    previousKid:       OLD_KID,
    previousSecretKey: OLD.secretKey,
    newKid:            NEW_KID,
    newPublicKey:      NEW.publicKey,
  })
  const m2 = { ...m, signature: { ...m.signature, value: '' } }
  const r = verifyRotationManifest(m2, OLD.publicKey)
  assert.equal(r.ok, false)
  assert.equal(r.reason, 'no_signature')
})

test('verify rejects unsupported version', () => {
  const m = buildRotationManifest({
    issuer:            'example.test',
    previousKid:       OLD_KID,
    previousSecretKey: OLD.secretKey,
    newKid:            NEW_KID,
    newPublicKey:      NEW.publicKey,
  })
  const r = verifyRotationManifest({ ...m, version: '2.0' }, OLD.publicKey)
  assert.equal(r.ok, false)
  assert.equal(r.reason, 'unsupported_version')
})

test('verify rejects wrong manifest type', () => {
  const m = buildRotationManifest({
    issuer:            'example.test',
    previousKid:       OLD_KID,
    previousSecretKey: OLD.secretKey,
    newKid:            NEW_KID,
    newPublicKey:      NEW.publicKey,
  })
  const r = verifyRotationManifest({ ...m, manifestType: 'revocation' }, OLD.publicKey)
  assert.equal(r.ok, false)
  assert.equal(r.reason, 'wrong_type')
})

test('verify rejects signature whose kid does not match previousKid', () => {
  const m = buildRotationManifest({
    issuer:            'example.test',
    previousKid:       OLD_KID,
    previousSecretKey: OLD.secretKey,
    newKid:            NEW_KID,
    newPublicKey:      NEW.publicKey,
  })
  const r = verifyRotationManifest({ ...m, signature: { ...m.signature, kid: 'deadbeefdeadbeef' } }, OLD.publicKey)
  assert.equal(r.ok, false)
  assert.equal(r.reason, 'signature_kid_mismatch')
})

test('build is deterministic for a given effectiveAt + inputs', () => {
  const fixed = '2026-05-22T00:00:00.000Z'
  const a = buildRotationManifest({
    issuer: 'x.test', previousKid: OLD_KID, previousSecretKey: OLD.secretKey,
    newKid: NEW_KID, newPublicKey: NEW.publicKey, effectiveAt: fixed,
  })
  const b = buildRotationManifest({
    issuer: 'x.test', previousKid: OLD_KID, previousSecretKey: OLD.secretKey,
    newKid: NEW_KID, newPublicKey: NEW.publicKey, effectiveAt: fixed,
  })
  // ML-DSA-65 signatures are deterministic for a given secret + message
  assert.equal(a.signature.value, b.signature.value)
})

test('build rejects missing required fields', () => {
  assert.throws(
    () => buildRotationManifest({ previousKid: OLD_KID, previousSecretKey: OLD.secretKey, newKid: NEW_KID, newPublicKey: NEW.publicKey }),
    /issuer is required/,
  )
})
