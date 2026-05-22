import { test }   from 'node:test'
import assert      from 'node:assert/strict'
import { mlDsa, fingerprint as fp } from 'kxco-post-quantum'

import { fingerprint } from '../src/commands/fingerprint.js'

function captureStdout(fn) {
  const chunks = []
  const orig = process.stdout.write.bind(process.stdout)
  process.stdout.write = (chunk) => { chunks.push(String(chunk)); return true }
  return Promise.resolve(fn()).finally(() => { process.stdout.write = orig })
    .then((rc) => ({ rc, out: chunks.join('') }))
}

test('fingerprint: prints the same kid that kxco-post-quantum fingerprint() computes', async () => {
  const kp  = mlDsa.keypairFromMaster(Buffer.from('00'.repeat(32), 'hex'), 'cli-fp-test')
  const hex = Buffer.from(kp.publicKey).toString('hex')
  const { rc, out } = await captureStdout(() => fingerprint([hex]))
  assert.equal(rc, 0)
  assert.equal(out.trim(), fp(kp.publicKey))
})

test('fingerprint: rejects non-hex', async () => {
  await assert.rejects(fingerprint(['not-hex']), /not a hex string/)
})

test('fingerprint: rejects wrong-length pubkey', async () => {
  await assert.rejects(fingerprint(['aabb']), /must be 1952 bytes/)
})

test('fingerprint: --help short-circuits with exit 0', async () => {
  const { rc } = await captureStdout(() => fingerprint(['--help']))
  assert.equal(rc, 0)
})
