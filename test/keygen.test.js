import { test }   from 'node:test'
import assert      from 'node:assert/strict'
import { mkdtempSync, readFileSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { mlDsa, fingerprint } from 'kxco-post-quantum'

import { keygen } from '../src/commands/keygen.js'

function captureStdout(fn) {
  const chunks = []
  const orig = process.stdout.write.bind(process.stdout)
  process.stdout.write = (chunk) => { chunks.push(String(chunk)); return true }
  return Promise.resolve(fn()).finally(() => { process.stdout.write = orig })
    .then((rc) => ({ rc, out: chunks.join('') }))
}

test('keygen: produces secret/public/kid files that match deterministic derivation', async () => {
  const dir = mkdtempSync(join(tmpdir(), 'kxco-pq-keygen-'))
  try {
    const masterHex = '00'.repeat(32)
    const { rc, out } = await captureStdout(() => keygen([
      '--master', masterHex,
      '--info', 'kxco-keygen-test-v1',
      '--out-dir', dir,
    ]))
    assert.equal(rc, 0)
    assert.match(out, /wrote keypair to/)

    const secretHex = readFileSync(join(dir, 'secret-key.hex'), 'utf-8').trim()
    const publicHex = readFileSync(join(dir, 'public-key.hex'), 'utf-8').trim()
    const kid       = readFileSync(join(dir, 'kid.txt'),        'utf-8').trim()

    // Re-derive in this test and confirm bytes match
    const kp = mlDsa.keypairFromMaster(Buffer.from(masterHex, 'hex'), 'kxco-keygen-test-v1')
    assert.equal(Buffer.from(kp.secretKey).toString('hex'), secretHex)
    assert.equal(Buffer.from(kp.publicKey).toString('hex'), publicHex)
    assert.equal(fingerprint(kp.publicKey), kid)
    assert.equal(kid.length, 16)
  } finally {
    rmSync(dir, { recursive: true, force: true })
  }
})

test('keygen: rejects missing --master', async () => {
  await assert.rejects(
    keygen(['--info', 'x', '--out-dir', '/tmp/never-used']),
    /--master is required/,
  )
})

test('keygen: rejects wrong-length master', async () => {
  await assert.rejects(
    keygen(['--master', 'aa', '--info', 'x', '--out-dir', '/tmp/never-used']),
    /must decode to 32 bytes/,
  )
})
