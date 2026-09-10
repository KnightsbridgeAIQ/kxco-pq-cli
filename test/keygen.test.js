import { test }   from 'node:test'
import assert      from 'node:assert/strict'
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs'
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

test('a secret on the command line warns; the @file form does not', async (t) => {
  const { readHexInput } = await import('../src/util.js')

  // Spy on emitWarning rather than listening for 'warning': the event is
  // process-wide, so other tests in this file would land in the same bucket.
  const seen = []
  const original = process.emitWarning
  process.emitWarning = (message, name) => { seen.push({ message, name }) }
  t.after(() => { process.emitWarning = original })

  const hex = 'ab'.repeat(32)
  const dir  = mkdtempSync(join(tmpdir(), 'kxco-cli-'))
  const file = join(dir, 'master.hex')
  writeFileSync(file, hex)
  t.after(() => rmSync(dir, { recursive: true, force: true }))

  readHexInput(hex, 'master', { secret: true })   // literal secret: warns
  readHexInput(hex, 'public key')                 // not secret: silent
  readHexInput('@' + file, 'master', { secret: true })  // the safe form: silent

  assert.equal(seen.length, 1)
  assert.equal(seen[0].name, 'KxcoSecretOnCommandLine')
  assert.match(seen[0].message, /shell history/)
  assert.match(seen[0].message, /--master @\/path\/to\/file/)
})
