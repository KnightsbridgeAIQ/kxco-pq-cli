import { test } from 'node:test'
import assert from 'node:assert/strict'
import { writeFileSync, mkdirSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { mlDsa } from 'kxco-post-quantum'
import { attest } from '../src/commands/attest.js'

const kp  = mlDsa.ml_dsa65.keygen()
const dir = join(tmpdir(), `kxco-pq-attest-test-${process.pid}`)
mkdirSync(dir, { recursive: true })

const secretHex = Buffer.from(kp.secretKey).toString('hex')
const publicHex = Buffer.from(kp.publicKey).toString('hex')
const payloadFile = join(dir, 'payload.txt')
writeFileSync(payloadFile, 'hello from test', 'utf-8')

test('attest sign: writes attestation to stdout', async () => {
  const out = []
  const orig = process.stdout.write.bind(process.stdout)
  process.stdout.write = (d) => { out.push(d); return true }
  try {
    const code = await attest(['sign',
      '--secret-key', secretHex,
      '--public-key', publicHex,
      '--file', payloadFile,
    ])
    assert.equal(code, 0)
    const json = JSON.parse(out.join(''))
    // v2 since kxco-pq-cli 2.0.0: `signature` became `sig`, and `alg` and the
    // anchor are inside the signed message.
    assert.equal(json['kxco-attest'], '2')
    assert.ok(typeof json.sig === 'string')
    assert.equal(json.alg, 'ML-DSA-65')
  } finally {
    process.stdout.write = orig
  }
})

test('attest sign: writes attestation to --out file', async () => {
  const outFile = join(dir, 'attestation.json')
  const code = await attest(['sign',
    '--secret-key', secretHex,
    '--public-key', publicHex,
    '--file', payloadFile,
    '--out', outFile,
  ])
  assert.equal(code, 0)

  const { readFileSync } = await import('node:fs')
  const json = JSON.parse(readFileSync(outFile, 'utf-8'))
  assert.equal(json['kxco-attest'], '2')

  const verifyCode = await attest(['verify',
    '--public-key', publicHex,
    '--attestation', outFile,
  ])
  assert.equal(verifyCode, 0)
})

test('attest verify: invalid attestation returns exit code 1', async () => {
  const otherKp    = mlDsa.ml_dsa65.keygen()
  const wrongKey   = Buffer.from(otherKp.publicKey).toString('hex')
  const attestFile = join(dir, 'bad.json')

  // sign with kp, verify with wrong key
  const signed = []
  const orig = process.stdout.write.bind(process.stdout)
  process.stdout.write = (d) => { signed.push(d); return true }
  await attest(['sign', '--secret-key', secretHex, '--public-key', publicHex, '--file', payloadFile])
  process.stdout.write = orig

  writeFileSync(attestFile, signed.join(''), 'utf-8')
  const code = await attest(['verify', '--public-key', wrongKey, '--attestation', attestFile])
  assert.equal(code, 1)
})

test('attest: unknown subcommand returns 2', async () => {
  const code = await attest(['bogus'])
  assert.equal(code, 2)
})

// The compatibility promise: envelopes this CLI produced before 2.0.0 must keep
// verifying, with no flag and no migration. An archive of signed files that
// stopped verifying on an upgrade would be worse than useless.
test('attest verify still reads a version 1 envelope', async () => {
  const { attest: attestLib } = await import('kxco-pq-attest')
  const v1 = await attestLib('legacy payload', kp, { version: '1' })
  assert.equal(v1['kxco-attest'], '1')
  assert.ok(typeof v1.signature === 'string', 'v1 uses `signature`, not `sig`')

  const envPath = join(dir, 'legacy-v1.json')
  writeFileSync(envPath, JSON.stringify(v1), 'utf-8')

  const code = await attest(['verify', '--public-key', publicHex, '--attestation', envPath])
  assert.equal(code, 0)
})
