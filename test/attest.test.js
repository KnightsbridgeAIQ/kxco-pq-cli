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
    assert.equal(json['kxco-attest'], '1')
    assert.ok(typeof json.signature === 'string')
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
  assert.equal(json['kxco-attest'], '1')

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
