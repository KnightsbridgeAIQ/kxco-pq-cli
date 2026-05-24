// `kxco-pq attest sign`   — sign a file with ML-DSA-65, emit JSON attestation
// `kxco-pq attest verify` — verify a JSON attestation against a public key

import { readFileSync, writeFileSync } from 'node:fs'
import { attest as attestLib, verify as verifyLib } from 'kxco-pq-attest'
import { parseFlags } from '../cli.js'
import { readHexInput } from '../util.js'

const SIGN_FLAGS   = new Set(['secret-key', 'public-key', 'file', 'out'])
const VERIFY_FLAGS = new Set(['public-key', 'attestation'])

const USAGE =
  `Usage:\n` +
  `  kxco-pq attest sign   --secret-key <hex|@file> --public-key <hex|@file> --file <path> [--out <path>]\n` +
  `  kxco-pq attest verify --public-key <hex|@file> --attestation <path>\n`

export async function attest(args) {
  const [sub, ...rest] = args
  if (sub === 'sign')   return sign(rest)
  if (sub === 'verify') return doVerify(rest)
  process.stderr.write(`kxco-pq attest: unknown subcommand '${sub ?? ''}'\n\n${USAGE}`)
  return 2
}

async function sign(args) {
  const flags = parseFlags(args, SIGN_FLAGS)
  for (const r of ['secret-key', 'public-key', 'file']) {
    if (!flags[r]) throw new Error(`attest sign: --${r} is required`)
  }

  const secretKey = readHexInput(flags['secret-key'], 'secret-key')
  const publicKey = readHexInput(flags['public-key'], 'public-key')
  const payload   = readFileSync(flags.file)
  const envelope  = attestLib(payload, { secretKey, publicKey })
  const json      = JSON.stringify(envelope, null, 2) + '\n'

  if (flags.out) {
    writeFileSync(flags.out, json, 'utf-8')
    process.stdout.write(`kxco-pq attest sign: wrote attestation to ${flags.out}\n`)
  } else {
    process.stdout.write(json)
  }
  return 0
}

async function doVerify(args) {
  const flags = parseFlags(args, VERIFY_FLAGS)
  for (const r of ['public-key', 'attestation']) {
    if (!flags[r]) throw new Error(`attest verify: --${r} is required`)
  }

  const publicKey = readHexInput(flags['public-key'], 'public-key')
  const envelope  = JSON.parse(readFileSync(flags.attestation, 'utf-8'))
  const result    = verifyLib(envelope, publicKey)

  if (!result.valid) {
    process.stderr.write(`kxco-pq attest verify: INVALID — ${result.error}\n`)
    return 1
  }

  process.stdout.write(`kxco-pq attest verify: VALID\n`)
  process.stdout.write(`  signer kid:  ${result.signerKid}\n`)
  process.stdout.write(`  issued at:   ${result.issuedAt}\n`)
  process.stdout.write(`  payload:     ${result.payload.length} bytes\n`)
  return 0
}
