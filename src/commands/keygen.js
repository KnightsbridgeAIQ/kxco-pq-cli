// `kxco-pq keygen` — derive a deterministic ML-DSA-65 keypair from
// (master, info) and write it to disk as hex files.

import { mlDsa, fingerprint } from 'kxco-post-quantum'
import { writeFileSync, mkdirSync, existsSync } from 'node:fs'
import { join } from 'node:path'

import { parseFlags } from '../cli.js'
import { readHexInput } from '../util.js'

const FLAGS = new Set(['master', 'info', 'out-dir'])

export async function keygen(args) {
  const flags = parseFlags(args, FLAGS)
  for (const required of ['master', 'info', 'out-dir']) {
    if (!flags[required]) throw new Error(`keygen: --${required} is required`)
  }

  const master = readHexInput(flags.master, 'master')
  if (master.length !== 32) throw new Error(`keygen: --master must decode to 32 bytes (got ${master.length})`)

  const kp  = mlDsa.keypairFromMaster(master, flags.info)
  const kid = fingerprint(kp.publicKey)

  const dir = flags['out-dir']
  if (!existsSync(dir)) mkdirSync(dir, { recursive: true })

  const secretHex = Buffer.from(kp.secretKey).toString('hex')
  const publicHex = Buffer.from(kp.publicKey).toString('hex')

  writeFileSync(join(dir, 'secret-key.hex'), secretHex + '\n', { encoding: 'utf-8' })
  writeFileSync(join(dir, 'public-key.hex'), publicHex + '\n', { encoding: 'utf-8' })
  writeFileSync(join(dir, 'kid.txt'),        kid + '\n',       { encoding: 'utf-8' })

  process.stdout.write(`kxco-pq keygen: wrote keypair to ${dir}\n`)
  process.stdout.write(`  kid:         ${kid}\n`)
  process.stdout.write(`  publicKey:   ${publicHex.length} hex chars (${kp.publicKey.length} bytes)\n`)
  process.stdout.write(`  secretKey:   ${secretHex.length} hex chars (${kp.secretKey.length} bytes) — chmod 600 advised\n`)
  process.stdout.write(`  info label:  ${JSON.stringify(flags.info)}\n`)
  return 0
}
