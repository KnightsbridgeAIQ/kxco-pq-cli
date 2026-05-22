// `kxco-pq fingerprint <pubkey-hex | @file>` — print the kid for a given pubkey.
// Useful for confirming a kid out-of-band without spinning up Node code.

import { fingerprint as fp } from 'kxco-post-quantum'
import { readHexInput } from '../util.js'

export async function fingerprint(args) {
  if (args.length !== 1) throw new Error('fingerprint: takes exactly one positional argument (hex or @file)')
  const input = args[0]
  if (input === '--help' || input === '-h') {
    process.stdout.write('Usage: kxco-pq fingerprint <pubkey-hex | @file>\n')
    return 0
  }
  const bytes = readHexInput(input, 'public key')
  if (bytes.length !== 1952) {
    throw new Error(`fingerprint: ML-DSA-65 public key must be 1952 bytes (got ${bytes.length})`)
  }
  process.stdout.write(fp(bytes) + '\n')
  return 0
}
