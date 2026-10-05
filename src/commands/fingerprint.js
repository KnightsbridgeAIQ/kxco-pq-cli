// `kxco-pq fingerprint <pubkey-hex | @file>` — print the kid for a given pubkey.
// Useful for confirming a kid out-of-band without spinning up Node code.

import { fingerprint as fp } from 'kxco-post-quantum'
import { readHexInput, dsaForPublicKey } from '../util.js'

export async function fingerprint(args) {
  if (args.length !== 1) throw new Error('fingerprint: takes exactly one positional argument (hex or @file)')
  const input = args[0]
  if (input === '--help' || input === '-h') {
    process.stdout.write('Usage: kxco-pq fingerprint <pubkey-hex | @file>\n')
    return 0
  }
  const bytes = readHexInput(input, 'public key')
  if (dsaForPublicKey(bytes) === null) {
    throw new Error(
      `fingerprint: an ML-DSA public key must be 1952 bytes (ML-DSA-65) or 2592 bytes (ML-DSA-87) (got ${bytes.length})`,
    )
  }
  process.stdout.write(fp(bytes) + '\n')
  return 0
}
