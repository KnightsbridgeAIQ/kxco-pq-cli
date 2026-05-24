// Router for `kxco-pq <command> [args]`. Subcommands handle their own arg
// parsing so each module is self-contained and individually testable.

import { keygen }      from './commands/keygen.js'
import { fingerprint } from './commands/fingerprint.js'
import { rotate }      from './commands/rotate.js'
import { attest }      from './commands/attest.js'

const USAGE = `kxco-pq — post-quantum key tooling for the kxco-post-quantum ecosystem

Usage:
  kxco-pq keygen      --master <hex|@file> --info <label> --out-dir <dir>
  kxco-pq fingerprint <pubkey-hex | @file>
  kxco-pq rotate      --old-secret <@file> --old-kid <hex> --new-master <hex|@file>
                      --info <label> --issuer <domain> --out-dir <dir>
                      [--previous-active-from <ISO8601>]
  kxco-pq attest sign   --secret-key <hex|@file> --public-key <hex|@file> --file <path> [--out <path>]
  kxco-pq attest verify --public-key <hex|@file> --attestation <path>

Common:
  --master / --new-master / --old-secret accept either a 64-char hex string OR
  '@/path/to/file' to read the hex from that file. Whitespace is stripped.

Output files (keygen + rotate):
  <out-dir>/secret-key.hex   (chmod 600 advised by user; CLI does not enforce)
  <out-dir>/public-key.hex
  <out-dir>/kid.txt          (16-char hex fingerprint)

Output files (rotate, in addition):
  <out-dir>/well-known.json  (publish at https://<issuer>/.well-known/kxco-pq-pubkey)
  <out-dir>/manifest.json    (RFC 8785 JCS canonical, signed by old kid)

See https://github.com/JackKXCO/kxco-post-quantum-webhook/blob/main/docs/webhook-contract.md
for the wire format the well-known + manifest documents conform to.
`

/** @param {string[]} argv */
export async function run(argv) {
  const [cmd, ...rest] = argv
  if (!cmd || cmd === '--help' || cmd === '-h') {
    process.stdout.write(USAGE)
    return 0
  }
  if (cmd === '--version' || cmd === '-v') {
    // Read from package.json at runtime — keeps source-of-truth single.
    const { default: pkg } = await import('../package.json', { with: { type: 'json' } })
    process.stdout.write(`${pkg.name} ${pkg.version}\n`)
    return 0
  }
  switch (cmd) {
    case 'keygen':      return keygen(rest)
    case 'fingerprint': return fingerprint(rest)
    case 'rotate':      return rotate(rest)
    case 'attest':      return attest(rest)
    default:
      process.stderr.write(`kxco-pq: unknown command '${cmd}'\n\n${USAGE}`)
      return 2
  }
}

/**
 * Tiny flag parser used by every subcommand. Recognises `--flag value` and
 * `--flag=value`. No GNU-style short flags; this CLI is small enough that
 * the verbosity is worth the clarity.
 *
 * @param {string[]} args
 * @param {Set<string>} expected
 * @returns {Record<string, string>}
 */
export function parseFlags(args, expected) {
  const out = {}
  for (let i = 0; i < args.length; i++) {
    const a = args[i]
    if (!a.startsWith('--')) {
      throw new Error(`unexpected positional argument '${a}' — every CLI input is a --flag`)
    }
    const eq = a.indexOf('=')
    let name, value
    if (eq >= 0) {
      name  = a.slice(2, eq)
      value = a.slice(eq + 1)
    } else {
      name  = a.slice(2)
      value = args[++i]
      if (value === undefined) throw new Error(`flag --${name} requires a value`)
    }
    if (!expected.has(name)) throw new Error(`unknown flag --${name}`)
    out[name] = value
  }
  return out
}
