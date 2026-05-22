// `kxco-pq rotate` — generate a new keypair AND a signed rotation manifest
// AND an updated well-known document. The signature on the manifest is made
// with the OUTGOING (old) secret key so receivers that already trust the old
// kid can verify the bridge.
//
// Inputs:
//   --old-secret @file   outgoing secret key (hex on disk)
//   --old-kid    <hex>   outgoing kid (16 hex chars) — also embedded in well-known/manifest
//   --new-master <hex|@file>   master for the NEW keypair
//   --info <label>             info label for the new keypair derivation
//   --issuer <domain>          publisher domain to embed in the well-known + manifest
//   --out-dir <dir>            where to write the four output files
//   --previous-active-from <ISO8601>   optional; when the OLD kid first went active.
//                                      Recorded in keys[] history. Defaults to "unknown".
//
// Outputs (all in --out-dir):
//   secret-key.hex     NEW key's secret
//   public-key.hex     NEW key's public
//   kid.txt            NEW kid
//   manifest.json      RFC 8785 JCS canonical, signed by OLD kid
//   well-known.json    Updated /.well-known/kxco-pq-pubkey doc with both keys

import { mlDsa, fingerprint } from 'kxco-post-quantum'
import { writeFileSync, mkdirSync, existsSync } from 'node:fs'
import { join } from 'node:path'

import { parseFlags } from '../cli.js'
import { readHexInput } from '../util.js'
import { buildRotationManifest } from '../manifest.js'

const FLAGS = new Set([
  'old-secret', 'old-kid', 'new-master', 'info', 'issuer', 'out-dir',
  'previous-active-from',
])

export async function rotate(args) {
  const flags = parseFlags(args, FLAGS)
  for (const required of ['old-secret', 'old-kid', 'new-master', 'info', 'issuer', 'out-dir']) {
    if (!flags[required]) throw new Error(`rotate: --${required} is required`)
  }

  // ── Load OLD key material ─────────────────────────────────────────────
  const oldSecret = readHexInput(flags['old-secret'], 'old secret key')
  if (oldSecret.length !== 4032) {
    throw new Error(`rotate: --old-secret must decode to 4032 bytes (ML-DSA-65 secret key; got ${oldSecret.length})`)
  }
  const oldKid = flags['old-kid'].trim().toLowerCase()
  if (!/^[0-9a-f]{16}$/.test(oldKid)) {
    throw new Error(`rotate: --old-kid must be 16 hex chars (got ${flags['old-kid']})`)
  }

  // The old kid's PUBLIC key is needed for the well-known. Derive it from
  // the secret: ML-DSA-65 secret keys are self-contained, so re-derivation
  // via keypairFromMaster would require the original master + info — which
  // we don't ask for. Instead, the secret key's last 1952 bytes ARE the
  // public key in the @noble/post-quantum encoding. But that's an
  // implementation detail; cleaner approach is to require the old PUBLIC key
  // as an additional flag if/when needed. For now we ALWAYS re-emit only
  // the NEW key's public material in the manifest, and the old key's pubkey
  // is whatever the receiver already trusted (out-of-band).
  //
  // The well-known doc records BOTH kids but only the NEW key's pubkey;
  // receivers fetching it for the first time after rotation can verify the
  // manifest using the previous-pubkey they were configured with, and learn
  // the new pubkey from the well-known itself. Receivers fetching for the
  // FIRST time (bootstrap) trust the new key on the strength of out-of-band
  // verification + the issuer's TLS identity.

  // ── Derive NEW keypair ─────────────────────────────────────────────────
  const newMaster = readHexInput(flags['new-master'], 'new master')
  if (newMaster.length !== 32) {
    throw new Error(`rotate: --new-master must decode to 32 bytes (got ${newMaster.length})`)
  }
  const newKp  = mlDsa.keypairFromMaster(newMaster, flags.info)
  const newKid = fingerprint(newKp.publicKey)
  if (newKid === oldKid) {
    throw new Error(`rotate: new kid equals old kid — refusing to "rotate" to the same key. Pick a different --new-master or --info.`)
  }
  const newPublicHex = Buffer.from(newKp.publicKey).toString('hex')
  const newSecretHex = Buffer.from(newKp.secretKey).toString('hex')

  // ── Build the signed rotation manifest ─────────────────────────────────
  const effectiveAt = new Date().toISOString()
  const manifest = buildRotationManifest({
    issuer:            flags.issuer,
    previousKid:       oldKid,
    previousSecretKey: oldSecret,
    newKid,
    newPublicKey:      newKp.publicKey,
    effectiveAt,
  })

  // ── Build the well-known doc ──────────────────────────────────────────
  const wellKnown = {
    version:   '1.1',
    algorithm: 'ml-dsa-65',
    issuer:    flags.issuer,
    kid:       newKid,
    publicKey: newPublicHex,
    keys: [
      {
        kid:         newKid,
        publicKey:   newPublicHex,
        status:      'active',
        activeFrom:  effectiveAt,
        activeUntil: null,
      },
      {
        kid:           oldKid,
        // publicKey omitted — receivers who already trust the old kid hold
        // the pubkey out-of-band; receivers bootstrapping after rotation
        // only need the new key. Including the old pubkey here would be
        // misleading (no signing happens with it anymore) and would also
        // require the user to pass --old-public on the CLI. Leave it out.
        status:        'retiring',
        activeUntil:   effectiveAt,
        supersededBy:  newKid,
        ...(flags['previous-active-from'] ? { activeFrom: flags['previous-active-from'] } : {}),
      },
    ],
  }

  // ── Write everything ───────────────────────────────────────────────────
  const dir = flags['out-dir']
  if (!existsSync(dir)) mkdirSync(dir, { recursive: true })
  writeFileSync(join(dir, 'secret-key.hex'),   newSecretHex + '\n', 'utf-8')
  writeFileSync(join(dir, 'public-key.hex'),   newPublicHex + '\n', 'utf-8')
  writeFileSync(join(dir, 'kid.txt'),          newKid + '\n',       'utf-8')
  writeFileSync(join(dir, 'manifest.json'),    JSON.stringify(manifest, null, 2) + '\n',   'utf-8')
  writeFileSync(join(dir, 'well-known.json'),  JSON.stringify(wellKnown, null, 2) + '\n',  'utf-8')

  process.stdout.write(`kxco-pq rotate: wrote rotation artefacts to ${dir}\n`)
  process.stdout.write(`  previous kid:    ${oldKid}  (retiring)\n`)
  process.stdout.write(`  new kid:         ${newKid}  (active)\n`)
  process.stdout.write(`  effective at:    ${effectiveAt}\n`)
  process.stdout.write(`  manifest signed by previous kid: yes (ml-dsa-65)\n`)
  process.stdout.write(`\nNext steps:\n`)
  process.stdout.write(`  1. Publish well-known.json at https://${flags.issuer}/.well-known/kxco-pq-pubkey\n`)
  process.stdout.write(`  2. Publish manifest.json at https://${flags.issuer}/.well-known/kxco-pq-rotation/${newKid}.json\n`)
  process.stdout.write(`  3. Tell receivers to add the new kid to pinnedKids[] alongside the old one\n`)
  process.stdout.write(`  4. After the drain window, retire the old kid (status: 'retired') and rotate again\n`)
  return 0
}
