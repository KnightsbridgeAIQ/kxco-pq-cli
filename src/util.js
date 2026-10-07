// Shared helpers for command modules.

import { readFileSync } from 'node:fs'
import { mlDsa, mlDsa87 } from 'kxco-post-quantum'

/**
 * The two ML-DSA parameter sets this CLI handles. The key decides which one is
 * in play: a key's length names its set, and the set picks the wrapper module.
 * ML-DSA-87 is the default where `keygen` makes a new key without one being
 * asked for. An existing key always keeps its own set: `rotate` keeps the old
 * key's set for the new key unless `--algorithm` names one, and signing uses
 * the set the secret key belongs to.
 */
export const DSA = Object.freeze({
  'ml-dsa-65': Object.freeze({ module: mlDsa,   publicKeyBytes: 1952, secretKeyBytes: 4032, signatureBytes: 3309 }),
  'ml-dsa-87': Object.freeze({ module: mlDsa87, publicKeyBytes: 2592, secretKeyBytes: 4896, signatureBytes: 4627 }),
})
export const DEFAULT_DSA = 'ml-dsa-87'

/** The set a public key of this length belongs to, or null for neither. */
export function dsaForPublicKey(bytes) {
  for (const [name, set] of Object.entries(DSA)) if (bytes.length === set.publicKeyBytes) return name
  return null
}

/** The set a secret key of this length belongs to, or null for neither. */
export function dsaForSecretKey(bytes) {
  for (const [name, set] of Object.entries(DSA)) if (bytes.length === set.secretKeyBytes) return name
  return null
}

/**
 * Read an `--algorithm` flag: one of the DSA names, or `fallback` when absent.
 *
 * @param {string|undefined} value
 * @param {string} fallback
 * @param {string} command  only for the error message
 */
export function readAlgorithmFlag(value, fallback, command) {
  const name = value ?? fallback
  if (!Object.hasOwn(DSA, name)) {
    throw new Error(`${command}: --algorithm must be ml-dsa-65 or ml-dsa-87 (got ${name})`)
  }
  return name
}

/**
 * Resolve a `--flag <value>` that accepts either a raw hex string or `@/path/to/file`.
 * Returns a Buffer of the decoded bytes.
 *
 * Prefer the `@path` form for anything secret. A value typed on the command
 * line is recorded in shell history and is readable from the process table by
 * every other user on the machine for as long as the command runs. The file
 * form keeps it out of both.
 *
 * @param {string} input
 * @param {string} fieldName    — only for error messages
 * @param {{ secret?: boolean }} [opts] — when true, a literal value warns
 * @returns {Buffer}
 */
export function readHexInput(input, fieldName, opts = {}) {
  if (opts.secret && typeof input === 'string' && !input.startsWith('@')) {
    process.emitWarning(
      `${fieldName} was given on the command line. It is now in your shell ` +
      'history and was readable from the process table while this ran. Pass ' +
      `--${fieldName.replace(/ /g, '-')} @/path/to/file instead.`,
      'KxcoSecretOnCommandLine',
    )
  }
  return readHexInputInner(input, fieldName)
}

function readHexInputInner(input, fieldName) {
  if (typeof input !== 'string' || input.length === 0) {
    throw new Error(`${fieldName}: empty input`)
  }
  let hex
  if (input.startsWith('@')) {
    const path = input.slice(1)
    hex = readFileSync(path, 'utf-8').trim()
  } else {
    hex = input.trim()
  }
  if (!/^[0-9a-fA-F]+$/.test(hex)) {
    throw new Error(`${fieldName}: not a hex string`)
  }
  if (hex.length % 2 !== 0) {
    throw new Error(`${fieldName}: hex length must be even`)
  }
  return Buffer.from(hex, 'hex')
}

/**
 * Same as readHexInput but returns the hex string directly (no decode).
 * Used when downstream APIs want hex anyway.
 *
 * @param {string} input
 * @param {string} fieldName
 * @returns {string}
 */
export function readHexInputAsString(input, fieldName) {
  return readHexInput(input, fieldName).toString('hex')
}
