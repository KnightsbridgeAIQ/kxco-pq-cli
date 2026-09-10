// Shared helpers for command modules.

import { readFileSync } from 'node:fs'

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
