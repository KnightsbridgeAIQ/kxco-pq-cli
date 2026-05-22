// Shared helpers for command modules.

import { readFileSync } from 'node:fs'

/**
 * Resolve a `--flag <value>` that accepts either a raw hex string or `@/path/to/file`.
 * Returns a Buffer of the decoded bytes.
 *
 * @param {string} input
 * @param {string} fieldName    — only for error messages
 * @returns {Buffer}
 */
export function readHexInput(input, fieldName) {
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
