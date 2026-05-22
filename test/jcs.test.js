import { test } from 'node:test'
import assert    from 'node:assert/strict'
import { canonicalize } from '../src/jcs.js'

test('jcs: sorts keys at every level', () => {
  assert.equal(
    canonicalize({ b: 1, a: 2, c: { y: 1, x: 2 } }),
    '{"a":2,"b":1,"c":{"x":2,"y":1}}',
  )
})

test('jcs: preserves array order', () => {
  assert.equal(canonicalize([3, 1, 2]), '[3,1,2]')
})

test('jcs: emits no insignificant whitespace', () => {
  const out = canonicalize({ a: 'hello world', b: [1, 2] })
  assert.equal(out, '{"a":"hello world","b":[1,2]}')
})

test('jcs: identical input → identical output (determinism)', () => {
  const a = canonicalize({ version: '1.0', kid: 'abc', list: ['x', 'y'] })
  const b = canonicalize({ list: ['x', 'y'], kid: 'abc', version: '1.0' })
  assert.equal(a, b)
})

test('jcs: rejects floats (subset limitation)', () => {
  assert.throws(() => canonicalize({ x: 1.5 }), /floats are not supported/)
})

test('jcs: rejects non-finite numbers', () => {
  assert.throws(() => canonicalize({ x: Infinity }), /non-finite/)
  assert.throws(() => canonicalize({ x: NaN }),      /non-finite/)
})

test('jcs: handles nested arrays + objects', () => {
  const v = { b: [{ y: 1, x: 2 }, { x: 3 }], a: null }
  assert.equal(canonicalize(v), '{"a":null,"b":[{"x":2,"y":1},{"x":3}]}')
})

test('jcs: handles booleans and null', () => {
  assert.equal(canonicalize({ a: true, b: false, c: null }), '{"a":true,"b":false,"c":null}')
})

test('jcs: drops undefined values from objects', () => {
  assert.equal(canonicalize({ a: 1, b: undefined }), '{"a":1}')
})

test('jcs: empty object and empty array', () => {
  assert.equal(canonicalize({}), '{}')
  assert.equal(canonicalize([]), '[]')
})
