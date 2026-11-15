import { describe, it, expect } from 'vitest'
import { jcs, payloadHashOf } from '../src/verify'

describe('jcs refuses values that are not plain data', () => {
  it('refuses a Date', () => {
    expect(() => payloadHashOf({ when: new Date(0) })).toThrow('only plain objects')
  })
  it('refuses a Map', () => {
    expect(() => jcs({ m: new Map([['a', 1]]) })).toThrow('only plain objects')
  })
  it('refuses a Set', () => {
    expect(() => jcs({ s: new Set([1]) })).toThrow('only plain objects')
  })
  it('refuses a class instance', () => {
    class Payment { amount = 5 }
    expect(() => jcs(new Payment())).toThrow('only plain objects')
  })
  it('refuses raw bytes', () => {
    expect(() => jcs(new Uint8Array([1]))).toThrow('only plain objects')
  })
  it('refuses a list with an empty slot', () => {
    const a = [1]
    a.length = 2
    expect(() => jcs(a)).toThrow('unsupported value type')
  })
  it('still accepts plain data, and key order does not matter', () => {
    expect(jcs({ b: 1, a: [true, null, 'x'] })).toBe('{"a":[true,null,"x"],"b":1}')
    expect(payloadHashOf({ a: 1, b: 2 })).toBe(payloadHashOf({ b: 2, a: 1 }))
  })
  it('accepts an object with no prototype', () => {
    const o = Object.create(null)
    o.a = 1
    expect(jcs(o)).toBe('{"a":1}')
  })
})
