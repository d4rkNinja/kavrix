import { describe, expect, it } from 'vitest';

import {
  NdjsonDecoder,
  boundedPreview,
  safeCommandName,
  tokensMatch,
} from '../src/execution/broker-protocol.js';

describe('ndjson framing', () => {
  it('reassembles frames split across arbitrary chunk boundaries', () => {
    const decoder = new NdjsonDecoder();
    const first = decoder.push(Buffer.from('{"a":1}\n{"b":', 'utf8'));
    expect(first).toEqual(['{"a":1}']);
    const second = decoder.push(Buffer.from('2}\n{"c":3}\n', 'utf8'));
    expect(second).toEqual(['{"b":2}', '{"c":3}']);
  });

  it('holds partial frames until their newline arrives', () => {
    const decoder = new NdjsonDecoder();
    expect(decoder.push(Buffer.from('no-newline-yet', 'utf8'))).toEqual([]);
    expect(decoder.push(Buffer.from('\n', 'utf8'))).toEqual(['no-newline-yet']);
  });

  it('drops buffered bytes when a peer floods without newlines', () => {
    const decoder = new NdjsonDecoder();
    const flood = Buffer.alloc(5 * 1024 * 1024, 0x61);
    expect(decoder.push(flood)).toEqual([]);
    // The decoder recovers: subsequent well-formed frames parse normally.
    expect(decoder.push(Buffer.from('{"ok":true}\n', 'utf8'))).toEqual(['{"ok":true}']);
  });
});

describe('token comparison', () => {
  const expected = 'kavrix-session-token-value';

  it('accepts only an exact match', () => {
    expect(tokensMatch(expected, expected)).toBe(true);
    expect(tokensMatch(`${expected}x`, expected)).toBe(false);
    expect(tokensMatch('', '')).toBe(true);
  });

  it('rejects different values of identical length in constant time', () => {
    const forged = `${expected.slice(0, -1)}X`;
    expect(forged.length).toBe(expected.length);
    expect(tokensMatch(forged, expected)).toBe(false);
  });
});

describe('argv sanitization for audit previews', () => {
  it('strips control characters and bounds each entry', () => {
    expect(safeCommandName('clean')).toBe('clean');
    expect(safeCommandName(`bad${String.fromCharCode(27)}[31m`)).toBe('bad?[31m');
    expect(safeCommandName('x'.repeat(100))).toBe(`${'x'.repeat(61)}...`);
    expect(safeCommandName('')).toBe('');
  });

  it('caps previews at eight entries', () => {
    const preview = boundedPreview(['1', '2', '3', '4', '5', '6', '7', '8', '9', '10']);
    expect(preview).toHaveLength(8);
    expect(preview).toEqual(['1', '2', '3', '4', '5', '6', '7', '8']);
  });
});
