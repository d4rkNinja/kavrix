import { describe, expect, it } from 'vitest';

import { SgrMouseDecoder } from '../../src/app/mouse.js';

const ESC = '\u001B';
const MAX_PASTE = 64 * 1024;
/** Longest well-formed SGR report is 19 cells; the cap only has to exceed that. */
const MAX_REPORT = 24;

describe('SgrMouseDecoder recovery guarantees', () => {
  it('recovers keyboard input after an oversized unterminated mouse prefix', () => {
    const decoder = new SgrMouseDecoder();

    decoder.push(`${ESC}[<${'0;'.repeat(30)}1`);
    expect(decoder.push('u')).toEqual({ input: 'u', events: [] });

    for (const character of 'nlock') {
      decoder.push(character);
    }

    expect(decoder.push('after')).toEqual({ input: 'after', events: [] });
  });

  it('never exceeds the report cap while quarantining a malformed frame', () => {
    const decoder = new SgrMouseDecoder();

    // Only a prefix short enough to still be a valid report can reach the
    // quarantine, which is what bounds how much keyboard input it can swallow.
    for (let index = 0; index < 20; index += 1) {
      decoder.push(`${ESC}[<0;1;1`);
      expect(decoder.flushPending()).toBe('');
      decoder.push('9'.repeat(MAX_REPORT + 10));
    }

    expect(decoder.push('recovered')).toEqual({
      input: 'recovered',
      events: [],
    });
  });

  it('delivers a click after a bracketed paste that never terminated', () => {
    const decoder = new SgrMouseDecoder();

    decoder.push(`${ESC}[200~secret`);
    decoder.push(`${ESC}[<`);
    expect(decoder.flushPending()).toBe('');
    decoder.push('0;1;1Mdiscard');

    expect(decoder.push(`${ESC}[<0;9;9M`)).toEqual({
      input: '',
      events: [{ type: 'click', x: 8, y: 8 }],
    });

    decoder.push(`${ESC}[200~unterminated`);
    decoder.push('x'.repeat(MAX_PASTE));

    expect(decoder.push(`${ESC}[<0;9;9M`)).toEqual({
      input: '',
      events: [{ type: 'click', x: 8, y: 8 }],
    });
  });

  it('bounds a single unterminated paste across many reads', () => {
    const decoder = new SgrMouseDecoder();

    decoder.push(`${ESC}[200~unterminated`);
    for (let index = 0; index < 6; index += 1) {
      decoder.push('y'.repeat(MAX_PASTE / 4));
    }

    expect(decoder.push(`${ESC}[<0;9;9M`)).toEqual({
      input: '',
      events: [{ type: 'click', x: 8, y: 8 }],
    });
  });
});

describe('SgrMouseDecoder terminal compatibility', () => {
  it('does not forward legacy X10 mouse reports as text', () => {
    const decoder = new SgrMouseDecoder();

    expect(decoder.push(`${ESC}[M\u0023\u0023\u0021`)).toEqual({
      input: '',
      events: [],
    });
    expect(decoder.push('after')).toEqual({ input: 'after', events: [] });
  });

  it('routes an X10 press as a click and an X10 wheel as a scroll', () => {
    const decoder = new SgrMouseDecoder();

    const click = decoder.push(`${ESC}[M\u0020\u0023\u0022`);
    expect(click.events).toEqual([{ type: 'click', x: 2, y: 1 }]);

    const wheel = decoder.push(`${ESC}[Ma\u0023\u0022`);
    expect(wheel.events).toEqual([{ type: 'scroll', x: 2, y: 1, delta: 1 }]);
  });

  it('keeps X10 reports split across reads from leaking into the stream', () => {
    const decoder = new SgrMouseDecoder();

    expect(decoder.push(`${ESC}[M`)).toEqual({ input: '', events: [] });
    expect(decoder.push('\u0020\u0023')).toEqual({ input: '', events: [] });
    expect(decoder.push('\u0022')).toEqual({
      input: '',
      events: [{ type: 'click', x: 2, y: 1 }],
    });
  });

  it('accepts wheel reports carrying shift, meta, or ctrl', () => {
    const decoder = new SgrMouseDecoder();

    expect(
      decoder.push(
        `${ESC}[<68;5;5M${ESC}[<72;5;5M${ESC}[<80;5;5M${ESC}[<69;5;5M${ESC}[<65;5;5M`,
      ),
    ).toEqual({
      input: '',
      events: [
        { type: 'scroll', x: 4, y: 4, delta: -1 },
        { type: 'scroll', x: 4, y: 4, delta: -1 },
        { type: 'scroll', x: 4, y: 4, delta: -1 },
        { type: 'scroll', x: 4, y: 4, delta: 1 },
        { type: 'scroll', x: 4, y: 4, delta: 1 },
      ],
    });
  });

  it('drops drag motion and extra-button reports without emitting text', () => {
    const decoder = new SgrMouseDecoder();

    expect(
      decoder.push(`${ESC}[<32;2;2M${ESC}[<128;2;2M${ESC}[<66;2;2M${ESC}[<67;2;2Mtail`),
    ).toEqual({ input: 'tail', events: [] });
  });
});

describe('SgrMouseDecoder orphaned control-sequence tails', () => {
  it('drops the tail of an arrow key that arrives after the escape window', () => {
    const decoder = new SgrMouseDecoder();

    // The escape window closed between the ESC and the rest of `ESC [ B`, so
    // Ink has already been handed a bare Escape. Forwarding `[B` would type
    // those two characters into a masked passphrase field.
    expect(decoder.push(ESC)).toEqual({ input: '', events: [] });
    expect(decoder.flushPending()).toBe(ESC);
    expect(decoder.push('[B')).toEqual({ input: '', events: [] });
  });

  it('drops the tail of a modified arrow and paged key the same way', () => {
    // The `[` is always part of the tail when only `ESC` was released.
    for (const tail of ['[A', '[1;5C', '[5~', '[H', '[3;2~']) {
      const decoder = new SgrMouseDecoder();
      decoder.push(ESC);
      decoder.flushPending();
      expect(decoder.push(tail)).toEqual({ input: '', events: [] });
    }
  });

  it('closes the ambiguity when the introducer itself was dropped', () => {
    // Releasing `ESC[` would make Ink resolve it as literal input and type a
    // stray `[` into the focused field, so it is dropped. The final byte that
    // follows is then ambiguous, and ambiguity resolves closed: exactly one byte
    // is consumed rather than typed into a masked field.
    const decoder = new SgrMouseDecoder();
    decoder.push(`${ESC}[`);
    expect(decoder.flushPending()).toBe('');
    expect(decoder.push('Brest')).toEqual({ input: 'rest', events: [] });
  });

  it('drops the parameter half of a report split after ESC[', () => {
    const decoder = new SgrMouseDecoder();
    decoder.push(`${ESC}[`);
    expect(decoder.flushPending()).toBe('');
    expect(decoder.push('<0;4;9M')).toEqual({ input: '', events: [] });
  });

  it('keeps the remainder of a split mouse report out of the text stream', () => {
    const decoder = new SgrMouseDecoder();

    decoder.push(ESC);
    decoder.flushPending();
    expect(decoder.push('[<0;4;9M')).toEqual({ input: '', events: [] });
  });

  it('still delivers a genuine Escape keypress', () => {
    const decoder = new SgrMouseDecoder();

    expect(decoder.push(ESC)).toEqual({ input: '', events: [] });
    expect(decoder.flushPending()).toBe(ESC);
  });

  it('still delivers ordinary typing that follows a released Escape', () => {
    const decoder = new SgrMouseDecoder();

    decoder.push(ESC);
    decoder.flushPending();
    expect(decoder.push('unlock')).toEqual({ input: 'unlock', events: [] });
  });

  it('does not swallow a whole typed secret after one ambiguous Escape', () => {
    const decoder = new SgrMouseDecoder();

    decoder.push(ESC);
    decoder.flushPending();
    const secret = 'correct horse battery staple';
    expect(decoder.push(secret)).toEqual({ input: secret, events: [] });
  });
});
