import { PassThrough } from 'node:stream';

import { createElement } from 'react';
import { Box, Text, render } from 'ink';
import { afterEach, describe, expect, it, vi } from 'vitest';

import {
  ClickTarget,
  createMouseInput,
  MouseProvider,
  SgrMouseDecoder,
} from '../../src/app/mouse.js';

class TestInput extends PassThrough {
  readonly isTTY = true;
  isRaw = false;

  setRawMode(value: boolean): this {
    this.isRaw = value;
    return this;
  }

  ref(): this {
    return this;
  }

  unref(): this {
    return this;
  }
}

class TestOutput extends PassThrough {
  columns = 80;
  rows = 24;
  readonly isTTY = true;
}

afterEach(() => {
  vi.useRealTimers();
});

describe('SgrMouseDecoder', () => {
  it('parses split left-click and scroll reports without forwarding their bytes', () => {
    const decoder = new SgrMouseDecoder();

    expect(decoder.push('a\u001B[<0;')).toEqual({ input: 'a', events: [] });
    expect(decoder.push('4;2M')).toEqual({
      input: '',
      events: [{ type: 'click', x: 3, y: 1 }],
    });
    expect(decoder.push('\u001B[<65;4;2M')).toEqual({
      input: '',
      events: [{ type: 'scroll', x: 3, y: 1, delta: 1 }],
    });
  });

  it('filters releases, other buttons, malformed frames, and oversized frames', () => {
    const decoder = new SgrMouseDecoder();
    const oversized = `\u001B[<${'1'.repeat(60)};2;2M`;

    expect(
      decoder.push(`before\u001B[<0;2;2m\u001B[<2;2;2M\u001B[<oopsM${oversized}after`),
    ).toEqual({ input: 'beforeafter', events: [] });
  });

  it('rejects zero and unbounded coordinates', () => {
    const decoder = new SgrMouseDecoder();

    expect(decoder.push('\u001B[<0;0;1M\u001B[<0;10001;1M')).toEqual({
      input: '',
      events: [],
    });
  });

  it('does not turn modified presses into sensitive clicks', () => {
    const decoder = new SgrMouseDecoder();

    expect(
      decoder.push('\u001B[<4;2;2M\u001B[<8;2;2M\u001B[<16;2;2M\u001B[<32;2;2M'),
    ).toEqual({ input: '', events: [] });
  });

  it('preserves arbitrarily split bracketed paste while filtering embedded mouse reports', () => {
    const decoder = new SgrMouseDecoder();
    const value = 'ordinary \u2603 paste';
    const framed = `\u001B[200~${value}\u001B[<0;2;2M tail\u001B[201~`;
    let input = '';
    const events: unknown[] = [];

    for (const character of framed) {
      const decoded = decoder.push(character);
      input += decoded.input;
      events.push(...decoded.events);
    }

    expect(input).toBe(`\u001B[200~${value} tail\u001B[201~`);
    expect(events).toEqual([]);
  });

  it('quarantines a delayed mouse tail after the prefix timeout', () => {
    const decoder = new SgrMouseDecoder();

    expect(decoder.push('\u001B[<')).toEqual({ input: '', events: [] });
    expect(decoder.flushPending()).toBe('');
    expect(decoder.push('0;1;1My')).toEqual({ input: '', events: [] });
    expect(decoder.push('safe')).toEqual({ input: 'safe', events: [] });
  });

  it('closes bracketed paste while quarantining a timed-out embedded mouse tail', () => {
    const decoder = new SgrMouseDecoder();

    expect(decoder.push('\u001B[200~safe\u001B[<')).toEqual({
      input: '\u001B[200~safe',
      events: [],
    });
    expect(decoder.flushPending()).toBe('');
    expect(decoder.push('0;1;1Mdiscard\u001B[201~y')).toEqual({
      input: '\u001B[201~',
      events: [],
    });
    expect(decoder.push('\u001B[<0;1;1M')).toEqual({
      input: '',
      events: [{ type: 'click', x: 0, y: 0 }],
    });
  });
});

describe('createMouseInput', () => {
  it('preserves keyboard input, filters mouse input, and restores terminal modes', async () => {
    const input = new TestInput();
    const output = new TestOutput();
    let terminalOutput = '';
    output.on('data', (chunk: Buffer) => {
      terminalOutput += chunk.toString();
    });
    const mouse = createMouseInput({
      stdin: input as unknown as NodeJS.ReadStream,
      stdout: output as unknown as NodeJS.WriteStream,
    });
    let filtered = '';
    mouse.stdin.on('data', (chunk: Buffer) => {
      filtered += chunk.toString();
    });

    const keyboardAndPaste = 'safe\u001B[A\u001B[200~pasted text\u001B[201~';
    input.write(`${keyboardAndPaste}\u001B[<0;1;1Mtext`);
    const unicodePaste = Buffer.from('\u001B[200~snowman \u2603\u001B[201~', 'utf8');
    for (const byte of unicodePaste) {
      input.write(Buffer.from([byte]));
    }
    await new Promise((resolve) => setImmediate(resolve));
    expect(filtered).toBe(
      `${keyboardAndPaste}text\u001B[200~snowman \u2603\u001B[201~`,
    );
    expect(terminalOutput).toContain('\u001B[?1000h\u001B[?1006h');

    mouse.dispose();
    expect(terminalOutput).toContain('\u001B[?1006l\u001B[?1000l');
    expect(input.listenerCount('data')).toBe(0);
  });

  it('releases a lone Escape key after the bounded ambiguity delay', async () => {
    vi.useFakeTimers();
    const input = new TestInput();
    const output = new TestOutput();
    const mouse = createMouseInput({
      stdin: input as unknown as NodeJS.ReadStream,
      stdout: output as unknown as NodeJS.WriteStream,
    });
    let filtered = '';
    mouse.stdin.on('data', (chunk: Buffer) => {
      filtered += chunk.toString();
    });

    input.write('\u001B');
    expect(filtered).toBe('');
    await vi.advanceTimersByTimeAsync(30);
    expect(filtered).toBe('\u001B');
    mouse.dispose();
  });

  it('restores terminal modes when the input stream errors', async () => {
    const input = new TestInput();
    const output = new TestOutput();
    let terminalOutput = '';
    output.on('data', (chunk: Buffer) => {
      terminalOutput += chunk.toString();
    });
    const mouse = createMouseInput({
      stdin: input as unknown as NodeJS.ReadStream,
      stdout: output as unknown as NodeJS.WriteStream,
    });
    mouse.stdin.on('error', () => undefined);

    input.destroy(new Error('input failed'));
    await new Promise((resolve) => setImmediate(resolve));
    expect(terminalOutput).toContain('\u001B[?1006l\u001B[?1000l');
    expect(input.listenerCount('data')).toBe(0);
  });

  it('routes only the highest-priority measured target under the pointer', async () => {
    const input = new TestInput();
    const output = new TestOutput();
    const mouse = createMouseInput({
      stdin: input as unknown as NodeJS.ReadStream,
      stdout: output as unknown as NodeJS.WriteStream,
    });
    const lower = vi.fn();
    const upper = vi.fn();
    const scroll = vi.fn();
    const app = render(
      createElement(
        MouseProvider,
        { controller: mouse },
        createElement(
          Box,
          { marginLeft: 2, marginTop: 1 },
          createElement(
            ClickTarget,
            {
              onClick: lower,
              onScroll: scroll,
              width: 5,
              height: 1,
            },
            createElement(
              ClickTarget,
              {
                onClick: upper,
                priority: 1,
                width: 5,
                height: 1,
              },
              createElement(Text, null, 'upper'),
            ),
          ),
        ),
      ),
      {
        stdin: mouse.stdin,
        stdout: output as unknown as NodeJS.WriteStream,
        stderr: output as unknown as NodeJS.WriteStream,
        exitOnCtrlC: false,
        patchConsole: false,
        alternateScreen: true,
      },
    );
    await new Promise((resolve) => setImmediate(resolve));

    input.write('\u001B[<0;20;20M\u001B[<4;3;2M\u001B[<0;3;2M\u001B[<65;3;2M');
    await new Promise((resolve) => setImmediate(resolve));
    expect(lower).not.toHaveBeenCalled();
    expect(upper).toHaveBeenCalledOnce();
    expect(scroll).toHaveBeenCalledWith(1);

    app.unmount();
    mouse.dispose();
  });

  it('does not route through an ancestor overflow clip', async () => {
    const input = new TestInput();
    const output = new TestOutput();
    const mouse = createMouseInput({
      stdin: input as unknown as NodeJS.ReadStream,
      stdout: output as unknown as NodeJS.WriteStream,
    });
    const clipped = vi.fn();
    const footer = vi.fn();
    const app = render(
      createElement(
        MouseProvider,
        { controller: mouse },
        createElement(
          Box,
          { flexDirection: 'column' },
          createElement(
            Box,
            { height: 1, overflow: 'hidden' },
            createElement(
              ClickTarget,
              { onClick: clipped, width: 5, height: 3 },
              createElement(Text, null, 'body'),
            ),
          ),
          createElement(
            ClickTarget,
            { onClick: footer, width: 5, height: 1 },
            createElement(Text, null, 'foot'),
          ),
        ),
      ),
      {
        stdin: mouse.stdin,
        stdout: output as unknown as NodeJS.WriteStream,
        stderr: output as unknown as NodeJS.WriteStream,
        exitOnCtrlC: false,
        patchConsole: false,
        alternateScreen: true,
      },
    );
    await new Promise((resolve) => setImmediate(resolve));

    input.write('\u001B[<0;1;2M');
    await new Promise((resolve) => setImmediate(resolve));
    expect(clipped).not.toHaveBeenCalled();
    expect(footer).toHaveBeenCalledOnce();

    app.unmount();
    mouse.dispose();
  });
});
