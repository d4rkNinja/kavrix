import { PassThrough, Writable } from 'node:stream';

import { afterEach, describe, expect, it, vi } from 'vitest';

import { readInitStorageSelection } from '../src/local-vault-cli.js';

afterEach(() => {
  vi.useRealTimers();
});

describe('interactive init storage selection', () => {
  it.each([
    ['', 'file'],
    ['1', 'file'],
    ['2', 'mongodb'],
    ['b', 'back'],
    ['back', 'back'],
    ['q', 'cancel'],
    ['quit', 'cancel'],
    ['cancel', 'cancel'],
  ] as const)('supports the line-input fallback value %j', async (answer, expected) => {
    const { input, output } = terminal({ tty: false });

    await expect(
      readInitStorageSelection(input, output, async () => answer),
    ).resolves.toBe(expected);
  });

  it('retries an invalid line-input fallback choice', async () => {
    const { input, output, rendered } = terminal({ tty: false });
    const answers = ['invalid', '2'];

    await expect(
      readInitStorageSelection(input, output, async () => answers.shift() ?? ''),
    ).resolves.toBe('mongodb');
    expect(rendered.join('')).toContain('Choose Local encrypted file or MongoDB.');
  });

  it('uses Enter for the default raw-mode selection', async () => {
    const { input, output } = terminal();
    const selected = readInitStorageSelection(input, output);

    input.write('\r');

    await expect(selected).resolves.toBe('file');
  });

  it('accepts a down-arrow sequence split across terminal chunks', async () => {
    const { input, output, setRawMode } = terminal();
    const selected = readInitStorageSelection(input, output);

    input.write('\u001b');
    input.write('[B');
    input.write('\r');

    await expect(selected).resolves.toBe('mongodb');
    expect(setRawMode.mock.calls).toEqual([[true], [false]]);
    expect(input.listenerCount('data')).toBe(0);
    expect(input.listenerCount('end')).toBe(0);
  });

  it('processes a down-arrow and Enter delivered in one terminal chunk', async () => {
    const { input, output } = terminal();
    const selected = readInitStorageSelection(input, output);

    input.write('\u001b[B\r');

    await expect(selected).resolves.toBe('mongodb');
  });

  it('processes multiple navigation keys in one chunk and restores existing raw mode', async () => {
    const { input, output, setRawMode } = terminal({ raw: true });
    const selected = readInitStorageSelection(input, output);

    input.write('\u001b[B\u001b[Aj\r');

    await expect(selected).resolves.toBe('mongodb');
    expect(setRawMode.mock.calls).toEqual([[true], [true]]);
  });

  it('accepts an arrow sequence split into three terminal chunks', async () => {
    const { input, output } = terminal();
    const selected = readInitStorageSelection(input, output);

    input.write('\u001b');
    input.write('[');
    input.write('B\r');

    await expect(selected).resolves.toBe('mongodb');
  });

  it('supports string j/k input, ignores unknown input, and accepts Ctrl+C', async () => {
    const first = terminal();
    const selected = readInitStorageSelection(first.input, first.output);
    first.input.emit('data', '?');
    first.input.emit('data', 'j');
    first.input.emit('data', 'k');
    first.input.emit('data', 'j');
    first.input.emit('data', '\n');
    await expect(selected).resolves.toBe('mongodb');

    const second = terminal();
    const cancelled = readInitStorageSelection(second.input, second.output);
    second.input.emit('data', '\u0003');
    await expect(cancelled).resolves.toBe('cancel');
  });

  it('treats a standalone Escape as back after the sequence window', async () => {
    vi.useFakeTimers();
    const { input, output } = terminal();
    const selected = readInitStorageSelection(input, output);

    input.write('\u001b');
    await vi.advanceTimersByTimeAsync(40);

    await expect(selected).resolves.toBe('back');
  });

  it('fails closed when terminal input ends before selection', async () => {
    const { input, output, setRawMode } = terminal();
    const selected = readInitStorageSelection(input, output);

    input.end();

    await expect(selected).rejects.toThrow(
      'Storage selection ended before a choice was made.',
    );
    expect(setRawMode.mock.calls).toEqual([[true], [false]]);
  });

  it('fails closed on terminal errors and preparation failures', async () => {
    const first = terminal();
    const failedRead = readInitStorageSelection(first.input, first.output);
    first.input.emit('error', new Error('private terminal detail'));
    await expect(failedRead).rejects.toThrow('Storage selection could not be read.');

    const second = terminal({ failRawMode: true });
    await expect(readInitStorageSelection(second.input, second.output)).rejects.toThrow(
      'Storage selection could not be started.',
    );
  });

  it('preserves an input error when cleanup also fails', async () => {
    const { input, output } = terminal({ failCleanup: true });
    const selected = readInitStorageSelection(input, output);

    input.emit('error', new Error('private terminal detail'));

    await expect(selected).rejects.toThrow('Storage selection could not be read.');
  });

  it('fails closed when terminal cleanup fails after a selection', async () => {
    const { input, output } = terminal({ failCleanup: true });
    const selected = readInitStorageSelection(input, output);
    input.write('\r');

    await expect(selected).rejects.toThrow('Storage selection cleanup failed.');
  });
});

function terminal(
  options: Readonly<{
    tty?: boolean;
    raw?: boolean;
    failRawMode?: boolean;
    failCleanup?: boolean;
  }> = {},
): Readonly<{
  input: NodeJS.ReadStream;
  output: NodeJS.WriteStream;
  setRawMode: ReturnType<typeof vi.fn<(enabled: boolean) => void>>;
  rendered: readonly string[];
}> {
  const stream = new PassThrough();
  const setRawMode = vi.fn<(enabled: boolean) => void>((enabled) => {
    if (options.failRawMode === true && enabled) throw new Error('private raw failure');
    Object.defineProperty(stream, 'isRaw', { configurable: true, value: enabled });
  });
  Object.defineProperties(stream, {
    isTTY: { configurable: true, value: options.tty ?? true },
    isRaw: { configurable: true, value: options.raw ?? false },
    setRawMode: { configurable: true, value: setRawMode },
  });
  if (options.failCleanup === true) {
    const originalPause = stream.pause.bind(stream);
    let calls = 0;
    stream.pause = (() => {
      calls += 1;
      if (calls > 1) throw new Error('private cleanup failure');
      return originalPause();
    }) as typeof stream.pause;
  }
  const rendered: string[] = [];
  const output = new Writable({
    write(chunk, _encoding, callback) {
      rendered.push(String(chunk));
      callback();
    },
  });
  return {
    input: stream as unknown as NodeJS.ReadStream,
    output: output as unknown as NodeJS.WriteStream,
    setRawMode,
    rendered,
  };
}
