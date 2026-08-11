import { PassThrough, Writable, type WritableOptions } from 'node:stream';

import { lifecycleOperationIdSchema } from '@kavrix/client';
import { describe, expect, it } from 'vitest';

import { CliUsageError } from '../src/errors.js';
import type { SensitiveInitializationDisplayRequest } from '../src/initialization.js';
import { NodeSensitiveInitializationDisplay } from '../src/production/sensitive-display.js';

const CLEAR = '\u001b[2J\u001b[3J\u001b[H';
const PORTABLE = 'portable-key-canary';
const RECOVERY = 'recovery-key-canary';

describe('sensitive initialization display', () => {
  it('shows only on the dedicated TTY, sanitizes hostile controls, and accepts saved', async () => {
    const terminal = tty();
    const pending = new NodeSensitiveInitializationDisplay(
      terminal.input,
      terminal.output,
    ).display(request(`${PORTABLE}\u001b[2J`, `${RECOVERY}\u001b]0;owned\u0007`));

    terminal.input.write('saved\r');
    await expect(pending).resolves.toEqual({
      acknowledged: true,
      interactiveTty: true,
    });
    expect(terminal.value()).toContain(PORTABLE);
    expect(terminal.value()).toContain(RECOVERY);
    expect(terminal.value()).not.toContain('\u001b]0;owned');
    expect(occurrences(terminal.value(), CLEAR)).toBe(2);
  });

  it('supports backspace and restores the prior raw state without listeners', async () => {
    const terminal = tty(true);
    const pending = new NodeSensitiveInitializationDisplay(
      terminal.input,
      terminal.output,
    ).display(request(PORTABLE, RECOVERY));
    terminal.input.write('saveX\u007fd\n');

    await expect(pending).resolves.toBeDefined();
    expect(terminal.rawModes).toEqual([true, true]);
    expect(terminal.input.listenerCount('data')).toBe(0);
    expect(terminal.input.listenerCount('end')).toBe(0);
    expect(terminal.input.listenerCount('error')).toBe(0);
  });

  it.each([
    ['mismatch', (input: PassThrough) => input.write('Saved\n')],
    ['Ctrl+C', (input: PassThrough) => input.write('\u0003')],
    ['end', (input: PassThrough) => input.end()],
    ['error', (input: PassThrough) => input.emit('error', new Error('canary'))],
    ['bounds', (input: PassThrough) => input.write(`${'x'.repeat(65)}\n`)],
    ['non-printable input', (input: PassThrough) => input.write('sa\u001bved\n')],
  ])('clears after %s and fails generically', async (_name, trigger) => {
    const terminal = tty();
    const pending = new NodeSensitiveInitializationDisplay(
      terminal.input,
      terminal.output,
    ).display(request(PORTABLE, RECOVERY));
    await waitFor(() => terminal.rawModes.length === 1);
    trigger(terminal.input);

    await expect(pending).rejects.toBeInstanceOf(CliUsageError);
    expect(occurrences(terminal.value(), CLEAR)).toBe(2);
    expect(terminal.rawModes.at(-1)).toBe(false);
  });

  it('refuses a non-TTY before displaying material', async () => {
    const terminal = tty();
    Object.defineProperty(terminal.input, 'isTTY', { value: false });

    await expect(
      new NodeSensitiveInitializationDisplay(terminal.input, terminal.output).display(
        request(PORTABLE, RECOVERY),
      ),
    ).rejects.toBeInstanceOf(CliUsageError);
    expect(terminal.value()).not.toContain(PORTABLE);
    expect(terminal.value()).not.toContain(RECOVERY);
  });

  it('refuses ordinary process stdout and stderr even when input is interactive', async () => {
    for (const ordinaryOutput of [process.stdout, process.stderr]) {
      const terminal = tty();
      await expect(
        new NodeSensitiveInitializationDisplay(terminal.input, ordinaryOutput).display(
          request(PORTABLE, RECOVERY),
        ),
      ).rejects.toBeInstanceOf(CliUsageError);
      expect(terminal.rawModes).toEqual([]);
    }
  });

  it('awaits delayed initial and final write callbacks before resolving', async () => {
    const callbacks: ((error?: Error | null) => void)[] = [];
    const terminal = tty(false, (_chunk, callback) => callbacks.push(callback));
    let settled = false;
    const pending = new NodeSensitiveInitializationDisplay(
      terminal.input,
      terminal.output,
    )
      .display(request(PORTABLE, RECOVERY))
      .finally(() => {
        settled = true;
      });
    terminal.input.write('saved\n');

    await nextTurn();
    expect(callbacks).toHaveLength(1);
    expect(settled).toBe(false);
    callbacks[0]?.();
    await waitFor(() => callbacks.length === 2);
    expect(settled).toBe(false);
    callbacks[1]?.();
    await expect(pending).resolves.toBeDefined();
    expect(occurrences(terminal.value(), CLEAR)).toBe(2);
    expectNoTerminalListeners(terminal);
  });

  it('attempts and awaits final clear after a synchronous initial write failure', async () => {
    let calls = 0;
    const terminal = tty(false, (chunk, callback) => {
      calls += 1;
      if (calls === 1) throw new Error('initial-write-secret-canary');
      callback();
    });

    await expect(
      new NodeSensitiveInitializationDisplay(terminal.input, terminal.output).display(
        request(PORTABLE, RECOVERY),
      ),
    ).rejects.toSatisfy(
      (error: unknown) =>
        error instanceof CliUsageError && !error.message.includes('secret-canary'),
    );
    expect(calls).toBe(2);
    expect(occurrences(terminal.value(), CLEAR)).toBe(2);
    expect(terminal.rawModes).toEqual([]);
    expectNoTerminalListeners(terminal);
  });

  it('owns asynchronous output errors and restores acknowledgement state', async () => {
    const terminal = tty();
    const pending = new NodeSensitiveInitializationDisplay(
      terminal.input,
      terminal.output,
    ).display(request(PORTABLE, RECOVERY));
    await waitFor(() => terminal.rawModes.length === 1);

    terminal.output.emit('error', new Error('output-error-secret-canary'));

    await expect(pending).rejects.toSatisfy(
      (error: unknown) =>
        error instanceof CliUsageError && !error.message.includes('secret-canary'),
    );
    expect(occurrences(terminal.value(), CLEAR)).toBe(2);
    expect(terminal.rawModes).toEqual([true, false]);
    expectNoTerminalListeners(terminal);
  });

  it('preserves acknowledgement and final-clear failures behind a generic aggregate', async () => {
    let calls = 0;
    const terminal = tty(false, (_chunk, callback) => {
      calls += 1;
      if (calls === 2) {
        callback(new Error('final-clear-secret-canary'));
        return;
      }
      callback();
    });
    const pending = new NodeSensitiveInitializationDisplay(
      terminal.input,
      terminal.output,
    ).display(request(PORTABLE, RECOVERY));
    terminal.input.write('Saved\n');

    await expect(pending).rejects.toSatisfy(
      (error: unknown) =>
        error instanceof AggregateError &&
        error.errors.length === 2 &&
        !error.message.includes('secret-canary'),
    );
    expect(calls).toBe(2);
    expect(terminal.rawModes).toEqual([true, false]);
    expectNoTerminalListeners(terminal);
  });
});

function request(
  portableKey: string,
  recoveryKey: string,
): SensitiveInitializationDisplayRequest {
  return {
    operationId: lifecycleOperationIdSchema.parse('operation.sensitive-display'),
    material: { portableKey, recoveryKey },
    requiresInteractiveTty: true as const,
    requiresExplicitAcknowledgement: true as const,
  };
}

function tty(
  initialRaw = false,
  write?: (chunk: string, callback: (error?: Error | null) => void) => void,
): TtyHarness {
  const input = new PassThrough() as PassThrough & {
    isTTY: boolean;
    isRaw: boolean;
    setRawMode(enabled: boolean): void;
  };
  input.isTTY = true;
  input.isRaw = initialRaw;
  const rawModes: boolean[] = [];
  input.setRawMode = (enabled) => {
    rawModes.push(enabled);
    input.isRaw = enabled;
  };
  const chunks: string[] = [];
  const options: WritableOptions = {
    write(chunk, _encoding, callback) {
      const text = Buffer.from(chunk).toString('utf8');
      chunks.push(text);
      if (write === undefined) callback();
      else write(text, callback);
    },
  };
  const output = new Writable(options) as Writable & { isTTY: boolean };
  if (write !== undefined) {
    output.write = ((
      chunk: string | Uint8Array,
      encodingOrCallback?: BufferEncoding | ((error?: Error | null) => void),
      callback?: (error?: Error | null) => void,
    ): boolean => {
      const text = Buffer.from(chunk).toString('utf8');
      chunks.push(text);
      const completed =
        typeof encodingOrCallback === 'function' ? encodingOrCallback : callback;
      if (completed === undefined) {
        throw new Error('Test output requires a completion callback.');
      }
      write(text, completed);
      return true;
    }) as typeof output.write;
  }
  output.isTTY = true;
  return { input, output, rawModes, value: () => chunks.join('') };
}

type TtyHarness = Readonly<{
  input: PassThrough & {
    isTTY: boolean;
    isRaw: boolean;
    setRawMode(enabled: boolean): void;
  };
  output: Writable & { isTTY: boolean };
  rawModes: boolean[];
  value(): string;
}>;

function occurrences(value: string, searched: string): number {
  return value.split(searched).length - 1;
}

function expectNoTerminalListeners(terminal: TtyHarness): void {
  expect(terminal.input.listenerCount('data')).toBe(0);
  expect(terminal.input.listenerCount('end')).toBe(0);
  expect(terminal.input.listenerCount('error')).toBe(0);
  expect(terminal.output.listenerCount('error')).toBe(0);
}

function nextTurn(): Promise<void> {
  return new Promise((resolve) => setImmediate(resolve));
}

async function waitFor(predicate: () => boolean): Promise<void> {
  for (let attempt = 0; attempt < 20; attempt += 1) {
    if (predicate()) return;
    await nextTurn();
  }
  throw new Error('Timed out waiting for deterministic test state.');
}
