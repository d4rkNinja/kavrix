import { PassThrough, Writable } from 'node:stream';

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

function tty(initialRaw = false): TtyHarness {
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
  const output = new Writable({
    write(chunk, _encoding, callback) {
      chunks.push(Buffer.from(chunk).toString('utf8'));
      callback();
    },
  }) as Writable & { isTTY: boolean };
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
