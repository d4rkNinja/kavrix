import { Readable, Writable } from 'node:stream';

import { afterEach, describe, expect, it, vi } from 'vitest';

import { LocalSecretInput } from '../src/local-secrets.js';

class TestTerminalInput extends Readable {
  public isRaw: boolean;
  public readonly isTTY = true;
  public readonly rawModeChanges: boolean[] = [];
  public failPreparation = false;
  public failCleanup = false;

  public constructor(initiallyRaw = false) {
    super();
    this.isRaw = initiallyRaw;
  }

  public override _read(): void {}

  public setRawMode(enabled: boolean): void {
    if (!(this instanceof TestTerminalInput)) {
      throw new Error('setRawMode receiver was lost');
    }
    this.rawModeChanges.push(enabled);
    if (enabled && this.failPreparation) {
      this.emit('error', new Error('raw mode unavailable'));
      return;
    }
    if (!enabled && this.failCleanup) throw new Error('raw mode restore failed');
    this.isRaw = enabled;
  }

  public enter(value: string | Uint8Array): void {
    this.push(value);
  }
}

class TestTerminalOutput extends Writable {
  readonly #chunks: Buffer[] = [];
  public readonly isTTY: boolean;

  public constructor(isTTY = false) {
    super();
    this.isTTY = isTTY;
  }

  public override _write(
    chunk: Buffer,
    _encoding: BufferEncoding,
    callback: (error?: Error | null) => void,
  ): void {
    this.#chunks.push(Buffer.from(chunk));
    callback();
  }

  public text(): string {
    return Buffer.concat(this.#chunks).toString('utf8');
  }
}

function secretInput(value: string): LocalSecretInput {
  const input = Readable.from([value]);
  const output = new Writable({
    write(_chunk, _encoding, callback) {
      callback();
    },
  });
  return new LocalSecretInput(input, output);
}

async function allowNextPrompt(): Promise<void> {
  await new Promise<void>((resolve) => setImmediate(resolve));
}

afterEach(() => {
  vi.unstubAllEnvs();
});

describe('local secret input policy', () => {
  it('rejects short passphrases before key derivation', async () => {
    await expect(secretInput('too-short\n').read(['passphrase'], true)).rejects.toThrow(
      'Passphrases must contain at least 16 bytes.',
    );
  });

  it('keeps non-passphrase stdin values governed by their own validation', async () => {
    await expect(
      secretInput('mongodb://localhost\n').read(['database-url'], true),
    ).resolves.toEqual(['mongodb://localhost']);
  });

  it('keeps successful stdin framing silent and ANSI-free even for TTY output', async () => {
    vi.stubEnv('TERM', 'xterm-256color');
    vi.stubEnv('NO_COLOR', undefined);
    const output = new TestTerminalOutput(true);

    await expect(
      new LocalSecretInput(Readable.from(['private-label\n']), output).read(
        ['label'],
        true,
      ),
    ).resolves.toEqual(['private-label']);

    expect(output.text()).toBe('');
  });

  it('accepts a sufficiently long passphrase', async () => {
    await expect(
      secretInput('correct horse battery staple\n').read(['passphrase'], true),
    ).resolves.toEqual(['correct horse battery staple']);
  });

  it('accepts the bounded seven-frame maximum required by migration construction', async () => {
    const values = [
      'mongodb://localhost/source',
      'mongodb://localhost/destination',
      'source passphrase value',
      'destination passphrase',
      'destination passphrase',
      'private database label',
      'private vault label',
    ];
    await expect(
      secretInput(`${values.join('\n')}\n`).read(
        [
          'database-url',
          'database-url',
          'passphrase',
          'new-passphrase',
          'new-passphrase',
          'label',
          'label',
        ],
        true,
      ),
    ).resolves.toEqual(values);
  });

  it('rejects secret requests above the migration frame bound', async () => {
    await expect(
      secretInput('unused\n').read(
        Array.from({ length: 8 }, () => 'label' as const),
        true,
      ),
    ).rejects.toThrow('Secret input request is invalid.');
  });

  it('rejects empty secret requests before reading stdin', async () => {
    await expect(secretInput('unused\n').read([], true)).rejects.toThrow(
      'Secret input request is invalid.',
    );
  });

  it('rejects missing and surplus stdin frames without exposing their contents', async () => {
    await expect(secretInput('').read(['label'], true)).rejects.toThrow(
      'Secret input contains the wrong number of values.',
    );

    const surplus = 'private-label\nsecret-surplus-value\n';
    const error = await secretInput(surplus)
      .read(['label'], true)
      .catch((caught: unknown) => caught);
    expect(error).toBeInstanceOf(Error);
    expect(String(error)).toContain(
      'Secret input contains the wrong number of values.',
    );
    expect(String(error)).not.toContain('private-label');
    expect(String(error)).not.toContain('secret-surplus-value');
  });

  it('rejects a surplus frame arriving in a later stdin chunk', async () => {
    const input = Readable.from(['private-label\n', 'secret-surplus-value\n']);
    const output = new TestTerminalOutput();

    await expect(
      new LocalSecretInput(input, output).read(['label'], true),
    ).rejects.toThrow('Secret input contains the wrong number of values.');
    expect(output.text()).toBe('');
  });

  it('skips empty stdin chunks and rejects non-byte chunks generically', async () => {
    const emptyThenValue = {
      async *[Symbol.asyncIterator]() {
        yield new Uint8Array(0);
        yield 'private-label\n';
      },
    } as unknown as Readable;
    await expect(
      new LocalSecretInput(emptyThenValue, new TestTerminalOutput()).read(
        ['label'],
        true,
      ),
    ).resolves.toEqual(['private-label']);

    const invalid = {
      async *[Symbol.asyncIterator]() {
        yield { secret: 'must-not-be-rendered' };
      },
    } as unknown as Readable;
    await expect(
      new LocalSecretInput(invalid, new TestTerminalOutput()).read(['label'], true),
    ).rejects.toThrow('Secret input contains invalid bytes.');
  });

  it('accepts a final unterminated stdin frame and fails closed after EOF', async () => {
    const reader = secretInput('private-label');
    await expect(reader.read(['label'], true)).resolves.toEqual(['private-label']);
    await expect(reader.read(['label'], true)).rejects.toThrow(
      'Secret input contains the wrong number of values.',
    );
  });

  it('trims a stdin carriage return while rejecting empty and NUL frames', async () => {
    await expect(
      secretInput('private-label\r\n').read(['label'], true),
    ).resolves.toEqual(['private-label']);
    for (const invalid of ['\n', 'private\0label\n', 'private\rlabel\n']) {
      await expect(secretInput(invalid).read(['label'], true)).rejects.toThrow(
        'Secret input must contain exactly one value.',
      );
    }
  });

  it('rejects an oversized stdin frame without including its value in the error', async () => {
    const oversized = Buffer.alloc(1_048_577, 0x61);
    const input = Readable.from([oversized]);

    const error = await new LocalSecretInput(input, new TestTerminalOutput())
      .read(['label'], true)
      .catch((caught: unknown) => caught);
    expect(error).toBeInstanceOf(Error);
    expect(String(error)).toContain('Secret input exceeds the supported size.');
    expect(String(error)).not.toContain('aaaaaaaa');
    expect([...oversized.subarray(0, 16)]).toEqual(new Array(16).fill(0));
  });

  it('rejects malformed and partial UTF-8 stdin frames and clears consumed chunks', async () => {
    for (const malformed of [
      Buffer.from([0xc3, 0x28, 0x0a]),
      Buffer.from([0x63, 0x6f, 0x72, 0x72, 0x65, 0x63, 0x74, 0xc3]),
    ]) {
      const input = Readable.from([malformed]);
      const output = new TestTerminalOutput();
      await expect(
        new LocalSecretInput(input, output).read(['database-url'], true),
      ).rejects.toThrow('Secret input contains invalid bytes.');
      expect([...malformed]).toEqual(new Array(malformed.byteLength).fill(0));
    }
  });

  it('reads protected stdin incrementally without returning later frames early', async () => {
    const reader = secretInput(
      'mongodb://localhost/kavrix\ncorrect horse battery staple\n',
    );
    await expect(reader.read(['database-url'], true, false)).resolves.toEqual([
      'mongodb://localhost/kavrix',
    ]);
    await expect(reader.read(['passphrase'], true)).resolves.toEqual([
      'correct horse battery staple',
    ]);
  });

  it('preserves the terminal receiver and restores raw mode across sequential prompts', async () => {
    const input = new TestTerminalInput();
    const output = new TestTerminalOutput();
    const reading = new LocalSecretInput(input, output).read(
      ['database-url', 'passphrase', 'passphrase'],
      false,
    );

    input.enter('mongodb://localhost/kavrix\r');
    await allowNextPrompt();
    input.enter('correct horse battery staple\r');
    await allowNextPrompt();
    input.enter('correct horse battery staple\r');

    await expect(reading).resolves.toEqual([
      'mongodb://localhost/kavrix',
      'correct horse battery staple',
      'correct horse battery staple',
    ]);
    expect(input.rawModeChanges).toEqual([true, false, true, false, true, false]);
    expect(input.isRaw).toBe(false);
    expect(output.text()).toBe(
      '[i] Requirement: enter one non-empty line.\n' +
        '? Enter database URL (input hidden): \n' +
        '[OK] Input accepted.\n' +
        `[i] Requirement: use at least 16 UTF-8 bytes in one line.\n` +
        '? Enter passphrase (input hidden): \n' +
        '[OK] Input accepted.\n' +
        '[i] Re-enter the same passphrase to confirm it.\n' +
        '? Confirm passphrase (input hidden): \n' +
        '[OK] Input accepted.\n',
    );
    expect(output.text()).not.toContain('mongodb://localhost/kavrix');
    expect(output.text()).not.toContain('correct horse battery staple');
  });

  it('restores an input that was already in raw mode', async () => {
    const input = new TestTerminalInput(true);
    const output = new TestTerminalOutput();
    const reading = new LocalSecretInput(input, output).read(['database-url'], false);

    input.enter('mongodb://localhost\n');

    await expect(reading).resolves.toEqual(['mongodb://localhost']);
    expect(input.rawModeChanges).toEqual([true, true]);
    expect(input.isRaw).toBe(true);
  });

  it('handles UTF-8 bytes, backspace, and Windows carriage-return input without echoing', async () => {
    const input = new TestTerminalInput();
    const output = new TestTerminalOutput();
    const reading = new LocalSecretInput(input, output).read(['passphrase'], false);

    input.enter(
      Buffer.concat([Buffer.from('correct horse battery staplex'), Buffer.from([8])]),
    );
    input.enter('-密码\r');

    await expect(reading).resolves.toEqual(['correct horse battery staple-密码']);
    expect(output.text()).not.toContain('correct horse');
    expect(output.text()).not.toContain('密码');
    expect(input.isRaw).toBe(false);
  });

  it('handles string-mode terminal chunks and backspace on an empty value', async () => {
    const input = new TestTerminalInput();
    input.setEncoding('utf8');
    const output = new TestTerminalOutput();
    const reading = new LocalSecretInput(input, output).read(['passphrase'], false);

    input.enter('\bcorrect horse battery staple\r');

    await expect(reading).resolves.toEqual(['correct horse battery staple']);
    expect(output.text()).not.toContain('correct horse battery staple');
    expect(input.isRaw).toBe(false);
  });

  it('uses specific hidden labels for every masked secret kind', async () => {
    const input = new TestTerminalInput();
    const output = new TestTerminalOutput();
    const reading = new LocalSecretInput(input, output).read(
      ['label', 'field-value', 'recovery-passphrase', 'new-passphrase'],
      false,
    );

    input.enter('private-label\r');
    await allowNextPrompt();
    input.enter('credential-secret-value\r');
    await allowNextPrompt();
    input.enter('recovery passphrase value\r');
    await allowNextPrompt();
    input.enter('replacement passphrase value\r');

    await expect(reading).resolves.toEqual([
      'private-label',
      'credential-secret-value',
      'recovery passphrase value',
      'replacement passphrase value',
    ]);
    expect(output.text()).toBe(
      '[i] Requirement: use 1-256 characters after trimming whitespace.\n' +
        '? Enter private label (input hidden): \n' +
        '[OK] Input accepted.\n' +
        '[i] Requirement: enter one non-empty line.\n' +
        '? Enter credential value (input hidden): \n' +
        '[OK] Input accepted.\n' +
        '[i] Requirement: use at least 16 UTF-8 bytes in one line.\n' +
        '? Enter recovery-kit passphrase (input hidden): \n' +
        '[OK] Input accepted.\n' +
        '[i] Requirement: use at least 16 UTF-8 bytes in one line.\n' +
        '? Enter new passphrase (input hidden): \n' +
        '[OK] Input accepted.\n',
    );
    expect(output.text()).not.toContain('credential-secret-value');
    expect(output.text()).not.toContain('recovery passphrase value');
    expect(output.text()).not.toContain('replacement passphrase value');
  });

  it('shows private-label requirements and retries only that invalid field', async () => {
    const input = new TestTerminalInput();
    const output = new TestTerminalOutput();
    const reading = new LocalSecretInput(input, output).read(['label'], false);

    input.enter('   \r');
    await allowNextPrompt();
    input.enter('  valid private label  \r');

    await expect(reading).resolves.toEqual(['valid private label']);
    const transcript = output.text();
    expect(transcript).toContain(
      '[i] Requirement: use 1-256 characters after trimming whitespace.',
    );
    expect(transcript.match(/Enter private label/gu)).toHaveLength(2);
    expect(transcript).toContain(
      '[X] Private labels must contain 1-256 characters after trimming whitespace. Re-enter this field.',
    );
    expect(transcript).not.toContain('valid private label');
    expect(input.rawModeChanges).toEqual([true, false, true, false]);
    expect(input.isRaw).toBe(false);
  });

  it('rejects oversized masked input and clears the consumed buffer', async () => {
    const input = new TestTerminalInput();
    const output = new TestTerminalOutput();
    const reading = new LocalSecretInput(input, output).read(['field-value'], false);
    const oversized = Buffer.alloc(1_048_577, 0x61);

    input.enter(oversized);
    await allowNextPrompt();
    input.enter('bounded-secret-value\r');

    await expect(reading).resolves.toEqual(['bounded-secret-value']);
    expect([...oversized.subarray(0, 16)]).toEqual(new Array(16).fill(0));
    expect(output.text()).not.toContain('aaaaaaaa');
    expect(output.text()).toContain(
      '[X] Secret input exceeds the supported size. Re-enter this field.',
    );
    expect(input.isRaw).toBe(false);
  });

  it('shows passphrase requirements and retries only the locally invalid field', async () => {
    const input = new TestTerminalInput();
    const output = new TestTerminalOutput();
    const reading = new LocalSecretInput(input, output).read(
      ['label', 'new-passphrase'],
      false,
    );

    input.enter('private-label-canary\r');
    await allowNextPrompt();
    input.enter('too-short\r');
    await allowNextPrompt();
    input.enter('correct horse battery staple\r');

    await expect(reading).resolves.toEqual([
      'private-label-canary',
      'correct horse battery staple',
    ]);
    const transcript = output.text();
    expect(transcript.match(/Enter private label/gu)).toHaveLength(1);
    expect(transcript.match(/Enter new passphrase/gu)).toHaveLength(2);
    expect(transcript).toContain(
      '[X] Passphrases must contain at least 16 bytes. Re-enter this field.',
    );
    expect(transcript).not.toContain('private-label-canary');
    expect(transcript).not.toContain('too-short');
    expect(transcript).not.toContain('correct horse battery staple');
    expect(input.rawModeChanges).toEqual([true, false, true, false, true, false]);
    expect(input.isRaw).toBe(false);
  });

  it('reads a confirmed passphrase pair and retries both fields after mismatch', async () => {
    const input = new TestTerminalInput();
    const output = new TestTerminalOutput();
    const reading = new LocalSecretInput(input, output).readConfirmed('new-passphrase');

    input.enter('first passphrase value\r');
    await allowNextPrompt();
    input.enter('different passphrase value\r');
    await allowNextPrompt();
    input.enter('matching passphrase value\r');
    await allowNextPrompt();
    input.enter('matching passphrase value\r');

    await expect(reading).resolves.toEqual([
      'matching passphrase value',
      'matching passphrase value',
    ]);
    const transcript = output.text();
    expect(transcript.match(/Enter new passphrase/gu)).toHaveLength(2);
    expect(transcript.match(/Confirm new passphrase/gu)).toHaveLength(2);
    expect(transcript).toContain('[X] New passphrases do not match; re-enter both.');
    for (const secret of [
      'first passphrase value',
      'different passphrase value',
      'matching passphrase value',
    ]) {
      expect(transcript).not.toContain(secret);
    }
    expect(input.rawModeChanges).toEqual([
      true,
      false,
      true,
      false,
      true,
      false,
      true,
      false,
    ]);
    expect(input.isRaw).toBe(false);
  });

  it('retries an adjacent passphrase pair through read before continuing later fields', async () => {
    const input = new TestTerminalInput();
    const output = new TestTerminalOutput();
    const reading = new LocalSecretInput(input, output).read(
      ['label', 'new-passphrase', 'new-passphrase', 'field-value'],
      false,
    );

    const entries = [
      'private-label-canary',
      'first-passphrase-canary',
      'different-passphrase-canary',
      'matching-passphrase-canary',
      'matching-passphrase-canary',
      'credential-value-canary',
    ];
    for (const entry of entries) {
      input.enter(`${entry}\r`);
      await allowNextPrompt();
    }

    await expect(reading).resolves.toEqual([
      'private-label-canary',
      'matching-passphrase-canary',
      'matching-passphrase-canary',
      'credential-value-canary',
    ]);
    const transcript = output.text();
    expect(transcript.match(/Enter private label/gu)).toHaveLength(1);
    expect(transcript.match(/Enter new passphrase/gu)).toHaveLength(2);
    expect(transcript.match(/Confirm new passphrase/gu)).toHaveLength(2);
    expect(transcript.match(/Enter credential value/gu)).toHaveLength(1);
    expect(transcript).toContain('[X] New passphrases do not match; re-enter both.');
    for (const secret of entries) expect(transcript).not.toContain(secret);
    expect(input.isRaw).toBe(false);
  });

  it('does not retry a confirmed pair after cancellation', async () => {
    const input = new TestTerminalInput();
    const output = new TestTerminalOutput();
    const reading = new LocalSecretInput(input, output).readConfirmed('passphrase');

    input.enter(Buffer.from([3]));

    await expect(reading).rejects.toThrow('Secret entry was cancelled.');
    expect(input.rawModeChanges).toEqual([true, false]);
    expect(input.isRaw).toBe(false);
    expect(output.text()).not.toContain('do not match');
  });

  it('uses ANSI color only for an eligible TTY while preserving text signals', async () => {
    vi.stubEnv('TERM', 'xterm-256color');
    vi.stubEnv('NO_COLOR', undefined);
    const coloredInput = new TestTerminalInput();
    const coloredOutput = new TestTerminalOutput(true);
    const colored = new LocalSecretInput(coloredInput, coloredOutput).read(
      ['passphrase'],
      false,
    );
    coloredInput.enter('correct horse battery staple\r');
    await colored;

    expect(coloredOutput.text()).toMatch(/\u001b\[\d+(?:;\d+)?m/u);
    expect(coloredOutput.text()).toContain('[i]');
    expect(coloredOutput.text()).toContain('[OK]');

    vi.stubEnv('NO_COLOR', '1');
    const plainInput = new TestTerminalInput();
    const plainOutput = new TestTerminalOutput(true);
    const plain = new LocalSecretInput(plainInput, plainOutput).read(
      ['passphrase'],
      false,
    );
    plainInput.enter('correct horse battery staple\r');
    await plain;

    expect(plainOutput.text()).not.toContain('\u001b');
    expect(plainOutput.text()).toContain('[i]');
    expect(plainOutput.text()).toContain('[OK]');

    vi.stubEnv('NO_COLOR', undefined);
    vi.stubEnv('TERM', 'dumb');
    const dumbInput = new TestTerminalInput();
    const dumbOutput = new TestTerminalOutput(true);
    const dumb = new LocalSecretInput(dumbInput, dumbOutput).read(
      ['passphrase'],
      false,
    );
    dumbInput.enter('correct horse battery staple\r');
    await dumb;

    expect(dumbOutput.text()).not.toContain('\u001b');
    expect(dumbOutput.text()).toContain('[i]');
    expect(dumbOutput.text()).toContain('[OK]');
  });

  it('accepts UTF-8 split across masked chunks and clears each consumed buffer', async () => {
    const input = new TestTerminalInput();
    const output = new TestTerminalOutput();
    const reading = new LocalSecretInput(input, output).read(['passphrase'], false);
    const first = Buffer.from([
      ...new TextEncoder().encode('correct horse battery staple-'),
      0xe5,
      0xaf,
    ]);
    const second = Buffer.from([0x86, 0xe7, 0xa0, 0x81, 13]);

    input.enter(first);
    input.enter(second);

    await expect(reading).resolves.toEqual(['correct horse battery staple-密码']);
    expect([...first]).toEqual(new Array(first.byteLength).fill(0));
    expect([...second]).toEqual(new Array(second.byteLength).fill(0));
  });

  it('rejects malformed masked UTF-8 generically and clears the input buffer', async () => {
    const input = new TestTerminalInput();
    const output = new TestTerminalOutput();
    const reading = new LocalSecretInput(input, output).read(['database-url'], false);
    const malformed = Buffer.from([0xc3, 0x28, 13]);

    input.enter(malformed);

    await expect(reading).rejects.toThrow('Secret input contains invalid bytes.');
    expect([...malformed]).toEqual(new Array(malformed.byteLength).fill(0));
    expect(input.isRaw).toBe(false);
  });

  it('restores terminal state when secret entry is cancelled', async () => {
    const input = new TestTerminalInput();
    const output = new TestTerminalOutput();
    const reading = new LocalSecretInput(input, output).read(['passphrase'], false);

    const cancellation = Buffer.from([3]);
    input.enter(cancellation);

    await expect(reading).rejects.toThrow('Secret entry was cancelled.');
    expect([...cancellation]).toEqual([0]);
    expect(input.rawModeChanges).toEqual([true, false]);
    expect(input.isRaw).toBe(false);
    expect(output.text()).toBe(
      '[i] Requirement: use at least 16 UTF-8 bytes in one line.\n' +
        '? Enter passphrase (input hidden): \n',
    );
  });

  it('handles synchronous raw-mode errors and restores without exposing details', async () => {
    const input = new TestTerminalInput();
    const output = new TestTerminalOutput();
    input.failPreparation = true;

    await expect(
      new LocalSecretInput(input, output).read(['database-url'], false),
    ).rejects.toThrow('Secret input terminal preparation failed.');
    expect(input.rawModeChanges).toEqual([true, false]);
    expect(input.isRaw).toBe(false);
    expect(output.text()).toBe('');
  });

  it('reports read errors generically and restores terminal state', async () => {
    const input = new TestTerminalInput();
    const output = new TestTerminalOutput();
    const reading = new LocalSecretInput(input, output).read(['database-url'], false);

    input.emit('error', new Error('sensitive platform detail'));

    await expect(reading).rejects.toThrow('Secret input could not be read.');
    expect(input.rawModeChanges).toEqual([true, false]);
    expect(input.isRaw).toBe(false);
    expect(output.text()).not.toContain('sensitive platform detail');
  });

  it('fails closed when the input stream errors during listener cleanup', async () => {
    const input = new TestTerminalInput();
    const output = new TestTerminalOutput();
    const originalOff = input.off.bind(input);
    let injected = false;
    input.off = ((eventName, listener) => {
      const result = originalOff(eventName, listener);
      if (!injected && eventName === 'data') {
        injected = true;
        input.emit('error', new Error('cleanup stream detail must stay hidden'));
      }
      return result;
    }) as typeof input.off;
    const reading = new LocalSecretInput(input, output).read(['passphrase'], false);

    input.enter('correct horse battery staple\r');

    await expect(reading).rejects.toThrow('Secret input terminal cleanup failed.');
    expect(output.text()).not.toContain('cleanup stream detail must stay hidden');
    expect(input.isRaw).toBe(false);
  });

  it('restores terminal state when input ends before a value is entered', async () => {
    const input = new TestTerminalInput();
    const output = new TestTerminalOutput();
    const reading = new LocalSecretInput(input, output).read(['database-url'], false);

    input.push(null);

    await expect(reading).rejects.toThrow(
      'Secret input ended before a value was entered.',
    );
    expect(input.rawModeChanges).toEqual([true, false]);
    expect(input.isRaw).toBe(false);
    expect(output.text()).toBe(
      '[i] Requirement: enter one non-empty line.\n' +
        '? Enter database URL (input hidden): \n',
    );
  });

  it('fails closed when terminal state cannot be restored', async () => {
    const input = new TestTerminalInput();
    const output = new TestTerminalOutput();
    input.failCleanup = true;
    const reading = new LocalSecretInput(input, output).read(['database-url'], false);

    input.enter('mongodb://localhost\r');

    await expect(reading).rejects.toThrow('Secret input terminal cleanup failed.');
    expect(input.rawModeChanges).toEqual([true, false]);
    expect(output.text()).not.toContain('mongodb://localhost');
  });

  it('rejects a masked prompt without a terminal before writing output', async () => {
    const input = Readable.from([]);
    const output = new TestTerminalOutput();

    await expect(
      new LocalSecretInput(input, output).read(['passphrase'], false),
    ).rejects.toThrow('A masked prompt requires a terminal');
    expect(output.text()).toBe('');
  });
});
