import { Readable, Writable } from 'node:stream';

import { describe, expect, it } from 'vitest';

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
      'Enter database URL (input hidden): \n' +
        'Enter passphrase (input hidden): \n' +
        'Enter passphrase (input hidden): \n',
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
      'Enter private label (input hidden): \n' +
        'Enter credential value (input hidden): \n' +
        'Enter recovery-kit passphrase (input hidden): \n' +
        'Enter new passphrase (input hidden): \n',
    );
    expect(output.text()).not.toContain('credential-secret-value');
    expect(output.text()).not.toContain('recovery passphrase value');
    expect(output.text()).not.toContain('replacement passphrase value');
  });

  it('rejects oversized masked input and clears the consumed buffer', async () => {
    const input = new TestTerminalInput();
    const output = new TestTerminalOutput();
    const reading = new LocalSecretInput(input, output).read(['field-value'], false);
    const oversized = Buffer.alloc(1_048_577, 0x61);

    input.enter(oversized);

    await expect(reading).rejects.toThrow('Secret input exceeds the supported size.');
    expect([...oversized.subarray(0, 16)]).toEqual(new Array(16).fill(0));
    expect(output.text()).not.toContain('aaaaaaaa');
    expect(input.isRaw).toBe(false);
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
    expect(output.text()).toBe('Enter passphrase (input hidden): \n');
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
    expect(output.text()).toBe('Enter database URL (input hidden): \n');
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
