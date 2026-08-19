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

  it('accepts the bounded six-frame maximum required by MongoDB-to-local migration', async () => {
    const values = [
      'mongodb://localhost/source',
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
        Array.from({ length: 7 }, () => 'label' as const),
        true,
      ),
    ).rejects.toThrow('Secret input request is invalid.');
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
