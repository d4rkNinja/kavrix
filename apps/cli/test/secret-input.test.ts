import { PassThrough, Writable } from 'node:stream';
import { describe, expect, it, vi } from 'vitest';

import { CliUsageError, NodeSecretInput, SECRET_INPUT_OPTIONS } from '../src/index.js';

describe('secure secret acquisition', () => {
  it('reads one explicitly requested stdin value and removes only its line ending', async () => {
    const input = new PassThrough();
    const output = capture();
    const secrets = new NodeSecretInput(input, output.stream);
    input.end('  keep surrounding spaces  \r\n');
    await expect(secrets.read({ kind: 'passphrase', fromStdin: true })).resolves.toBe(
      '  keep surrounding spaces  ',
    );
    await expect(
      secrets.read({ kind: 'portable-key', fromStdin: true }),
    ).rejects.toThrow('Standard input can supply only one secret per command.');
    expect(output.value()).toBe('');
  });

  it('rejects implicit redirected input, multiple lines, NUL, and invalid UTF-8', async () => {
    const redirected = new NodeSecretInput(new PassThrough(), capture().stream);
    await expect(redirected.read({ kind: 'invite', fromStdin: false })).rejects.toThrow(
      'requires a terminal',
    );

    for (const bytes of [
      Buffer.from('first\nsecond\n'),
      Buffer.from('value\0\n'),
      Buffer.from([0xff, 0x0a]),
    ]) {
      const input = new PassThrough();
      const secrets = new NodeSecretInput(input, capture().stream);
      input.end(bytes);
      await expect(
        secrets.read({ kind: 'invite', fromStdin: true }),
      ).rejects.toBeInstanceOf(CliUsageError);
    }
  });

  it('uses raw, non-echoing terminal input and restores terminal state', async () => {
    const input = new FakeTty();
    const output = capture();
    const secrets = new NodeSecretInput(input, output.stream);
    const pending = secrets.read({ kind: 'portable-key', fromStdin: false });
    input.write(Buffer.from('abcX\u007fZ\r'));
    await expect(pending).resolves.toBe('abcZ');
    expect(input.rawTransitions).toEqual([true, false]);
    expect(output.value()).toBe('Enter portable-key (input hidden): \n');
    expect(output.value()).not.toContain('abcZ');
  });

  it('cancels masked input without disclosing what was entered', async () => {
    const input = new FakeTty();
    const output = capture();
    const secrets = new NodeSecretInput(input, output.stream);
    const pending = secrets.read({ kind: 'invite', fromStdin: false });
    input.write(Buffer.from([0x73, 0x65, 0x63, 0x72, 0x65, 0x74, 0x03]));
    await expect(pending).rejects.toThrow('cancelled');
    expect(output.value()).not.toContain('secret');
    expect(input.rawTransitions).toEqual([true, false]);
  });

  it('fails closed and detaches listeners when raw-mode entry throws', async () => {
    const input = new FakeTty({ throwOnRawMode: true });
    const output = capture();
    const pending = new NodeSecretInput(input, output.stream).read({
      kind: 'passphrase',
      fromStdin: false,
    });

    await expectGenericSecretFailure(pending, 'private raw-mode true detail');
    expect(input.rawTransitions).toEqual([true, false]);
    expect(input.pauseCalls).toBe(1);
    expectMaskedListenersRemoved(input);
    expect(output.value()).toBe('Enter passphrase (input hidden): \n');

    input.write('later\r');
    input.emit('end');
    input.on('error', () => undefined);
    input.emit('error', new Error('later private stream detail'));
    expect(input.rawTransitions).toEqual([true, false]);
    expect(input.pauseCalls).toBe(1);
  });

  it('aggregates completion cleanup failures, wipes bytes, and settles once', async () => {
    const input = new FakeTty({ throwOnRawMode: false, throwOnPause: true });
    const output = capture({ throwOnWrite: 2 });
    let ownedResult: Uint8Array<ArrayBuffer> | undefined;
    const from = vi.spyOn(Uint8Array, 'from').mockImplementation(((
      values: Iterable<number>,
    ) => {
      ownedResult = new Uint8Array([...values]);
      return ownedResult;
    }) as typeof Uint8Array.from);
    const pending = new NodeSecretInput(input, output.stream).read({
      kind: 'portable-key',
      fromStdin: false,
    });

    input.write('private-cleanup-canary\r');
    const error = await expectGenericSecretFailure(pending, [
      'private-cleanup-canary',
      'private raw-mode false detail',
      'private pause detail',
      'private output failure detail',
    ]);
    expect(error).toBeInstanceOf(AggregateError);
    expect(input.rawTransitions).toEqual([true, false]);
    expect(input.pauseCalls).toBe(1);
    expect(output.writeCalls()).toBe(2);
    expectMaskedListenersRemoved(input);
    expect(ownedResult).toBeDefined();
    if (ownedResult === undefined) throw new Error('Missing owned result buffer.');
    expect([...ownedResult]).toEqual(
      Array.from({ length: ownedResult.byteLength }, () => 0),
    );

    input.write('later\r');
    input.emit('end');
    expect(input.rawTransitions).toEqual([true, false]);
    expect(input.pauseCalls).toBe(1);
    expect(output.writeCalls()).toBe(2);
    from.mockRestore();
  });

  it('restores raw mode when pausing fails and rejects without secret detail', async () => {
    const input = new FakeTty({ throwOnPause: true });
    const output = capture();
    const pending = new NodeSecretInput(input, output.stream).read({
      kind: 'invite',
      fromStdin: false,
    });

    input.write('private-pause-detail\r');
    await expectGenericSecretFailure(pending, [
      'private-pause-detail',
      'private pause detail',
    ]);
    expect(input.rawTransitions).toEqual([true, false]);
    expect(input.pauseCalls).toBe(1);
    expectMaskedListenersRemoved(input);
    expect(output.value()).toBe('Enter invite (input hidden): \n');
  });

  it('fails closed when initial prompt output throws', async () => {
    const input = new FakeTty();
    const output = capture({ throwOnWrite: 1 });
    const pending = new NodeSecretInput(input, output.stream).read({
      kind: 'passphrase',
      fromStdin: false,
    });

    await expectGenericSecretFailure(pending, 'private output failure detail');
    expect(input.rawTransitions).toEqual([false]);
    expect(input.pauseCalls).toBe(1);
    expectMaskedListenersRemoved(input);
    expect(output.writeCalls()).toBe(2);
  });

  it('fails closed on terminal end, stream errors, empty input, and oversized input', async () => {
    const ended = new FakeTty();
    const endedRead = new NodeSecretInput(ended, capture().stream).read({
      kind: 'invite',
      fromStdin: false,
    });
    ended.end();
    await expect(endedRead).rejects.toThrow('ended before a value');

    const failed = new FakeTty();
    const failedRead = new NodeSecretInput(failed, capture().stream).read({
      kind: 'invite',
      fromStdin: false,
    });
    failed.destroy(new Error('private stream detail'));
    await expect(failedRead).rejects.toThrow('could not be read');

    const empty = new PassThrough();
    const emptyRead = new NodeSecretInput(empty, capture().stream).read({
      kind: 'invite',
      fromStdin: true,
    });
    empty.end('\n');
    await expect(emptyRead).rejects.toThrow('exactly one non-empty value');

    const oversized = new PassThrough();
    const oversizedRead = new NodeSecretInput(oversized, capture().stream).read({
      kind: 'passphrase',
      fromStdin: true,
    });
    oversized.end(Buffer.alloc(1_048_579, 0x61));
    await expect(oversizedRead).rejects.toThrow('exceeds the supported size');
  });

  it('bounds framed input and rejects terminal/EOF contract misuse', async () => {
    const terminal = new FakeTty();
    const terminalSecrets = new NodeSecretInput(terminal, capture().stream);
    await expect(
      terminalSecrets.readBatch({
        kinds: ['portable-key'],
        fromStdin: false,
        requireEnd: true,
      }),
    ).rejects.toThrow('cannot require standard-input EOF');

    const oversized = new PassThrough();
    const framed = new NodeSecretInput(oversized, capture().stream);
    const pending = framed.readBatch({
      kinds: ['portable-key'],
      fromStdin: true,
      requireEnd: true,
    });
    oversized.end(Buffer.alloc(1_048_579, 0x61));
    await expect(pending).rejects.toThrow('exceeds the supported size');

    const chunked = new PassThrough();
    const chunkedFrames = new NodeSecretInput(chunked, capture().stream);
    const chunkedPending = chunkedFrames.readBatch({
      kinds: ['portable-key'],
      fromStdin: true,
      requireEnd: true,
    });
    chunked.write(Buffer.alloc(600_000, 0x61));
    await new Promise<void>((resolve) => {
      setImmediate(resolve);
    });
    chunked.write(Buffer.alloc(500_000, 0x61));
    await expect(chunkedPending).rejects.toThrow('exceeds the supported size');
    chunked.destroy();
  });

  it('handles a multibyte backspace and a hidden empty terminal submission', async () => {
    const input = new FakeTty();
    const secrets = new NodeSecretInput(input, capture().stream);
    const pending = secrets.read({ kind: 'passphrase', fromStdin: false });
    input.write(
      Buffer.concat([Buffer.from('é'), Buffer.from([0x7f]), Buffer.from('x\r')]),
    );
    await expect(pending).resolves.toBe('x');

    const empty = new FakeTty();
    const emptyPending = new NodeSecretInput(empty, capture().stream).read({
      kind: 'passphrase',
      fromStdin: false,
    });
    empty.write('\r');
    await expect(emptyPending).rejects.toThrow('exactly one non-empty value');
  });

  it('defines stdin switches rather than secret-value flags', () => {
    expect(SECRET_INPUT_OPTIONS.passphrase.flag).toBe('--passphrase-stdin');
    expect(SECRET_INPUT_OPTIONS.portableKey.flag).toBe('--portable-key-stdin');
    expect(SECRET_INPUT_OPTIONS.invite.flag).toBe('--invite-stdin');
    expect(SECRET_INPUT_OPTIONS.totpSeed.flag).toBe('--secret-stdin');
    const serialized = JSON.stringify(SECRET_INPUT_OPTIONS);
    expect(serialized).not.toMatch(/--(?:passphrase|portable-key|invite|secret)["' ]/u);
  });
});

class FakeTty extends PassThrough {
  public readonly isTTY = true;
  public isRaw = false;
  public readonly rawTransitions: boolean[] = [];
  public pauseCalls = 0;
  readonly #throwOnRawMode: boolean | undefined;
  readonly #throwOnPause: boolean;

  constructor(
    options: {
      throwOnRawMode?: boolean;
      throwOnPause?: boolean;
    } = {},
  ) {
    super();
    this.#throwOnRawMode = options.throwOnRawMode;
    this.#throwOnPause = options.throwOnPause ?? false;
  }

  public setRawMode(enabled: boolean): void {
    this.isRaw = enabled;
    this.rawTransitions.push(enabled);
    if (enabled === this.#throwOnRawMode) {
      throw new Error(`private raw-mode ${String(enabled)} detail`);
    }
  }

  public override pause(): this {
    this.pauseCalls += 1;
    if (this.#throwOnPause) throw new Error('private pause detail');
    return super.pause();
  }
}

type CapturedWritable = Readonly<{
  stream: Writable;
  value: () => string;
  writeCalls: () => number;
}>;

function capture(options: { throwOnWrite?: number } = {}): CapturedWritable {
  let content = '';
  let writeCalls = 0;
  const stream = new Writable({
    write(chunk, _encoding, callback) {
      content += Buffer.from(chunk).toString('utf8');
      callback();
    },
  });
  const write = stream.write.bind(stream);
  stream.write = ((...arguments_: Parameters<Writable['write']>) => {
    writeCalls += 1;
    if (writeCalls === options.throwOnWrite) {
      throw new Error('private output failure detail');
    }
    return write(...arguments_);
  }) as Writable['write'];
  return { stream, value: () => content, writeCalls: () => writeCalls };
}

function expectMaskedListenersRemoved(input: FakeTty): void {
  expect(input.listenerCount('data')).toBe(0);
  expect(input.listenerCount('end')).toBe(0);
  expect(input.listenerCount('error')).toBe(0);
}

async function expectGenericSecretFailure(
  pending: Promise<unknown>,
  privateDetails: string | readonly string[],
): Promise<unknown> {
  const error = await pending.catch((caught: unknown) => caught);
  const text = collectErrorText(error);
  expect(error).toBeInstanceOf(Error);
  for (const privateDetail of typeof privateDetails === 'string'
    ? [privateDetails]
    : privateDetails) {
    expect(text).not.toContain(privateDetail);
  }
  expect(text).toContain('Secret input');
  return error;
}

function collectErrorText(error: unknown): string {
  if (!(error instanceof Error)) return String(error);
  const nested = error instanceof AggregateError ? error.errors : [];
  return [error.name, error.message, ...nested.map(collectErrorText)].join('\n');
}
