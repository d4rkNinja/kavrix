import type { Readable, Writable } from 'node:stream';
import { TextDecoder } from 'node:util';

import { z } from 'zod';

import { CliUsageError } from './errors.js';

const MAX_SECRET_BYTES = 1_048_576;
const MAX_SECRET_FRAMES = 3;
const MAX_FRAMED_INPUT_BYTES = MAX_SECRET_FRAMES * (MAX_SECRET_BYTES + 2);

export const secretKindSchema = z.enum([
  'passphrase',
  'portable-key',
  'recovery-key',
  'totp-seed',
  'invite',
  'field-value',
]);
export const acquiredSecretSchema = z
  .string()
  .min(1)
  .max(MAX_SECRET_BYTES)
  .refine((value) => !value.includes('\0') && !/[\r\n]/u.test(value), {
    error: 'Secret input must be exactly one value',
  })
  .brand<'AcquiredSecret'>();

export type SecretKind = z.infer<typeof secretKindSchema>;
export type AcquiredSecret = z.infer<typeof acquiredSecretSchema>;
export type SecretReadRequest = Readonly<{
  kind: SecretKind;
  fromStdin: boolean;
}>;
export type SecretBatchReadRequest = Readonly<{
  kinds: readonly SecretKind[];
  fromStdin: boolean;
  /** Require EOF after the requested frames, rejecting trailing input. */
  requireEnd: boolean;
}>;

export interface SecretInputPort {
  read(request: SecretReadRequest): Promise<AcquiredSecret>;
  readBatch(request: SecretBatchReadRequest): Promise<readonly AcquiredSecret[]>;
}

export const SECRET_INPUT_OPTIONS = Object.freeze({
  passphrase: Object.freeze({
    kind: 'passphrase' as const,
    flag: '--passphrase-stdin',
    description: 'Read the passphrase from standard input (never from an argument).',
  }),
  portableKey: Object.freeze({
    kind: 'portable-key' as const,
    flag: '--portable-key-stdin',
    description: 'Read the portable key from standard input (never from an argument).',
  }),
  invite: Object.freeze({
    kind: 'invite' as const,
    flag: '--invite-stdin',
    description: 'Read the invite token from standard input (never from an argument).',
  }),
  totpSeed: Object.freeze({
    kind: 'totp-seed' as const,
    flag: '--secret-stdin',
    description: 'Read the TOTP seed from standard input (never from an argument).',
  }),
  fieldValue: Object.freeze({
    kind: 'field-value' as const,
    flag: '--value-stdin',
    description:
      'Read a credential field value from standard input (never from an argument).',
  }),
});

type SecretReadable = Readable &
  Readonly<{
    isTTY?: boolean;
    isRaw?: boolean;
    setRawMode?: (enabled: boolean) => void;
  }>;

export class NodeSecretInput implements SecretInputPort {
  readonly #input: SecretReadable;
  readonly #output: Writable;
  #stdinConsumed = false;
  #stdinFrames: IncrementalSecretFrameReader | undefined;

  constructor(input: SecretReadable, output: Writable) {
    this.#input = input;
    this.#output = output;
  }

  async read(request: SecretReadRequest): Promise<AcquiredSecret> {
    const kind = secretKindSchema.parse(request.kind);
    if (request.fromStdin) {
      if (this.#stdinConsumed || this.#stdinFrames !== undefined) {
        throw new CliUsageError(
          'Standard input can supply only one secret per command.',
        );
      }
      this.#stdinConsumed = true;
      return normalizeSecret(await readEntireStream(this.#input));
    }
    if (this.#input.isTTY !== true || this.#input.setRawMode === undefined) {
      throw new CliUsageError(
        `A masked ${secretKindLabel(kind)} prompt requires a terminal; use ${secretKindStdinFlag(kind)} explicitly.`,
      );
    }
    return normalizeSecret(
      await readMasked(this.#input, this.#output, secretKindLabel(kind)),
    );
  }

  async readBatch(request: SecretBatchReadRequest): Promise<readonly AcquiredSecret[]> {
    const kinds = z
      .array(secretKindSchema)
      .min(1)
      .max(MAX_SECRET_FRAMES)
      .parse(request.kinds);
    if (!request.fromStdin) {
      if (request.requireEnd) {
        throw new CliUsageError(
          'Terminal secret input cannot require standard-input EOF.',
        );
      }
      const values: AcquiredSecret[] = [];
      for (const kind of kinds) {
        values.push(await this.read({ kind, fromStdin: false }));
      }
      return values;
    }
    if (this.#stdinConsumed) {
      throw new CliUsageError('Standard input was already consumed.');
    }
    this.#stdinFrames ??= new IncrementalSecretFrameReader(this.#input);
    const values = await this.#stdinFrames.read(kinds.length, request.requireEnd);
    if (request.requireEnd) this.#stdinConsumed = true;
    return values;
  }
}

async function readEntireStream(input: Readable): Promise<Uint8Array> {
  const chunks: Uint8Array[] = [];
  let length = 0;
  try {
    for await (const chunk of input) {
      const bytes = copyBoundedChunk(
        chunk,
        MAX_SECRET_BYTES + 2 - length,
        'Secret input exceeds the supported size.',
      );
      length += bytes.byteLength;
      chunks.push(bytes);
    }
    return Buffer.concat(chunks, length);
  } finally {
    for (const chunk of chunks) chunk.fill(0);
  }
}

class IncrementalSecretFrameReader {
  readonly #input: Readable;
  #buffer = Buffer.alloc(0);
  #ended = false;
  #busy = false;
  #failed = false;
  #frameCount = 0;
  #receivedBytes = 0;
  #pendingFrameBytes = 0;

  constructor(input: Readable) {
    this.#input = input;
  }

  async read(count: number, requireEnd: boolean): Promise<readonly AcquiredSecret[]> {
    if (this.#busy || this.#failed || (this.#ended && this.#buffer.length === 0)) {
      throw new CliUsageError('Framed secret input is not available.');
    }
    if (this.#frameCount + count > MAX_SECRET_FRAMES) {
      throw new CliUsageError('Framed secret input has too many values.');
    }
    this.#busy = true;
    const values: AcquiredSecret[] = [];
    try {
      for (let index = 0; index < count; index += 1) {
        values.push(normalizeSecret(await this.#nextFrame()));
        this.#frameCount += 1;
      }
      if (requireEnd) await this.#requireEnd();
      return values;
    } catch (error) {
      this.#failed = true;
      this.#wipeBuffer();
      throw error;
    } finally {
      this.#busy = false;
    }
  }

  async #nextFrame(): Promise<Uint8Array> {
    for (;;) {
      this.#pullAvailable();
      const newline = this.#buffer.indexOf(0x0a);
      if (newline >= 0) {
        if (newline > MAX_SECRET_BYTES + 1) {
          throw new CliUsageError('Framed secret input exceeds the supported size.');
        }
        const frame = Buffer.from(this.#buffer.subarray(0, newline));
        const remainder = Buffer.from(this.#buffer.subarray(newline + 1));
        this.#wipeBuffer();
        this.#buffer = remainder;
        if (frame.at(-1) === 0x0d) return frame.subarray(0, -1);
        return frame;
      }
      if (this.#buffer.length > MAX_SECRET_BYTES + 1) {
        throw new CliUsageError('Framed secret input exceeds the supported size.');
      }
      if (this.#ended) {
        if (this.#buffer.length === 0) {
          throw new CliUsageError('Framed secret input ended before all values.');
        }
        const frame = Buffer.from(this.#buffer);
        this.#wipeBuffer();
        return frame;
      }
      await this.#waitForInput();
    }
  }

  async #requireEnd(): Promise<void> {
    for (;;) {
      this.#pullAvailable();
      if (this.#buffer.length !== 0) {
        throw new CliUsageError('Framed secret input contains trailing data.');
      }
      if (this.#ended) return;
      await this.#waitForInput();
    }
  }

  #pullAvailable(): void {
    let chunk: unknown;
    while ((chunk = this.#input.read()) !== null) {
      const incoming = copyBoundedChunk(
        chunk,
        MAX_FRAMED_INPUT_BYTES - this.#receivedBytes,
        'Framed secret input exceeds the supported size.',
      );
      try {
        this.#validateFrameBounds(incoming);
        this.#receivedBytes += incoming.length;
        const combined = Buffer.concat(
          [this.#buffer, incoming],
          this.#buffer.length + incoming.length,
        );
        this.#wipeBuffer();
        this.#buffer = combined;
      } finally {
        incoming.fill(0);
      }
    }
    if (this.#input.readableEnded) this.#ended = true;
  }

  #waitForInput(): Promise<void> {
    return new Promise((resolve, reject) => {
      let settled = false;
      const cleanup = (): void => {
        this.#input.off('readable', onReadable);
        this.#input.off('end', onEnd);
        this.#input.off('error', onError);
      };
      const finish = (callback: () => void): void => {
        if (settled) return;
        settled = true;
        cleanup();
        callback();
      };
      const onReadable = (): void => {
        finish(resolve);
      };
      const onEnd = (): void => {
        this.#ended = true;
        finish(resolve);
      };
      const onError = (): void => {
        finish(() => {
          reject(new CliUsageError('Framed secret input could not be read.'));
        });
      };
      this.#input.once('readable', onReadable);
      this.#input.once('end', onEnd);
      this.#input.once('error', onError);
      if (this.#input.errored !== null) onError();
      else if (this.#input.readableEnded) onEnd();
    });
  }

  #wipeBuffer(): void {
    this.#buffer.fill(0);
    this.#buffer = Buffer.alloc(0);
  }

  #validateFrameBounds(incoming: Buffer): void {
    let offset = 0;
    for (;;) {
      const newline = incoming.indexOf(0x0a, offset);
      const segmentEnd = newline < 0 ? incoming.length : newline;
      this.#pendingFrameBytes += segmentEnd - offset;
      if (this.#pendingFrameBytes > MAX_SECRET_BYTES + 1) {
        throw new CliUsageError('Framed secret input exceeds the supported size.');
      }
      if (newline < 0) return;
      this.#pendingFrameBytes = 0;
      offset = newline + 1;
    }
  }
}

function copyBoundedChunk(
  chunk: unknown,
  remainingBytes: number,
  oversizeMessage: string,
): Buffer {
  if (typeof chunk === 'string') {
    if (Buffer.byteLength(chunk) > remainingBytes) {
      throw new CliUsageError(oversizeMessage);
    }
    return Buffer.from(chunk);
  }
  if (chunk instanceof Uint8Array) {
    if (chunk.byteLength > remainingBytes) {
      throw new CliUsageError(oversizeMessage);
    }
    return Buffer.from(chunk);
  }
  throw new CliUsageError('Secret input could not be read.');
}

function readMasked(
  input: SecretReadable,
  output: Writable,
  label: string,
): Promise<Uint8Array> {
  return new Promise((resolve, reject) => {
    const bytes: number[] = [];
    const wasRaw = input.isRaw === true;
    let settled = false;
    const finish = (result: Uint8Array | Error): void => {
      if (settled) {
        if (!(result instanceof Error)) result.fill(0);
        bytes.fill(0);
        return;
      }
      settled = true;
      const cleanupFailures: Error[] = [];
      const attemptCleanup = (operation: () => void): void => {
        try {
          operation();
        } catch {
          cleanupFailures.push(
            new CliUsageError('Secret input terminal cleanup failed.'),
          );
        }
      };
      try {
        attemptCleanup(() => input.off('data', onData));
        attemptCleanup(() => input.off('end', onEnd));
        attemptCleanup(() => input.off('error', onError));
        attemptCleanup(() => input.setRawMode?.(wasRaw));
        attemptCleanup(() => input.pause());
        attemptCleanup(() => {
          output.write('\n');
        });

        if (cleanupFailures.length === 0) {
          if (result instanceof Error) reject(result);
          else resolve(result);
          return;
        }

        if (!(result instanceof Error)) result.fill(0);
        const failures =
          result instanceof Error ? [result, ...cleanupFailures] : cleanupFailures;
        const failure = failures[0];
        reject(
          failures.length === 1 && failure !== undefined
            ? failure
            : new AggregateError(failures, 'Secret input terminal cleanup failed.'),
        );
      } finally {
        bytes.fill(0);
      }
    };
    const onEnd = (): void => {
      finish(new CliUsageError('Secret input ended before a value was entered.'));
    };
    const onError = (): void => {
      finish(new CliUsageError('Secret input could not be read.'));
    };
    const onData = (chunk: Buffer | string): void => {
      const incoming = Buffer.from(chunk);
      try {
        for (const byte of incoming) {
          if (byte === 3) {
            finish(new CliUsageError('Secret entry was cancelled.'));
            return;
          }
          if (byte === 13 || byte === 10) {
            finish(Uint8Array.from(bytes));
            return;
          }
          if (byte === 8 || byte === 127) {
            removeLastUtf8CodePoint(bytes);
            continue;
          }
          bytes.push(byte);
          if (bytes.length > MAX_SECRET_BYTES) {
            finish(new CliUsageError('Secret input exceeds the supported size.'));
            return;
          }
        }
      } finally {
        incoming.fill(0);
      }
    };
    try {
      output.write(`Enter ${label} (input hidden): `);
      input.setRawMode?.(true);
      input.on('data', onData);
      input.once('end', onEnd);
      input.once('error', onError);
      input.resume();
    } catch {
      finish(new CliUsageError('Secret input terminal preparation failed.'));
    }
  });
}

function secretKindLabel(kind: SecretKind): string {
  switch (kind) {
    case 'totp-seed':
      return 'TOTP seed';
    case 'field-value':
      return 'field value';
    default:
      return kind;
  }
}

function secretKindStdinFlag(kind: SecretKind): string {
  if (kind === 'totp-seed') return '--secret-stdin';
  if (kind === 'field-value') return '--value-stdin';
  return `--${kind}-stdin`;
}

function removeLastUtf8CodePoint(bytes: number[]): void {
  const removed = bytes.pop();
  if (removed === undefined || (removed & 0xc0) !== 0x80) return;
  for (;;) {
    const last = bytes.at(-1);
    if (last === undefined) return;
    if ((last & 0xc0) !== 0x80) {
      bytes.pop();
      return;
    }
    bytes.pop();
  }
}

function normalizeSecret(bytes: Uint8Array): AcquiredSecret {
  try {
    let value: string;
    try {
      value = new TextDecoder('utf-8', { fatal: true }).decode(bytes);
    } catch {
      throw new CliUsageError('Secret input must use valid UTF-8.');
    }
    if (value.endsWith('\r\n')) value = value.slice(0, -2);
    else if (value.endsWith('\n')) value = value.slice(0, -1);
    try {
      return acquiredSecretSchema.parse(value);
    } catch {
      throw new CliUsageError('Secret input must contain exactly one non-empty value.');
    }
  } finally {
    bytes.fill(0);
  }
}
