import type { Readable, Writable } from 'node:stream';

import { MIN_PASSPHRASE_BYTES } from '@kavrix/crypto';

const MAX_SECRET_BYTES = 1_048_576;
const MAX_SECRET_FRAMES = 4;

export type LocalSecretKind =
  | 'database-url'
  | 'passphrase'
  | 'recovery-passphrase'
  | 'new-passphrase'
  | 'field-value';

export class LocalSecretInput {
  readonly #input: Readable & {
    isTTY?: boolean;
    isRaw?: boolean;
    setRawMode?: (enabled: boolean) => void;
  };
  readonly #output: Writable;

  public constructor(
    input: Readable & {
      isTTY?: boolean;
      isRaw?: boolean;
      setRawMode?: (enabled: boolean) => void;
    },
    output: Writable,
  ) {
    this.#input = input;
    this.#output = output;
  }

  public async read(
    kinds: readonly LocalSecretKind[],
    fromStdin: boolean,
  ): Promise<readonly string[]> {
    if (kinds.length === 0 || kinds.length > MAX_SECRET_FRAMES) {
      throw new LocalSecretInputError('Secret input request is invalid.');
    }
    if (fromStdin) return this.#readStdin(kinds);
    const values: string[] = [];
    for (const kind of kinds) {
      values.push(await this.#readMasked(kind, labelFor(kind)));
    }
    return values;
  }

  async #readStdin(kinds: readonly LocalSecretKind[]): Promise<readonly string[]> {
    const count = kinds.length;
    const chunks: Uint8Array[] = [];
    let length = 0;
    try {
      for await (const chunk of this.#input) {
        const source =
          typeof chunk === 'string'
            ? Buffer.from(chunk)
            : chunk instanceof Uint8Array
              ? chunk
              : undefined;
        if (source === undefined) {
          throw new LocalSecretInputError('Secret input contains invalid bytes.');
        }
        const bytes = Uint8Array.from(source);
        length += bytes.byteLength;
        if (length > count * (MAX_SECRET_BYTES + 1)) {
          throw new LocalSecretInputError('Secret input exceeds the supported size.');
        }
        chunks.push(bytes);
      }
      const text = Buffer.concat(
        chunks.map((chunk) => Uint8Array.from(chunk)),
        length,
      ).toString('utf8');
      const frames = text.replace(/\r\n/gu, '\n').split('\n');
      if (frames.at(-1) === '') frames.pop();
      if (frames.length !== count) {
        throw new LocalSecretInputError(
          'Secret input contains the wrong number of values.',
        );
      }
      return frames.map((value, index) => validateSecret(value, kinds[index]));
    } finally {
      for (const chunk of chunks) chunk.fill(0);
    }
  }

  #readMasked(kind: LocalSecretKind, label: string): Promise<string> {
    const input = this.#input;
    const rawModeSetter = input.setRawMode;
    if (input.isTTY !== true || rawModeSetter === undefined) {
      throw new LocalSecretInputError(
        'A masked prompt requires a terminal; use the matching stdin flags.',
      );
    }
    const setRawMode = rawModeSetter.bind(input);
    return new Promise((resolve, reject) => {
      const bytes: number[] = [];
      const wasRaw = input.isRaw === true;
      let settled = false;
      let rawModeAttempted = false;
      let promptWritten = false;
      let preparing = true;
      let cleanupStreamFailed = false;
      const finish = (error?: Error): void => {
        if (settled) return;
        settled = true;
        input.off('data', onData);
        input.off('end', onEnd);
        let cleanupFailed = false;
        try {
          if (rawModeAttempted) setRawMode(wasRaw);
        } catch {
          cleanupFailed = true;
        }
        try {
          input.pause();
        } catch {
          cleanupFailed = true;
        }
        input.off('error', onError);
        if (promptWritten) {
          try {
            this.#output.write('\n');
          } catch {
            cleanupFailed = true;
          }
        }
        const value = Buffer.from(bytes).toString('utf8');
        bytes.fill(0);
        if ((cleanupFailed || cleanupStreamFailed) && error === undefined) {
          error = new LocalSecretInputError('Secret input terminal cleanup failed.');
        }
        if (error !== undefined) reject(error);
        else {
          try {
            resolve(validateSecret(value, kind));
          } catch (validationError) {
            reject(
              validationError instanceof Error
                ? validationError
                : new LocalSecretInputError('Secret input is invalid.'),
            );
          }
        }
      };
      const onEnd = (): void => {
        finish(
          new LocalSecretInputError('Secret input ended before a value was entered.'),
        );
      };
      const onError = (): void => {
        if (settled) {
          cleanupStreamFailed = true;
          return;
        }
        finish(
          new LocalSecretInputError(
            preparing
              ? 'Secret input terminal preparation failed.'
              : 'Secret input could not be read.',
          ),
        );
      };
      const onData = (chunk: Buffer | string): void => {
        const incoming = Buffer.from(chunk);
        try {
          for (const byte of incoming) {
            if (byte === 3) {
              finish(new LocalSecretInputError('Secret entry was cancelled.'));
              return;
            }
            if (byte === 13 || byte === 10) {
              finish();
              return;
            }
            if (byte === 8 || byte === 127) {
              bytes.pop();
              continue;
            }
            bytes.push(byte);
            if (bytes.length > MAX_SECRET_BYTES) {
              finish(
                new LocalSecretInputError('Secret input exceeds the supported size.'),
              );
              return;
            }
          }
        } finally {
          incoming.fill(0);
        }
      };
      try {
        input.pause();
        input.on('error', onError);
        input.once('end', onEnd);
        input.on('data', onData);
        rawModeAttempted = true;
        setRawMode(true);
        if (!input.listeners('data').includes(onData)) return;
        this.#output.write('Enter ' + label + ' (input hidden): ');
        promptWritten = true;
        preparing = false;
        input.resume();
      } catch {
        finish(new LocalSecretInputError('Secret input terminal preparation failed.'));
      }
    });
  }
}

export class LocalSecretInputError extends Error {
  public constructor(message: string) {
    super(message);
    this.name = 'LocalSecretInputError';
  }
}

function labelFor(kind: LocalSecretKind): string {
  if (kind === 'database-url') return 'database URL';
  if (kind === 'field-value') return 'credential value';
  if (kind === 'recovery-passphrase') return 'recovery-kit passphrase';
  if (kind === 'new-passphrase') return 'new passphrase';
  return 'passphrase';
}

function validateSecret(value: string, kind?: LocalSecretKind): string {
  if (
    value.length === 0 ||
    Buffer.byteLength(value, 'utf8') > MAX_SECRET_BYTES ||
    value.includes('\0') ||
    /[\r\n]/u.test(value)
  ) {
    throw new LocalSecretInputError('Secret input must contain exactly one value.');
  }
  if (
    (kind === 'passphrase' ||
      kind === 'new-passphrase' ||
      kind === 'recovery-passphrase') &&
    Buffer.byteLength(value, 'utf8') < MIN_PASSPHRASE_BYTES
  ) {
    throw new LocalSecretInputError(
      `Passphrases must contain at least ${String(MIN_PASSPHRASE_BYTES)} bytes.`,
    );
  }
  return value;
}
