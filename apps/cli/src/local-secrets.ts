import type { Readable, Writable } from 'node:stream';

import { MIN_PASSPHRASE_BYTES } from '@kavrix/crypto';
import { databaseCatalogPayloadSchema } from '@kavrix/schemas';

import {
  renderTerminalPrompt,
  renderTerminalStatus,
  terminalColorEnabled,
  type TerminalStatusKind,
} from './terminal-presentation.js';

const MAX_SECRET_BYTES = 1_048_576;
// MongoDB-source migration into a new local database is the widest supported
// command: source URL, source passphrase, expected source-vault label,
// destination passphrase and confirmation, database label, and vault label.
// MongoDB destination initialization is rejected before secret input.
const MAX_SECRET_FRAMES = 7;
const UTF8_ENCODER = new TextEncoder();
const STRICT_UTF8_DECODER = new TextDecoder('utf-8', { fatal: true });

export type LocalSecretKind =
  | 'database-url'
  | 'label'
  | 'database-label'
  | 'vault-label'
  | 'passphrase'
  | 'recovery-passphrase'
  | 'new-passphrase'
  | 'field-value'
  | 'field-value-base64';

export type ConfirmableLocalSecretKind =
  'passphrase' | 'recovery-passphrase' | 'new-passphrase';

export class LocalSecretInput {
  readonly #input: Readable & {
    isTTY?: boolean;
    isRaw?: boolean;
    setRawMode?: (enabled: boolean) => void;
  };
  readonly #output: Writable;
  #stdinIterator: AsyncIterator<unknown> | undefined;
  #stdinPending: Uint8Array = new Uint8Array(0);
  #stdinEnded = false;

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
    finalFrames = true,
  ): Promise<readonly string[]> {
    if (kinds.length === 0 || kinds.length > MAX_SECRET_FRAMES) {
      throw new LocalSecretInputError('Secret input request is invalid.');
    }
    if (fromStdin) return this.#readStdin(kinds, finalFrames);
    const values: string[] = [];
    let index = 0;
    while (index < kinds.length) {
      const kind = kinds[index];
      if (kind === undefined) break;
      if (isConfirmableKind(kind) && kinds[index + 1] === kind) {
        const confirmed = await this.readConfirmed(kind);
        values.push(...confirmed);
        index += 2;
        continue;
      }
      values.push(await this.#readInteractiveField(kind, false));
      index += 1;
    }
    return values;
  }

  /**
   * Reads and compares one interactive passphrase pair. Local validation
   * retries one field; a mismatch retries the pair without revealing details.
   * Framed stdin intentionally remains available only through `read`.
   */
  public async readConfirmed(
    kind: ConfirmableLocalSecretKind,
  ): Promise<readonly [string, string]> {
    if (!isConfirmableKind(kind)) {
      throw new LocalSecretInputError('Secret input request is invalid.');
    }
    for (;;) {
      const first = await this.#readInteractiveField(kind, false);
      const confirmation = await this.#readInteractiveField(kind, true);
      if (first === confirmation) return [first, confirmation];
      this.#writeStatus('error', mismatchMessage(kind));
    }
  }

  async #readInteractiveField(
    kind: LocalSecretKind,
    confirmation: boolean,
  ): Promise<string> {
    for (;;) {
      try {
        const value = await this.#readMasked(kind, promptFor(kind, confirmation));
        this.#writeStatus('success', 'Input accepted.');
        return value;
      } catch (error) {
        if (!(error instanceof LocalSecretInputError) || !error.retryable) throw error;
        this.#writeStatus('error', `${error.message} Re-enter this field.`);
      }
    }
  }

  async #readStdin(
    kinds: readonly LocalSecretKind[],
    finalFrames: boolean,
  ): Promise<readonly string[]> {
    const frames: string[] = [];
    let frame: Uint8Array = new Uint8Array(0);
    try {
      while (frames.length < kinds.length) {
        const newline = this.#stdinPending.indexOf(10);
        if (newline >= 0) {
          frame = appendBytes(frame, this.#stdinPending.subarray(0, newline));
          this.#consumePending(newline + 1);
          frames.push(decodeFrame(frame, kinds[frames.length]));
          zeroBytes(frame);
          frame = new Uint8Array(0);
          continue;
        }
        frame = appendBytes(frame, this.#stdinPending);
        this.#consumePending(this.#stdinPending.byteLength);
        if (frame.byteLength > MAX_SECRET_BYTES) {
          throw new LocalSecretInputError('Secret input exceeds the supported size.');
        }
        const next = await this.#nextStdinChunk();
        if (next === null) {
          if (frame.byteLength === 0) {
            throw new LocalSecretInputError(
              'Secret input contains the wrong number of values.',
            );
          }
          frames.push(decodeFrame(frame, kinds[frames.length]));
          zeroBytes(frame);
          frame = new Uint8Array(0);
        }
      }
      if (finalFrames) await this.#requireStdinEnd();
      return frames;
    } catch (error) {
      this.#clearPending();
      throw error;
    } finally {
      zeroBytes(frame);
    }
  }

  async #nextStdinChunk(): Promise<Uint8Array | null> {
    if (this.#stdinPending.byteLength > 0) return this.#stdinPending;
    if (this.#stdinEnded) return null;
    this.#stdinIterator ??= this.#input[Symbol.asyncIterator]();
    for (;;) {
      const next = await this.#stdinIterator.next();
      if (next.done === true) {
        this.#stdinEnded = true;
        return null;
      }
      let bytes: Uint8Array;
      if (typeof next.value === 'string') {
        bytes = UTF8_ENCODER.encode(next.value);
      } else if (next.value instanceof Uint8Array) {
        bytes = Uint8Array.from(next.value);
        zeroBytes(next.value);
      } else {
        throw new LocalSecretInputError('Secret input contains invalid bytes.');
      }
      if (bytes.byteLength === 0) continue;
      this.#stdinPending = bytes;
      return bytes;
    }
  }

  async #requireStdinEnd(): Promise<void> {
    if (this.#stdinPending.byteLength > 0) {
      throw new LocalSecretInputError(
        'Secret input contains the wrong number of values.',
      );
    }
    if ((await this.#nextStdinChunk()) !== null) {
      throw new LocalSecretInputError(
        'Secret input contains the wrong number of values.',
      );
    }
  }

  #consumePending(length: number): void {
    const prior = this.#stdinPending;
    this.#stdinPending = Uint8Array.from(prior.subarray(length));
    zeroBytes(prior);
  }

  #clearPending(): void {
    const prior = this.#stdinPending;
    this.#stdinPending = new Uint8Array(0);
    zeroBytes(prior);
  }

  #readMasked(kind: LocalSecretKind, prompt: SecretPrompt): Promise<string> {
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
        if (cleanupFailed || cleanupStreamFailed) {
          error = new LocalSecretInputError('Secret input terminal cleanup failed.');
        }
        let value: string | undefined;
        if (error === undefined) {
          const encoded = Uint8Array.from(bytes);
          try {
            value = decodeFrame(encoded, kind);
          } catch (decodeError) {
            error =
              decodeError instanceof Error
                ? decodeError
                : new LocalSecretInputError('Secret input contains invalid bytes.');
          } finally {
            zeroBytes(encoded);
          }
        }
        bytes.fill(0);
        bytes.length = 0;
        if (error !== undefined) reject(error);
        else if (value !== undefined) resolve(value);
        else reject(new LocalSecretInputError('Secret input is invalid.'));
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
        const incoming = typeof chunk === 'string' ? UTF8_ENCODER.encode(chunk) : chunk;
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
              if (bytes.length > 0) bytes[bytes.length - 1] = 0;
              bytes.pop();
              continue;
            }
            bytes.push(byte);
            if (bytes.length > MAX_SECRET_BYTES) {
              finish(
                new LocalSecretInputError(
                  'Secret input exceeds the supported size.',
                  true,
                ),
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
        const color = terminalColorEnabled(this.#output);
        this.#output.write(
          renderTerminalStatus(
            'info',
            requirementFor(kind, prompt.confirmation),
            color,
          ),
        );
        this.#output.write(renderTerminalPrompt(prompt.label, color));
        promptWritten = true;
        preparing = false;
        input.resume();
      } catch {
        finish(new LocalSecretInputError('Secret input terminal preparation failed.'));
      }
    });
  }

  #writeStatus(kind: TerminalStatusKind, message: string): void {
    try {
      this.#output.write(
        renderTerminalStatus(kind, message, terminalColorEnabled(this.#output)),
      );
    } catch {
      throw new LocalSecretInputError('Secret input terminal output failed.');
    }
  }
}

export class LocalSecretInputError extends Error {
  public constructor(
    message: string,
    public readonly retryable = false,
  ) {
    super(message);
    this.name = 'LocalSecretInputError';
  }
}

type SecretPrompt = Readonly<{ label: string; confirmation: boolean }>;

function isConfirmableKind(kind: LocalSecretKind): kind is ConfirmableLocalSecretKind {
  return (
    kind === 'passphrase' || kind === 'new-passphrase' || kind === 'recovery-passphrase'
  );
}

function promptFor(kind: LocalSecretKind, confirmation: boolean): SecretPrompt {
  const label = labelFor(kind);
  return {
    label: `${confirmation ? 'Confirm' : 'Enter'} ${label}`,
    confirmation,
  };
}

function requirementFor(kind: LocalSecretKind, confirmation: boolean): string {
  if (confirmation) {
    return `Re-enter the same ${labelFor(kind)} to confirm it.`;
  }
  if (isConfirmableKind(kind)) {
    return `Requirement: use at least ${String(MIN_PASSPHRASE_BYTES)} UTF-8 bytes in one line.`;
  }
  if (kind === 'field-value-base64') {
    return 'Requirement: enter valid base64 that decodes to UTF-8 text.';
  }
  if (kind === 'label') {
    return 'Requirement: use 1-256 characters after trimming whitespace.';
  }
  return 'Requirement: enter one non-empty line.';
}

function mismatchMessage(kind: ConfirmableLocalSecretKind): string {
  if (kind === 'new-passphrase') {
    return 'New passphrases do not match; re-enter both.';
  }
  if (kind === 'recovery-passphrase') {
    return 'Recovery-kit passphrases do not match; re-enter both.';
  }
  return 'Passphrases do not match; re-enter both.';
}

function labelFor(kind: LocalSecretKind): string {
  if (kind === 'database-url') return 'database URL';
  if (kind === 'label') return 'private label';
  if (kind === 'database-label') return 'private database label';
  if (kind === 'vault-label') return 'private vault label';
  if (kind === 'field-value') return 'credential value';
  if (kind === 'field-value-base64') return 'credential value (base64)';
  if (kind === 'recovery-passphrase') return 'recovery-kit passphrase';
  if (kind === 'new-passphrase') return 'new passphrase';
  return 'passphrase';
}

const BASE64_PATTERN =
  /^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/u;

/**
 * Decodes one base64 frame into its exact text value. This is the supported
 * automation path for values that contain line breaks or are empty: the
 * encoded frame is a single newline-free line, so framing stays unambiguous
 * while the stored value may contain any UTF-8 text within the size bound.
 */
function decodeBase64Value(frame: string): string {
  const normalized = frame.trim();
  if (!BASE64_PATTERN.test(normalized)) {
    throw new LocalSecretInputError(
      'The base64 value frame is not valid base64.',
      true,
    );
  }
  const decoded = Buffer.from(normalized, 'base64');
  if (decoded.byteLength > MAX_SECRET_BYTES) {
    throw new LocalSecretInputError('Secret input exceeds the supported size.', true);
  }
  let value: string;
  try {
    value = STRICT_UTF8_DECODER.decode(decoded);
  } catch {
    throw new LocalSecretInputError(
      'The base64 value frame does not decode to UTF-8 text.',
      true,
    );
  } finally {
    decoded.fill(0);
  }
  if (value.includes('\0')) {
    throw new LocalSecretInputError('Secret input must not contain NUL bytes.', true);
  }
  return value;
}

function validateSecret(value: string, kind?: LocalSecretKind): string {
  if (kind === 'field-value-base64') return decodeBase64Value(value);
  if (
    value.length === 0 ||
    Buffer.byteLength(value, 'utf8') > MAX_SECRET_BYTES ||
    value.includes('\0') ||
    /[\r\n]/u.test(value)
  ) {
    throw new LocalSecretInputError(
      'Secret input must contain exactly one value.',
      true,
    );
  }
  if (kind === 'label' || kind === 'database-label' || kind === 'vault-label') {
    try {
      return databaseCatalogPayloadSchema.shape.label.parse(value);
    } catch {
      throw new LocalSecretInputError(
        'Private labels must contain 1-256 characters after trimming whitespace.',
        true,
      );
    }
  }
  if (
    (kind === 'passphrase' ||
      kind === 'new-passphrase' ||
      kind === 'recovery-passphrase') &&
    Buffer.byteLength(value, 'utf8') < MIN_PASSPHRASE_BYTES
  ) {
    throw new LocalSecretInputError(
      `Passphrases must contain at least ${String(MIN_PASSPHRASE_BYTES)} bytes.`,
      true,
    );
  }
  return value;
}

function appendBytes(left: Uint8Array, right: Uint8Array): Uint8Array {
  if (left.byteLength + right.byteLength > MAX_SECRET_BYTES) {
    throw new LocalSecretInputError('Secret input exceeds the supported size.');
  }
  const joined = new Uint8Array(left.byteLength + right.byteLength);
  joined.set(left);
  joined.set(right, left.byteLength);
  zeroBytes(left);
  return joined;
}

function decodeFrame(bytes: Uint8Array, kind?: LocalSecretKind): string {
  const end = bytes.at(-1) === 13 ? bytes.byteLength - 1 : bytes.byteLength;
  let value: string;
  try {
    value = STRICT_UTF8_DECODER.decode(bytes.subarray(0, end));
  } catch {
    throw new LocalSecretInputError('Secret input contains invalid bytes.');
  }
  return validateSecret(value, kind);
}

function zeroBytes(bytes: Uint8Array): void {
  bytes.fill(0);
}
