import { isUtf8 } from 'node:buffer';
import { createHash, timingSafeEqual } from 'node:crypto';

import { detectClipboardBackend, type ClipboardBackend } from './backends.js';
import { ClipboardError } from './errors.js';
import { createNodeClipboardRuntime } from './node-runtime.js';
import {
  CLIPBOARD_CLEANUP_RETRY_DEADLINE_MS,
  MAX_CLEAR_TIMEOUT_MS,
  MAX_CLIPBOARD_CLEANUP_ATTEMPTS,
  MAX_CLIPBOARD_BYTES,
  MIN_CLEAR_TIMEOUT_MS,
  type ClipboardCopyOptions,
  type ClipboardCopyReceipt,
  type ClipboardRuntime,
  type SecureClipboardPort,
} from './types.js';

const INITIAL_EXPIRY_RETRY_DELAY_MS = 100;
const MAX_EXPIRY_RETRY_DELAY_MS = 400;

interface ActiveClipboard {
  readonly generation: number;
  readonly fingerprints: readonly Uint8Array[];
  readonly cleanupRetryDeadline: number;
  timer: object | number | null;
}

export class SecureClipboard implements SecureClipboardPort {
  readonly #runtime: ClipboardRuntime;
  #backend: ClipboardBackend | null = null;
  #generation = 0;
  #active: ActiveClipboard | null = null;
  #backgroundError: ClipboardError | null = null;
  #tail: Promise<void> = Promise.resolve();

  public constructor(runtime: ClipboardRuntime) {
    this.#runtime = runtime;
  }

  public copy(
    secret: Uint8Array,
    options: ClipboardCopyOptions,
  ): Promise<ClipboardCopyReceipt> {
    assertCopyOptions(options);
    validateCopy(secret, options.clearAfterMs, options.signal);
    const ownedSecret = Uint8Array.from(secret);
    let expectedFingerprint: Uint8Array;
    try {
      expectedFingerprint = fingerprint(ownedSecret);
    } catch {
      ownedSecret.fill(0);
      throw new ClipboardError(
        'CLIPBOARD_OPERATION_FAILED',
        'Clipboard operation failed.',
      );
    }
    return this.#exclusive(async () => {
      const backend = await this.#getBackend();
      const generation = this.#generation + 1;
      this.#generation = generation;
      const previous = this.#detachActive();
      let writeAttempted = false;
      try {
        assertNotAborted(options.signal);
        writeAttempted = true;
        await backend.write(ownedSecret, options.signal);
        const current = await backend.read(options.signal);
        let matches = false;
        try {
          matches = matchesFingerprints(current, [expectedFingerprint]);
        } finally {
          current.fill(0);
        }
        if (!matches) {
          throw new ClipboardError(
            'CLIPBOARD_CHANGED',
            'Clipboard contents changed before copy verification.',
          );
        }
        const active: ActiveClipboard = {
          generation,
          fingerprints: [Uint8Array.from(expectedFingerprint)],
          cleanupRetryDeadline:
            this.#runtime.scheduler.now() +
            options.clearAfterMs +
            CLIPBOARD_CLEANUP_RETRY_DEADLINE_MS,
          timer: null,
        };
        try {
          active.timer = this.#runtime.scheduler.set(
            options.clearAfterMs,
            this.#expiryTask(generation, 1),
          );
        } catch (error) {
          wipeActive(active);
          throw error;
        }
        this.#active = active;
        wipeActive(previous);
        return {
          generation,
          requestedClearAfterMs: options.clearAfterMs,
          cleanupRetryDeadlineAfterMs:
            options.clearAfterMs + CLIPBOARD_CLEANUP_RETRY_DEADLINE_MS,
          maxCleanupAttempts: MAX_CLIPBOARD_CLEANUP_ATTEMPTS,
          clearAfterMs: options.clearAfterMs,
        };
      } catch (error) {
        const cleanupFingerprints = [
          ...(writeAttempted ? [expectedFingerprint] : []),
          ...(previous?.fingerprints ?? []),
        ];
        if (cleanupFingerprints.length > 0) {
          try {
            await this.#clearMatching(backend, cleanupFingerprints);
          } catch {
            this.#active = {
              generation,
              fingerprints: cleanupFingerprints.map((value) => Uint8Array.from(value)),
              cleanupRetryDeadline: this.#runtime.scheduler.now(),
              timer: null,
            };
            wipeActive(previous);
            throw new ClipboardError(
              'CLIPBOARD_OPERATION_FAILED',
              'Clipboard operation and guarded cleanup failed.',
            );
          }
        }
        wipeActive(previous);
        throw normalizeFailure(error);
      }
    }).finally(() => {
      ownedSecret.fill(0);
      expectedFingerprint.fill(0);
    });
  }

  public lock(signal?: AbortSignal): Promise<boolean> {
    return this.#clearActive(signal);
  }

  public dispose(signal?: AbortSignal): Promise<boolean> {
    return this.#clearActive(signal);
  }

  public takeBackgroundError(): ClipboardError | null {
    const error = this.#backgroundError;
    this.#backgroundError = null;
    return error;
  }

  async #clearActive(signal?: AbortSignal): Promise<boolean> {
    return this.#exclusive(async () => {
      this.#generation += 1;
      const active = this.#detachActive();
      if (active === null) return false;
      let completed = false;
      try {
        assertNotAborted(signal);
        const backend = await this.#getBackend();
        const cleared = await this.#clearMatching(backend, active.fingerprints, signal);
        completed = true;
        return cleared;
      } catch (error) {
        this.#active = active;
        throw error;
      } finally {
        if (completed) wipeActive(active);
      }
    });
  }

  async #expire(generation: number, attempt: number): Promise<void> {
    await this.#exclusive(async () => {
      const active = this.#active;
      if (active?.generation !== generation || this.#generation !== generation) return;
      active.timer = null;
      try {
        const backend = await this.#getBackend();
        await this.#clearMatching(backend, active.fingerprints);
        this.#finishExpiry(active);
      } catch {
        if (this.#active !== active || active.generation !== generation) return;
        const remainingRetryMs =
          active.cleanupRetryDeadline - this.#runtime.scheduler.now();
        if (attempt >= MAX_CLIPBOARD_CLEANUP_ATTEMPTS || remainingRetryMs <= 0) {
          this.#finishExpiry(active);
          this.#recordBackgroundFailure();
          return;
        }
        const retryDelayMs = Math.min(
          INITIAL_EXPIRY_RETRY_DELAY_MS * 2 ** (attempt - 1),
          MAX_EXPIRY_RETRY_DELAY_MS,
          remainingRetryMs,
        );
        try {
          active.timer = this.#runtime.scheduler.set(
            retryDelayMs,
            this.#expiryTask(generation, attempt + 1),
          );
        } catch {
          this.#finishExpiry(active);
          this.#recordBackgroundFailure();
        }
      }
    }).catch(() => {
      this.#recordBackgroundFailure();
    });
  }

  #expiryTask(generation: number, attempt: number): () => void {
    return () => {
      void this.#expire(generation, attempt);
    };
  }

  #finishExpiry(active: ActiveClipboard): void {
    if (this.#active !== active) return;
    this.#active = null;
    wipeActive(active);
  }

  #recordBackgroundFailure(): void {
    this.#backgroundError ??= new ClipboardError(
      'CLIPBOARD_OPERATION_FAILED',
      'Clipboard operation failed.',
    );
  }

  async #clearMatching(
    backend: ClipboardBackend,
    expectedFingerprints: readonly Uint8Array[],
    signal?: AbortSignal,
  ): Promise<boolean> {
    const current = await backend.read(signal);
    try {
      if (!matchesFingerprints(current, expectedFingerprints)) return false;
      await backend.clear(signal);
      return true;
    } finally {
      current.fill(0);
    }
  }

  async #getBackend(): Promise<ClipboardBackend> {
    this.#backend ??= await detectClipboardBackend(this.#runtime);
    return this.#backend;
  }

  #detachActive(): ActiveClipboard | null {
    const active = this.#active;
    this.#active = null;
    if (active?.timer != null) {
      this.#runtime.scheduler.clear(active.timer);
      active.timer = null;
    }
    return active;
  }

  #exclusive<Result>(operation: () => Promise<Result>): Promise<Result> {
    const predecessor = this.#tail;
    let release: (() => void) | undefined;
    this.#tail = new Promise((resolve) => {
      release = resolve;
    });
    return predecessor.then(operation).finally(() => release?.());
  }
}

export function createSecureClipboard(): SecureClipboard {
  return new SecureClipboard(createNodeClipboardRuntime());
}

function validateCopy(
  secret: Uint8Array,
  clearAfterMs: number,
  signal?: AbortSignal,
): void {
  if (
    !(secret instanceof Uint8Array) ||
    secret.byteLength < 1 ||
    secret.byteLength > MAX_CLIPBOARD_BYTES ||
    secret.includes(0) ||
    !isUtf8(secret) ||
    !Number.isSafeInteger(clearAfterMs) ||
    clearAfterMs < MIN_CLEAR_TIMEOUT_MS ||
    clearAfterMs > MAX_CLEAR_TIMEOUT_MS ||
    (signal !== undefined && !(signal instanceof AbortSignal))
  ) {
    throw validationError();
  }
}

function assertCopyOptions(value: unknown): asserts value is ClipboardCopyOptions {
  if (typeof value !== 'object' || value === null) throw validationError();
}

function validationError(): ClipboardError {
  return new ClipboardError(
    'CLIPBOARD_VALIDATION_FAILED',
    'Clipboard input is invalid.',
  );
}

function fingerprint(value: Uint8Array): Uint8Array {
  const digest = createHash('sha256').update(value).digest();
  try {
    return Uint8Array.from(digest);
  } finally {
    digest.fill(0);
  }
}

function matchesFingerprints(
  value: Uint8Array,
  expectedFingerprints: readonly Uint8Array[],
): boolean {
  const actual = fingerprint(value);
  try {
    let matches = false;
    for (const expected of expectedFingerprints) {
      if (actual.byteLength === expected.byteLength) {
        matches = timingSafeEqual(actual, expected) || matches;
      }
    }
    return matches;
  } finally {
    actual.fill(0);
  }
}

function assertNotAborted(signal?: AbortSignal): void {
  if (signal?.aborted === true) {
    throw new ClipboardError('CLIPBOARD_ABORTED', 'Clipboard operation was cancelled.');
  }
}

function normalizeFailure(error: unknown): ClipboardError {
  return error instanceof ClipboardError
    ? error
    : new ClipboardError('CLIPBOARD_OPERATION_FAILED', 'Clipboard operation failed.');
}

function wipeActive(active: ActiveClipboard | null): void {
  if (active === null) return;
  for (const value of active.fingerprints) value.fill(0);
}
