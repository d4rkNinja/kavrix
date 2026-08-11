import type { Readable, Writable } from 'node:stream';

import { CliUsageError } from '../errors.js';
import type {
  SensitiveInitializationDisplayPort,
  SensitiveInitializationDisplayRequest,
  SensitiveInitializationMaterial,
} from '../initialization.js';
import { sanitizeTerminalText } from '../terminal.js';

/** Typed verbatim by the user to confirm the material was written down. */
const ACKNOWLEDGEMENT = 'saved';
const MAX_ACKNOWLEDGEMENT_BYTES = 64;
/** Clear screen, clear scrollback, cursor home. Scrollback clearing is advisory. */
const ESCAPE = String.fromCharCode(0x1b);
const CLEAR_SURFACE = `${ESCAPE}[2J${ESCAPE}[3J${ESCAPE}[H`;

type SensitiveReadable = Readable &
  Readonly<{
    isTTY?: boolean;
    isRaw?: boolean;
    setRawMode?: (enabled: boolean) => void;
  }>;
type SensitiveWritable = Writable & Readonly<{ isTTY?: boolean }>;

export type SensitiveInitializationDisplayAcknowledgement = Readonly<{
  acknowledged: true;
  interactiveTty: true;
}>;

/**
 * Shows generated portable and recovery keys on a dedicated terminal surface.
 *
 * The material goes to the terminal stream rather than stdout, so a redirected
 * or piped stdout never receives key material, and the surface is cleared once
 * the user acknowledges it. A non-interactive terminal is refused outright:
 * nobody would be there to read the keys, and writing them into a pipe or a log
 * is the exact leak this port exists to prevent.
 */
export class NodeSensitiveInitializationDisplay implements SensitiveInitializationDisplayPort {
  readonly #input: SensitiveReadable;
  readonly #output: SensitiveWritable;

  constructor(input: SensitiveReadable, output: SensitiveWritable) {
    this.#input = input;
    this.#output = output;
  }

  async display(
    request: SensitiveInitializationDisplayRequest,
  ): Promise<SensitiveInitializationDisplayAcknowledgement> {
    if (
      this.#input.isTTY !== true ||
      this.#input.setRawMode === undefined ||
      this.#output.isTTY !== true ||
      this.#output === process.stdout ||
      this.#output === process.stderr
    ) {
      throw new CliUsageError(
        'Recovery material can only be shown on an interactive terminal.',
      );
    }
    const abort = new AbortController();
    const writer = new SensitiveTerminalWriter(this.#output, () => {
      abort.abort();
    });
    let primary:
      Readonly<{ succeeded: true }> | Readonly<{ succeeded: false; error: unknown }>;
    try {
      await writer.write(CLEAR_SURFACE + renderMaterial(request.material));
      await this.#readAcknowledgement(abort.signal);
      primary = { succeeded: true };
    } catch (error) {
      primary = { succeeded: false, error };
    }
    let cleanup:
      Readonly<{ succeeded: true }> | Readonly<{ succeeded: false; error: unknown }>;
    try {
      await writer.write(CLEAR_SURFACE);
      cleanup = { succeeded: true };
    } catch (error) {
      cleanup = { succeeded: false, error };
    }
    writer.close();
    if (!cleanup.succeeded) {
      if (!primary.succeeded) {
        throw new AggregateError(
          [primary.error, cleanup.error],
          'The sensitive terminal operation and cleanup both failed.',
          { cause: primary.error },
        );
      }
      throw cleanup.error;
    }
    if (!primary.succeeded) throw primary.error;
    return { acknowledged: true, interactiveTty: true };
  }

  /** Reads one line and requires it to equal `ACKNOWLEDGEMENT` exactly. */
  #readAcknowledgement(signal: AbortSignal): Promise<void> {
    const input = this.#input;
    return new Promise((resolve, reject) => {
      const typed: number[] = [];
      const wasRaw = input.isRaw === true;
      let settled = false;
      const finish = (error?: Error): void => {
        if (settled) return;
        settled = true;
        input.off('data', onData);
        input.off('end', onEnd);
        input.off('error', onError);
        signal.removeEventListener('abort', onAbort);
        const cleanupFailures: Error[] = [];
        try {
          input.setRawMode?.(wasRaw);
        } catch {
          cleanupFailures.push(
            new CliUsageError('The sensitive terminal could not be restored.'),
          );
        }
        try {
          input.pause();
        } catch {
          cleanupFailures.push(
            new CliUsageError('The sensitive terminal could not be restored.'),
          );
        }
        typed.fill(0);
        if (cleanupFailures.length > 0) {
          if (error !== undefined) {
            reject(
              new AggregateError(
                [error, ...cleanupFailures],
                'The sensitive terminal input and cleanup both failed.',
                { cause: error },
              ),
            );
          } else {
            reject(
              new AggregateError(
                cleanupFailures,
                'The sensitive terminal input cleanup failed.',
              ),
            );
          }
        } else if (error === undefined) resolve();
        else reject(error);
      };
      const onEnd = (): void => {
        finish(new CliUsageError('The acknowledgement ended before it was entered.'));
      };
      const onError = (): void => {
        finish(new CliUsageError('The acknowledgement could not be read.'));
      };
      const onAbort = (): void => {
        finish(new CliUsageError('The sensitive terminal output failed.'));
      };
      const onData = (chunk: Buffer | string): void => {
        const incoming = Buffer.from(chunk);
        try {
          for (const byte of incoming) {
            if (byte === 3) {
              finish(new CliUsageError('Initialization was cancelled.'));
              return;
            }
            if (byte === 13 || byte === 10) {
              const acknowledgement = Buffer.from(typed);
              try {
                finish(
                  acknowledgement.toString('ascii') === ACKNOWLEDGEMENT
                    ? undefined
                    : new CliUsageError('The acknowledgement did not match.'),
                );
              } finally {
                acknowledgement.fill(0);
              }
              return;
            }
            if (byte === 8 || byte === 127) {
              typed.pop();
              continue;
            }
            // The acknowledgement is exactly one printable-ASCII word. Refuse
            // every other byte rather than normalizing a hostile sequence into
            // an accepted acknowledgement.
            if (byte < 0x20 || byte > 0x7e) {
              finish(new CliUsageError('The acknowledgement did not match.'));
              return;
            }
            typed.push(byte);
            if (typed.length > MAX_ACKNOWLEDGEMENT_BYTES) {
              finish(new CliUsageError('The acknowledgement is too long.'));
              return;
            }
          }
        } finally {
          incoming.fill(0);
        }
      };
      try {
        if (signal.aborted) {
          finish(new CliUsageError('The sensitive terminal output failed.'));
          return;
        }
        input.setRawMode?.(true);
        input.on('data', onData);
        input.once('end', onEnd);
        input.once('error', onError);
        signal.addEventListener('abort', onAbort, { once: true });
        input.resume();
      } catch {
        finish(new CliUsageError('The sensitive terminal could not be prepared.'));
      }
    });
  }
}

class SensitiveTerminalWriter {
  readonly #output: SensitiveWritable;
  readonly #onFailure: () => void;
  #failCurrentWrite: ((error: CliUsageError) => void) | undefined;
  #closed = false;

  constructor(output: SensitiveWritable, onFailure: () => void) {
    this.#output = output;
    this.#onFailure = onFailure;
    output.on('error', this.#handleOutputError);
  }

  write(value: string): Promise<void> {
    if (this.#closed) {
      return Promise.reject(new CliUsageError('The sensitive terminal is closed.'));
    }
    return new Promise((resolve, reject) => {
      let settled = false;
      const finish = (error?: CliUsageError): void => {
        if (settled) return;
        settled = true;
        if (this.#failCurrentWrite === fail) this.#failCurrentWrite = undefined;
        if (error === undefined) resolve();
        else reject(error);
      };
      const fail = (error: CliUsageError): void => {
        finish(error);
      };
      this.#failCurrentWrite = fail;
      try {
        this.#output.write(value, (error) => {
          // Keep the error listener through the stream's next-turn error event.
          setImmediate(() => {
            if (error !== null && error !== undefined) {
              this.#recordFailure(error);
            } else {
              finish();
            }
          });
        });
      } catch (error) {
        this.#recordFailure(error);
      }
    });
  }

  close(): void {
    if (this.#closed) return;
    this.#closed = true;
    this.#output.off('error', this.#handleOutputError);
    this.#failCurrentWrite = undefined;
  }

  readonly #handleOutputError = (error: Error): void => {
    this.#recordFailure(error);
  };

  #recordFailure(cause: unknown): void {
    this.#onFailure();
    this.#failCurrentWrite?.(sensitiveOutputFailure(cause));
  }
}

function sensitiveOutputFailure(cause: unknown): CliUsageError {
  const failure = new CliUsageError('The sensitive terminal output failed.');
  Object.defineProperty(failure, 'cause', {
    value: cause,
    configurable: false,
    enumerable: false,
    writable: false,
  });
  return failure;
}

function renderMaterial(material: SensitiveInitializationMaterial): string {
  const lines = [
    'Write these down now. They are shown once and cannot be recovered.',
    '',
  ];
  if ('portableKey' in material) {
    lines.push(`  Portable key: ${sanitizeTerminalText(material.portableKey)}`);
  }
  lines.push(`  Recovery key: ${sanitizeTerminalText(material.recoveryKey)}`, '');
  lines.push(`Type ${ACKNOWLEDGEMENT} and press Enter once both are stored safely: `);
  return lines.join('\n');
}
