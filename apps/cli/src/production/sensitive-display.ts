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
    this.#output.write(CLEAR_SURFACE + renderMaterial(request.material));
    try {
      await this.#readAcknowledgement();
    } finally {
      // A failed acknowledgement must not leave the keys on screen while the
      // operation is cancelled.
      this.#output.write(CLEAR_SURFACE);
    }
    return { acknowledged: true, interactiveTty: true };
  }

  /** Reads one echoed line and requires it to equal `ACKNOWLEDGEMENT` exactly. */
  #readAcknowledgement(): Promise<void> {
    const input = this.#input;
    const output = this.#output;
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
        let cleanupError: Error | undefined;
        try {
          input.setRawMode?.(wasRaw);
          input.pause();
          output.write('\n');
        } catch {
          cleanupError = new CliUsageError(
            'The sensitive terminal could not be restored.',
          );
        } finally {
          typed.fill(0);
        }
        if (cleanupError !== undefined) reject(cleanupError);
        else if (error === undefined) resolve();
        else reject(error);
      };
      const onEnd = (): void => {
        finish(new CliUsageError('The acknowledgement ended before it was entered.'));
      };
      const onError = (): void => {
        finish(new CliUsageError('The acknowledgement could not be read.'));
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
              if (typed.pop() !== undefined) output.write('\b \b');
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
            output.write(String.fromCharCode(byte));
          }
        } finally {
          incoming.fill(0);
        }
      };
      input.setRawMode?.(true);
      input.on('data', onData);
      input.once('end', onEnd);
      input.once('error', onError);
      input.resume();
    });
  }
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
