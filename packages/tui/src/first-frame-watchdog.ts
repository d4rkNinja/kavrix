/**
 * Ink 7 treats CI hosts as non-interactive even when stdout is a TTY, which
 * delays the first frame until unmount — live xfce4-terminal then stays blank
 * while the process is alive. Mount helpers force `interactive: true` and arm
 * this watchdog so a still-blank mount fails loudly instead of hanging forever.
 */

export const FIRST_FRAME_TIMEOUT_MS = 2_500;

export class FirstFrameTimeoutError extends Error {
  public override readonly name = 'FirstFrameTimeoutError';

  public constructor(message: string) {
    super(message);
  }
}

export interface FirstFrameWatchdogOptions {
  readonly stdout: NodeJS.WritableStream;
  readonly label: string;
  readonly timeoutMs?: number;
  readonly onTimeout?: (error: FirstFrameTimeoutError) => void;
}

export interface FirstFrameWatchdog {
  readonly sawFrame: () => boolean;
  readonly dispose: () => void;
}

interface WriteFn {
  (
    chunk: string | Uint8Array,
    encoding?: BufferEncoding,
    callback?: (error?: Error | null) => void,
  ): boolean;
  (chunk: string | Uint8Array, callback?: (error?: Error | null) => void): boolean;
}

const ESC = '\u001B';

/**
 * True when a write carries something a human could actually see. Entering the
 * alternate screen and enabling mouse reporting are longer than the size probe
 * below yet paint nothing, so a byte count alone would declare a frame that was
 * never rendered.
 */
function carriesVisibleText(chunk: string): boolean {
  let index = 0;
  while (index < chunk.length) {
    const code = chunk.charCodeAt(index);
    if (code === 0x1b) {
      const next = chunk[index + 1];
      if (next === '[') {
        index += 2;
        while (index < chunk.length) {
          const parameter = chunk.charCodeAt(index);
          if (parameter >= 0x40 && parameter <= 0x7e) {
            index += 1;
            break;
          }
          index += 1;
        }
        continue;
      }
      if (next === ']') {
        index += 2;
        while (index < chunk.length) {
          if (chunk[index] === '\u0007') {
            index += 1;
            break;
          }
          if (chunk[index] === ESC && chunk[index + 1] === '\\') {
            index += 2;
            break;
          }
          index += 1;
        }
        continue;
      }
      index += 2;
      continue;
    }
    if (code >= 0x20 && code !== 0x7f) {
      return true;
    }
    index += 1;
  }

  return false;
}

/**
 * Wraps `stdout.write` to detect the first non-empty frame. If nothing is
 * written before `timeoutMs`, invokes `onTimeout` so operators see a hard
 * failure instead of a silent blank TTY.
 */
export function armFirstFrameWatchdog(
  options: FirstFrameWatchdogOptions,
): FirstFrameWatchdog {
  const timeoutMs = options.timeoutMs ?? FIRST_FRAME_TIMEOUT_MS;
  let painted = false;
  let disposed = false;
  const stdout = options.stdout as NodeJS.WriteStream;
  const originalWrite: WriteFn = stdout.write.bind(stdout);

  const restore = (): void => {
    if (disposed) return;
    disposed = true;
    stdout.write = originalWrite;
    clearTimeout(timer);
  };

  const wrappedWrite: WriteFn = (
    chunk: string | Uint8Array,
    encodingOrCallback?: BufferEncoding | ((error?: Error | null) => void),
    callback?: (error?: Error | null) => void,
  ): boolean => {
    if (!painted) {
      const text =
        typeof chunk === 'string'
          ? chunk
          : Buffer.isBuffer(chunk)
            ? chunk.toString('utf8')
            : '';
      const size = typeof chunk === 'string' ? chunk.length : text.length;
      // Ignore bare cursor/mode probes under ~4 bytes, and any write that only
      // carries escape sequences; real frames contain visible text.
      if (size > 4 && carriesVisibleText(text)) {
        painted = true;
        restore();
      }
    }
    if (typeof encodingOrCallback === 'function') {
      return originalWrite(chunk, encodingOrCallback);
    }
    return originalWrite(chunk, encodingOrCallback, callback);
  };

  stdout.write = wrappedWrite;

  const timer = setTimeout(() => {
    if (painted || disposed) return;
    restore();
    const error = new FirstFrameTimeoutError(
      `${options.label}: no first frame painted within ${String(timeoutMs)}ms. ` +
        'The terminal stayed blank (often CI=1 making Ink non-interactive, or a 0×0 TTY). ' +
        'Retry on a real TTY; if this persists, unset CI and report a bug.',
    );
    if (options.onTimeout !== undefined) {
      options.onTimeout(error);
      return;
    }
    try {
      process.stderr.write(`${error.message}\n`);
    } catch {
      // stderr may already be closed during teardown
    }
  }, timeoutMs);
  if (typeof timer.unref === 'function') {
    timer.unref();
  }

  return {
    sawFrame: () => painted,
    dispose: restore,
  };
}
