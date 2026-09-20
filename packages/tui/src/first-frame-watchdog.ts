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
      const size =
        typeof chunk === 'string'
          ? chunk.length
          : Buffer.isBuffer(chunk)
            ? chunk.length
            : 0;
      // Ignore bare cursor/mode probes under ~4 bytes; real frames are larger.
      if (size > 4) {
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
