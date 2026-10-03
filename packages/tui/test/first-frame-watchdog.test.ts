import { PassThrough } from 'node:stream';

import { afterEach, describe, expect, it, vi } from 'vitest';

import {
  FIRST_FRAME_TIMEOUT_MS,
  FirstFrameTimeoutError,
  armFirstFrameWatchdog,
} from '../src/first-frame-watchdog.js';

class TestStdout extends PassThrough {
  override write(
    chunk: string | Uint8Array,
    encodingOrCallback?: BufferEncoding | ((error?: Error | null) => void),
    callback?: (error?: Error | null) => void,
  ): boolean {
    if (typeof encodingOrCallback === 'function') {
      encodingOrCallback(null);
      return true;
    }
    if (callback !== undefined) callback(null);
    return true;
  }
}

describe('armFirstFrameWatchdog', () => {
  const handles: { dispose: () => void }[] = [];

  afterEach(() => {
    for (const handle of handles.splice(0)) handle.dispose();
    vi.useRealTimers();
  });

  it('marks painted and disposes after a non-trivial string frame', () => {
    const stdout = new TestStdout();
    const watchdog = armFirstFrameWatchdog({
      stdout,
      label: 'test-string',
      timeoutMs: 5_000,
    });
    handles.push(watchdog);
    expect(watchdog.sawFrame()).toBe(false);
    stdout.write('HELLO FRAME');
    expect(watchdog.sawFrame()).toBe(true);
  });

  it('ignores tiny probes then accepts a Buffer frame', () => {
    const stdout = new TestStdout();
    const watchdog = armFirstFrameWatchdog({
      stdout,
      label: 'test-buffer',
      timeoutMs: 5_000,
    });
    handles.push(watchdog);
    stdout.write('ab');
    expect(watchdog.sawFrame()).toBe(false);
    stdout.write(Buffer.from('FRAME-BYTES'));
    expect(watchdog.sawFrame()).toBe(true);
  });

  it('supports write(chunk, callback) overload without painting on empty', () => {
    const stdout = new TestStdout();
    const watchdog = armFirstFrameWatchdog({
      stdout,
      label: 'test-cb',
      timeoutMs: 5_000,
    });
    handles.push(watchdog);
    const cb = vi.fn();
    stdout.write(Buffer.alloc(0), cb);
    expect(cb).toHaveBeenCalled();
    expect(watchdog.sawFrame()).toBe(false);
  });

  it('fires onTimeout when no frame arrives before timeoutMs', () => {
    vi.useFakeTimers();
    const stdout = new TestStdout();
    const onTimeout = vi.fn();
    const watchdog = armFirstFrameWatchdog({
      stdout,
      label: 'test-timeout',
      timeoutMs: 50,
      onTimeout,
    });
    handles.push(watchdog);
    expect(watchdog.sawFrame()).toBe(false);
    vi.advanceTimersByTime(50);
    expect(onTimeout).toHaveBeenCalledTimes(1);
    const error = onTimeout.mock.calls[0]?.[0] as FirstFrameTimeoutError | undefined;
    expect(error).toBeInstanceOf(FirstFrameTimeoutError);
    expect(error?.message).toMatch(/test-timeout/);
    expect(error?.message).toMatch(/50ms/);
  });

  it('writes stderr when onTimeout is omitted', () => {
    vi.useFakeTimers();
    const stdout = new TestStdout();
    const writeErr = vi.spyOn(process.stderr, 'write').mockImplementation(() => true);
    const watchdog = armFirstFrameWatchdog({
      stdout,
      label: 'test-stderr',
      timeoutMs: 25,
    });
    handles.push(watchdog);
    vi.advanceTimersByTime(25);
    expect(writeErr).toHaveBeenCalled();
    expect(String(writeErr.mock.calls[0]?.[0])).toMatch(/test-stderr/);
    writeErr.mockRestore();
  });

  it('dispose is idempotent and prevents timeout', () => {
    vi.useFakeTimers();
    const stdout = new TestStdout();
    const onTimeout = vi.fn();
    const watchdog = armFirstFrameWatchdog({
      stdout,
      label: 'test-dispose',
      timeoutMs: 40,
      onTimeout,
    });
    handles.push(watchdog);
    watchdog.dispose();
    watchdog.dispose();
    vi.advanceTimersByTime(40);
    expect(onTimeout).not.toHaveBeenCalled();
    expect(watchdog.sawFrame()).toBe(false);
  });

  it('defaults timeout to FIRST_FRAME_TIMEOUT_MS', () => {
    expect(FIRST_FRAME_TIMEOUT_MS).toBe(2_500);
    vi.useFakeTimers();
    const stdout = new TestStdout();
    const onTimeout = vi.fn();
    const watchdog = armFirstFrameWatchdog({
      stdout,
      label: 'test-default-timeout',
      onTimeout,
    });
    handles.push(watchdog);
    vi.advanceTimersByTime(FIRST_FRAME_TIMEOUT_MS - 1);
    expect(onTimeout).not.toHaveBeenCalled();
    vi.advanceTimersByTime(1);
    expect(onTimeout).toHaveBeenCalledTimes(1);
  });

  it('treats non-Buffer Uint8Array as size 0 and accepts encoding overload', () => {
    const stdout = new TestStdout();
    const watchdog = armFirstFrameWatchdog({
      stdout,
      label: 'test-uint8',
      timeoutMs: 5_000,
    });
    handles.push(watchdog);
    const probe = new Uint8Array([1, 2, 3, 4, 5, 6, 7, 8]);
    // Not a Buffer — size branch counts as 0 so the frame is ignored.
    stdout.write(probe);
    expect(watchdog.sawFrame()).toBe(false);
    stdout.write('PAINTED', 'utf8');
    expect(watchdog.sawFrame()).toBe(true);
  });

  it('does not mistake alternate-screen and mouse mode sets for a frame', () => {
    const stdout = new TestStdout();
    const watchdog = armFirstFrameWatchdog({
      stdout,
      label: 'test-modes',
      timeoutMs: 5_000,
    });
    handles.push(watchdog);

    stdout.write('\u001B[?1049h');
    expect(watchdog.sawFrame()).toBe(false);
    stdout.write('\u001B[?25l');
    expect(watchdog.sawFrame()).toBe(false);
    stdout.write('\u001B[?1000h\u001B[?1006h');
    expect(watchdog.sawFrame()).toBe(false);
    stdout.write('\u001B[2K\u001B[1A\u001B[G');
    expect(watchdog.sawFrame()).toBe(false);

    stdout.write('\u001B[2K\u001B[1Akavrix\u001B[?25l');
    expect(watchdog.sawFrame()).toBe(true);
  });

  it('accepts a frame whose visible text is shorter than a mode set', () => {
    const stdout = new TestStdout();
    const watchdog = armFirstFrameWatchdog({
      stdout,
      label: 'test-short-frame',
      timeoutMs: 5_000,
    });
    handles.push(watchdog);

    stdout.write('\u001B[2K\u001B[1Ahi\n');
    expect(watchdog.sawFrame()).toBe(true);
  });

  it('fires onTimeout when only mode sets are written before timeoutMs', () => {
    vi.useFakeTimers();
    const stdout = new TestStdout();
    const onTimeout = vi.fn();
    const watchdog = armFirstFrameWatchdog({
      stdout,
      label: 'test-modes-timeout',
      timeoutMs: 50,
      onTimeout,
    });
    handles.push(watchdog);

    stdout.write('\u001B[?1049h\u001B[?25l');
    vi.advanceTimersByTime(50);
    expect(onTimeout).toHaveBeenCalledTimes(1);
  });

  it('swallows stderr write failures when onTimeout is omitted', () => {
    vi.useFakeTimers();
    const stdout = new TestStdout();
    const writeErr = vi.spyOn(process.stderr, 'write').mockImplementation(() => {
      throw new Error('stderr closed');
    });
    const watchdog = armFirstFrameWatchdog({
      stdout,
      label: 'test-stderr-throw',
      timeoutMs: 20,
    });
    handles.push(watchdog);
    expect(() => vi.advanceTimersByTime(20)).not.toThrow();
    expect(writeErr).toHaveBeenCalled();
    writeErr.mockRestore();
  });

  describe('escape sequences that paint nothing', () => {
    function watchdogFor(label: string): {
      stdout: TestStdout;
      watchdog: { sawFrame: () => boolean; dispose: () => void };
    } {
      const stdout = new TestStdout();
      const watchdog = armFirstFrameWatchdog({
        stdout,
        label,
        timeoutMs: 5_000,
      });
      handles.push(watchdog);
      return { stdout, watchdog };
    }

    it('ignores an OSC sequence terminated by BEL', () => {
      const { stdout, watchdog } = watchdogFor('test-osc-bel');
      // Window-title and clipboard sequences carry text a user never sees on the
      // grid, so they must not be mistaken for a painted frame.
      stdout.write('\u001B]0;kavrix\u0007');
      expect(watchdog.sawFrame()).toBe(false);
    });

    it('ignores an OSC sequence terminated by ST', () => {
      const { stdout, watchdog } = watchdogFor('test-osc-st');
      stdout.write('\u001B]11;rgb:1e1e/1e1e/1e1e\u001B\\');
      expect(watchdog.sawFrame()).toBe(false);
    });

    it('ignores an unterminated OSC sequence', () => {
      const { stdout, watchdog } = watchdogFor('test-osc-open');
      stdout.write('\u001B]0;never-closed');
      expect(watchdog.sawFrame()).toBe(false);
    });

    it('finds visible text after a completed OSC sequence', () => {
      const { stdout, watchdog } = watchdogFor('test-osc-then-text');
      stdout.write('\u001B]0;kavrix\u0007');
      expect(watchdog.sawFrame()).toBe(false);
      stdout.write('kavrix');
      expect(watchdog.sawFrame()).toBe(true);
    });

    it('ignores a two-byte escape that introduces nothing visible', () => {
      const { stdout, watchdog } = watchdogFor('test-esc-pair');
      // ESC followed by a single non-CSI byte: consumed as a pair, never text.
      stdout.write('\u001B\u001B\u001B\u0007\u0000\u0001');
      expect(watchdog.sawFrame()).toBe(false);
    });

    it('ignores an unterminated CSI sequence', () => {
      const { stdout, watchdog } = watchdogFor('test-csi-open');
      stdout.write('\u001B[2;1;1');
      expect(watchdog.sawFrame()).toBe(false);
    });

    it('ignores a chunk of control bytes with no printable character', () => {
      const { stdout, watchdog } = watchdogFor('test-controls');
      stdout.write('\u0000\u0001\u001F\u007F');
      expect(watchdog.sawFrame()).toBe(false);
    });
  });
});
