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
});
