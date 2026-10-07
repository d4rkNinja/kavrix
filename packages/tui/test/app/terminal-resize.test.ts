import { EventEmitter } from 'node:events';
import { afterEach, expect, it, vi } from 'vitest';

import { subscribeToTerminalResize } from '../../src/app/terminal-resize.js';

afterEach(() => vi.useRealTimers());

it('coalesces resize storms using the latest dimensions without retaining an idle timer', () => {
  vi.useFakeTimers();
  const stdout = Object.assign(new EventEmitter(), { columns: 80 });
  const observed: number[] = [];
  const stop = subscribeToTerminalResize(stdout, () => observed.push(stdout.columns));
  try {
    for (let width = 81; width <= 120; width += 1) {
      stdout.columns = width;
      stdout.emit('resize');
    }
    expect(observed).toEqual([]);
    expect(vi.getTimerCount()).toBe(1);
    vi.advanceTimersByTime(32);
    expect(observed).toEqual([120]);
    expect(vi.getTimerCount()).toBe(0);
    stdout.columns = 60;
    stdout.emit('resize');
    vi.advanceTimersByTime(32);
    expect(observed).toEqual([120, 60]);
  } finally {
    stop();
  }
  expect(stdout.listenerCount('resize')).toBe(0);
});

it('cancels pending resize work when the app unmounts', () => {
  vi.useFakeTimers();
  const stdout = new EventEmitter();
  const update = vi.fn();
  const stop = subscribeToTerminalResize(stdout, update);
  stdout.emit('resize');
  stop();
  expect(vi.getTimerCount()).toBe(0);
  vi.advanceTimersByTime(100);
  stdout.emit('resize');
  vi.advanceTimersByTime(100);
  expect(update).not.toHaveBeenCalled();
});

it('releases each input hold when an update schedules another resize', () => {
  vi.useFakeTimers();
  const stdout = new EventEmitter();
  let holds = 0;
  let updates = 0;
  const stop = subscribeToTerminalResize(
    stdout,
    () => {
      updates += 1;
      if (updates === 1) stdout.emit('resize');
    },
    () => {
      holds += 1;
      return () => {
        holds -= 1;
      };
    },
  );
  try {
    stdout.emit('resize');
    expect(holds).toBe(1);
    vi.advanceTimersByTime(32);
    expect(holds).toBe(1);
    vi.advanceTimersByTime(32);
    expect(holds).toBe(0);
    expect(updates).toBe(2);
    stdout.emit('resize');
    expect(holds).toBe(1);
  } finally {
    stop();
  }
  expect(holds).toBe(0);
});
