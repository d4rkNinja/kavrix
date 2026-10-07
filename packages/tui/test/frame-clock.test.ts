import { afterEach, describe, expect, it, vi } from 'vitest';

import { FRAME_TICK_MS, subscribeToFrameClock } from '../src/frame-clock.js';

describe('bounded animation subscriptions', () => {
  afterEach(() => vi.useRealTimers());

  it('delivers the exact final frame and stops the idle timer', () => {
    vi.useFakeTimers({ toFake: ['setInterval', 'clearInterval', 'performance'] });
    const frames: number[] = [];
    const unsubscribe = subscribeToFrameClock((elapsed) => frames.push(elapsed), 40);
    expect(frames).toEqual([0]);
    vi.advanceTimersByTime(FRAME_TICK_MS * 3);
    expect(frames).toEqual([0, 32, 40]);
    expect(vi.getTimerCount()).toBe(0);
    vi.advanceTimersByTime(10_000);
    expect(frames).toEqual([0, 32, 40]);
    unsubscribe();
  });

  it('keeps a continuous subscriber alive after finite animations finish', () => {
    vi.useFakeTimers({ toFake: ['setInterval', 'clearInterval', 'performance'] });
    const finite = vi.fn();
    const continuous = vi.fn();
    const stopFinite = subscribeToFrameClock(finite, 32);
    const stopContinuous = subscribeToFrameClock(continuous);
    try {
      vi.advanceTimersByTime(96);
      expect(finite.mock.calls).toEqual([[0], [32]]);
      expect(continuous.mock.calls).toEqual([[0], [32], [64], [96]]);
      expect(vi.getTimerCount()).toBe(1);
    } finally {
      stopFinite();
      stopContinuous();
    }
    expect(vi.getTimerCount()).toBe(0);
  });

  it('settles zero-duration animations without starting a timer and rejects invalid durations', () => {
    vi.useFakeTimers();
    const frame = vi.fn();
    subscribeToFrameClock(frame, 0)();
    expect(frame.mock.calls).toEqual([[0]]);
    expect(vi.getTimerCount()).toBe(0);
    expect(() => subscribeToFrameClock(frame, -1)).toThrow(RangeError);
    expect(() => subscribeToFrameClock(frame, NaN)).toThrow(RangeError);
  });

  it('does not deliver to a subscription removed by another subscriber', () => {
    vi.useFakeTimers({ toFake: ['setInterval', 'clearInterval', 'performance'] });
    let removeSecond = (): void => undefined;
    const removeFirst = subscribeToFrameClock((elapsed) => {
      if (elapsed > 0) removeSecond();
    });
    const second = vi.fn();
    removeSecond = subscribeToFrameClock(second);
    try {
      vi.advanceTimersByTime(32);
      expect(second.mock.calls).toEqual([[0]]);
    } finally {
      removeFirst();
      removeSecond();
    }
  });
});
