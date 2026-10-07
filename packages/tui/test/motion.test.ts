import { PassThrough } from 'node:stream';

import { createElement, useRef, type ReactElement } from 'react';
import { render, renderToString, Text } from 'ink';
import { describe, expect, it, vi } from 'vitest';

import {
  applyEase,
  clamp01,
  easeOutCubic,
  easeOutExpo,
  easeOutQuad,
  enterDimmed,
  enterOffsetCells,
  MOTION,
  resolveMotionPolicy,
  staggerVisibleCount,
  useElapsedMs,
  useEnterProgress,
  useMotionFrame,
  type MotionEase,
} from '../src/motion.js';
import { EXECUTABLE_NAME, PRODUCT_LABEL } from '../src/product.js';
import { splashEnabled } from '../src/splash.js';

class TestOutput extends PassThrough {
  columns = 80;
  rows = 12;
  readonly isTTY = true;
}

interface ProbeSample {
  frame: number;
  elapsedMs: number;
  progress: number;
}

interface ProbeProps {
  readonly frameEnabled: boolean;
  readonly elapsedEnabled: boolean;
  readonly enterEnabled: boolean;
  readonly durationMs: number;
  readonly ease: MotionEase;
  readonly onSample: (sample: ProbeSample) => void;
}

function MotionProbe(props: ProbeProps): ReactElement {
  const frame = useMotionFrame(props.frameEnabled, MOTION.tickMs);
  const elapsedMs = useElapsedMs(props.elapsedEnabled);
  const progress = useEnterProgress(props.enterEnabled, props.durationMs, props.ease);
  props.onSample({ frame, elapsedMs, progress });
  return createElement(Text, null, [frame, elapsedMs, progress].join(':'));
}

function EnterDefaultsProbe(props: {
  readonly enabled: boolean;
  readonly onSample: (progress: number) => void;
}): ReactElement {
  const progress = useEnterProgress(props.enabled);
  props.onSample(progress);
  return createElement(Text, null, String(progress));
}

/**
 * Renders one animation per cadence, all on the shared clock. Used to prove
 * that several animations at different cadences cost one timer, not one each.
 */
function CadenceProbe(props: {
  readonly cadences: readonly number[];
  readonly onSample: (frames: readonly number[]) => void;
  readonly onFrame: (value: number) => void;
}): ReactElement {
  const frames = props.cadences.map((intervalMs) =>
    useMotionFrameAt(intervalMs, props.onFrame),
  );
  props.onSample(frames);
  return createElement(Text, null, frames.join(':'));
}

/**
 * Hook wrapper that reports only the times this cadence actually stepped, which
 * is the signal that unrelated shared ticks are not repainting it.
 */
function useMotionFrameAt(intervalMs: number, onStep: (value: number) => void): number {
  const frame = useMotionFrame(true, intervalMs);
  const reported = useRef<number>(-1);
  if (frame !== reported.current) {
    reported.current = frame;
    onStep(frame);
  }
  return frame;
}

function mountProbe(
  props: Omit<ProbeProps, 'onSample'>,
  latest: ProbeSample,
): ReturnType<typeof render> {
  const stdout = new TestOutput();
  return render(
    createElement(MotionProbe, {
      ...props,
      onSample: (sample) => {
        latest.frame = sample.frame;
        latest.elapsedMs = sample.elapsedMs;
        latest.progress = sample.progress;
      },
    }),
    {
      stdout: stdout as unknown as NodeJS.WriteStream,
      interactive: true,
      exitOnCtrlC: false,
      patchConsole: false,
    },
  );
}

async function unmountProbe(instance: ReturnType<typeof render>): Promise<void> {
  instance.unmount();
  await instance.waitUntilExit();
}

describe('motion policy', () => {
  it('animates by default and fail-closes on reduced-motion flags', () => {
    expect(resolveMotionPolicy({ env: {} }).animate).toBe(true);
    expect(resolveMotionPolicy({ requested: true, env: {} }).animate).toBe(true);
    expect(resolveMotionPolicy({ requested: false, env: {} }).animate).toBe(false);
    expect(
      resolveMotionPolicy({ env: { KAVRIX_TUI_REDUCED_MOTION: '1' } }).animate,
    ).toBe(false);
    expect(
      resolveMotionPolicy({ env: { PREFERS_REDUCED_MOTION: 'true' } }).animate,
    ).toBe(false);
    expect(
      resolveMotionPolicy({ env: { KAVRIX_TUI_REDUCED_MOTION: ' yes ' } }).animate,
    ).toBe(false);
    expect(
      resolveMotionPolicy({ env: { PREFERS_REDUCED_MOTION: 'YES' } }).animate,
    ).toBe(false);
    expect(
      resolveMotionPolicy({ env: { KAVRIX_TUI_REDUCED_MOTION: '0' } }).animate,
    ).toBe(true);
  });

  it('reads process.env when the caller omits an env bag', () => {
    expect(resolveMotionPolicy()).toEqual(resolveMotionPolicy({ env: process.env }));
    expect(resolveMotionPolicy({ requested: true })).toEqual(
      resolveMotionPolicy({ requested: true, env: process.env }),
    );
  });

  it('skips splash when reduced motion is set', () => {
    expect(splashEnabled({ env: {} })).toBe(true);
    expect(splashEnabled({ env: { KAVRIX_TUI_REDUCED_MOTION: '1' } })).toBe(false);
    expect(splashEnabled({ noSplash: true, env: {} })).toBe(false);
  });
});

describe('easing and stagger', () => {
  it('uses OpenTUI outQuad / outExpo and keeps stagger decorative', () => {
    expect(clamp01(-1)).toBe(0);
    expect(clamp01(0.4)).toBe(0.4);
    expect(clamp01(2)).toBe(1);
    expect(easeOutQuad(0)).toBe(0);
    expect(easeOutQuad(1)).toBe(1);
    expect(easeOutQuad(0.5)).toBeGreaterThan(0.5);
    expect(easeOutCubic(0.5)).toBeGreaterThan(easeOutQuad(0.5));
    expect(easeOutExpo(0.5)).toBeGreaterThan(0.5);
    expect(easeOutExpo(1)).toBe(1);
    expect(applyEase(0.25)).toBe(easeOutQuad(0.25));
    expect(applyEase(0.25, 'linear')).toBe(0.25);
    expect(applyEase(0.25, 'outCubic')).toBe(easeOutCubic(0.25));
    expect(applyEase(0.25, 'outExpo')).toBe(easeOutExpo(0.25));
    expect(applyEase(0.25, 'outQuad')).toBe(easeOutQuad(0.25));
    expect(staggerVisibleCount(0, 0)).toBe(0);
    expect(staggerVisibleCount(40, -2)).toBe(0);
    expect(staggerVisibleCount(-8, 12)).toBe(1);
    expect(staggerVisibleCount(0, 12, MOTION.staggerMs)).toBe(1);
    expect(staggerVisibleCount(MOTION.staggerMs * 3, 12)).toBe(4);
    expect(staggerVisibleCount(MOTION.staggerMs * MOTION.staggerCap, 12)).toBe(12);
    expect(enterOffsetCells(0.2, false)).toBe(0);
    expect(enterOffsetCells(0.2, true)).toBe(1);
    expect(enterOffsetCells(0.7, true)).toBe(0);
    expect(enterOffsetCells(1, true)).toBe(0);
    expect(enterDimmed(0.2, false)).toBe(false);
    expect(enterDimmed(0.2, true)).toBe(true);
    expect(enterDimmed(1, true)).toBe(false);
  });
});

describe('motion clocks', () => {
  it('releases the entrance timer while the component stays mounted', async () => {
    const clearTimer = vi.spyOn(globalThis, 'clearInterval');
    const latest: ProbeSample = { frame: 0, elapsedMs: 0, progress: -1 };
    const instance = mountProbe(
      {
        frameEnabled: false,
        elapsedEnabled: false,
        enterEnabled: true,
        durationMs: 40,
        ease: 'linear',
      },
      latest,
    );
    try {
      await vi.waitFor(() => {
        expect(latest.progress).toBe(1);
        expect(clearTimer).toHaveBeenCalled();
      });
    } finally {
      await unmountProbe(instance);
      clearTimer.mockRestore();
    }
  });
  it('keeps disabled clocks settled for static snapshots', () => {
    const latest: ProbeSample = { frame: -1, elapsedMs: -1, progress: -1 };
    const painted = renderToString(
      createElement(MotionProbe, {
        frameEnabled: false,
        elapsedEnabled: false,
        enterEnabled: false,
        durationMs: MOTION.enterMs,
        ease: 'outQuad',
        onSample: (sample) => {
          latest.frame = sample.frame;
          latest.elapsedMs = sample.elapsedMs;
          latest.progress = sample.progress;
        },
      }),
    );
    expect(latest).toEqual({ frame: 0, elapsedMs: 0, progress: 1 });
    expect(painted).toContain('0:0:1');

    let defaulted = -1;
    renderToString(
      createElement(EnterDefaultsProbe, {
        enabled: false,
        onSample: (progress) => {
          defaulted = progress;
        },
      }),
    );
    expect(defaulted).toBe(1);
  });

  it('starts enter progress at 0, then resets clocks when disabled', async () => {
    const latest: ProbeSample = { frame: -1, elapsedMs: -1, progress: -1 };
    const props = {
      frameEnabled: false,
      elapsedEnabled: false,
      enterEnabled: false,
      durationMs: MOTION.enterMs,
      ease: 'outQuad' as const,
    };
    const instance = mountProbe(props, latest);
    try {
      await instance.waitUntilRenderFlush();
      expect(latest.progress).toBe(1);
      expect(latest.elapsedMs).toBe(0);
      expect(latest.frame).toBe(0);

      instance.rerender(
        createElement(MotionProbe, {
          ...props,
          frameEnabled: true,
          elapsedEnabled: true,
          enterEnabled: true,
          durationMs: 2_000,
          onSample: (sample) => {
            latest.frame = sample.frame;
            latest.elapsedMs = sample.elapsedMs;
            latest.progress = sample.progress;
          },
        }),
      );
      await vi.waitFor(
        () => {
          expect(latest.frame).toBeGreaterThan(0);
          expect(latest.elapsedMs).toBeGreaterThan(0);
          expect(latest.progress).toBeGreaterThan(0);
          expect(latest.progress).toBeLessThan(1);
        },
        { timeout: 2_000, interval: 16 },
      );

      instance.rerender(
        createElement(MotionProbe, {
          ...props,
          onSample: (sample) => {
            latest.frame = sample.frame;
            latest.elapsedMs = sample.elapsedMs;
            latest.progress = sample.progress;
          },
        }),
      );
      await vi.waitFor(
        () => {
          expect(latest.elapsedMs).toBe(0);
          expect(latest.progress).toBe(1);
        },
        { timeout: 1_000, interval: 16 },
      );
    } finally {
      await unmountProbe(instance);
    }
  });

  it('advances enter progress to 1 and clears the interval', async () => {
    const latest: ProbeSample = { frame: 0, elapsedMs: 0, progress: -1 };
    const instance = mountProbe(
      {
        frameEnabled: true,
        elapsedEnabled: true,
        enterEnabled: true,
        durationMs: 40,
        ease: 'linear',
      },
      latest,
    );
    try {
      await instance.waitUntilRenderFlush();
      expect(latest.progress).toBe(0);
      await vi.waitFor(
        () => {
          expect(latest.progress).toBe(1);
          expect(latest.frame).toBeGreaterThan(0);
          expect(latest.elapsedMs).toBeGreaterThan(0);
        },
        { timeout: 2_000, interval: 16 },
      );
    } finally {
      await unmountProbe(instance);
    }
  });

  it('runs one timer for many animations with different cadences', async () => {
    const createTimer = vi.spyOn(globalThis, 'setInterval');
    const samples: number[] = [];
    try {
      const stdout = new TestOutput();
      const instance = render(
        createElement(CadenceProbe, {
          cadences: [MOTION.sweepMs, MOTION.splashPulseMs, MOTION.tickMs],
          onSample: () => undefined,
          onFrame: (value: number) => samples.push(value),
        }),
        {
          stdout: stdout as unknown as NodeJS.WriteStream,
          interactive: true,
          patchConsole: false,
        },
      );
      try {
        await vi.waitFor(
          () => {
            expect(samples.length).toBeGreaterThan(3);
          },
          { timeout: 2_000, interval: 16 },
        );
        // Three animations at three different cadences share a single timer.
        // Independent intervals would have created three.
        expect(createTimer).toHaveBeenCalledTimes(1);
      } finally {
        await unmountProbe(instance);
      }
    } finally {
      createTimer.mockRestore();
    }
  });

  it('steps an animation only on the shared ticks it has reached', async () => {
    const frames: number[] = [];
    const stdout = new TestOutput();
    const instance = render(
      createElement(CadenceProbe, {
        // Far slower than the shared tick, so most ticks must not step it.
        cadences: [MOTION.tickMs * 20],
        onSample: () => undefined,
        onFrame: (value: number) => frames.push(value),
      }),
      {
        stdout: stdout as unknown as NodeJS.WriteStream,
        interactive: true,
        patchConsole: false,
      },
    );
    try {
      await vi.waitFor(
        () => {
          expect(frames.length).toBeGreaterThan(0);
        },
        { timeout: 3_000, interval: 16 },
      );
      // Frames advance in whole cadence steps, never once per shared tick.
      const distinct = [...new Set(frames)];
      expect(distinct).toEqual([...distinct].sort((left, right) => left - right));
    } finally {
      await unmountProbe(instance);
    }
  });
});

describe('product identity', () => {
  it('is kavrix everywhere — no legacy brand remains', () => {
    expect(PRODUCT_LABEL).toBe('kavrix');
    expect(EXECUTABLE_NAME).toBe('kavrix');
  });
});
