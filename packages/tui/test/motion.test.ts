import { PassThrough } from 'node:stream';

import { createElement, type ReactElement } from 'react';
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
import {
  DEFAULT_EXECUTABLE_NAME,
  DEFAULT_PRODUCT_LABEL,
  resolveProductIdentity,
} from '../src/product.js';
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
});

describe('product identity', () => {
  it('defaults to CredVault / creds and accepts overrides', () => {
    expect(resolveProductIdentity()).toEqual({
      productLabel: DEFAULT_PRODUCT_LABEL,
      executableName: DEFAULT_EXECUTABLE_NAME,
    });
    expect(resolveProductIdentity({ productLabel: '  ', executableName: '' })).toEqual({
      productLabel: 'CredVault',
      executableName: 'creds',
    });
    expect(
      resolveProductIdentity({ productLabel: 'VaultOne', executableName: 'vo' }),
    ).toEqual({
      productLabel: 'VaultOne',
      executableName: 'vo',
    });
  });
});
