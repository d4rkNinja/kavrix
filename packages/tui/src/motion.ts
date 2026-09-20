import { useEffect, useState } from 'react';

/**
 * OpenTUI-inspired motion tokens, ported to Ink. Character-cell motion only:
 * easing, stagger, and pulse clocks. Keyboard selection never uses these.
 */
export const MOTION = {
  enterMs: 180,
  exitMs: 140,
  feedbackMs: 120,
  pulseMs: 200,
  staggerMs: 28,
  staggerCap: 8,
  tickMs: 32,
  splashPulseMs: 180,
} as const;

export type MotionEase = 'linear' | 'outQuad' | 'outCubic' | 'outExpo';

export interface MotionPolicy {
  readonly animate: boolean;
}

function truthyFlag(value: string | undefined): boolean {
  if (value === undefined) return false;
  const normalized = value.trim().toLowerCase();
  return normalized === '1' || normalized === 'true' || normalized === 'yes';
}

/**
 * Fail closed: animation is off unless the caller requested it and the
 * environment is not reduced-motion / dumb-terminal. CI and non-TTY never
 * mount this package in production; tests may still request motion.
 */
export function resolveMotionPolicy(
  options: Readonly<{
    requested?: boolean;
    env?: NodeJS.ProcessEnv;
  }> = {},
): MotionPolicy {
  if (options.requested === false) return { animate: false };
  const env = options.env ?? process.env;
  if (
    truthyFlag(env['KAVRIX_TUI_REDUCED_MOTION']) ||
    truthyFlag(env['PREFERS_REDUCED_MOTION'])
  ) {
    return { animate: false };
  }
  return { animate: true };
}

export function clamp01(value: number): number {
  if (value <= 0) return 0;
  if (value >= 1) return 1;
  return value;
}

/** OpenTUI `outQuad` — default UI ease-out. */
export function easeOutQuad(t: number): number {
  const x = clamp01(t);
  return 1 - (1 - x) * (1 - x);
}

export function easeOutCubic(t: number): number {
  const x = clamp01(t);
  return 1 - (1 - x) ** 3;
}

/** OpenTUI `outExpo` — reserved for the authored splash settle. */
export function easeOutExpo(t: number): number {
  const x = clamp01(t);
  return x === 1 ? 1 : 1 - 2 ** (-10 * x);
}

export function applyEase(t: number, ease: MotionEase = 'outQuad'): number {
  switch (ease) {
    case 'linear':
      return clamp01(t);
    case 'outCubic':
      return easeOutCubic(t);
    case 'outExpo':
      return easeOutExpo(t);
    case 'outQuad':
      return easeOutQuad(t);
  }
}

/**
 * How many list rows have visually settled. Decorative only — callers must
 * keep the full list interactive while this climbs.
 */
export function staggerVisibleCount(
  elapsedMs: number,
  itemCount: number,
  staggerMs: number = MOTION.staggerMs,
  cap: number = MOTION.staggerCap,
): number {
  if (itemCount <= 0) return 0;
  if (elapsedMs < 0) return 1;
  const revealed = Math.min(itemCount, Math.floor(elapsedMs / staggerMs) + 1);
  const maxStaggered = Math.min(itemCount, cap);
  return revealed >= maxStaggered ? itemCount : revealed;
}

export function useMotionFrame(enabled: boolean, intervalMs: number): number {
  const [frame, setFrame] = useState(0);
  useEffect(() => {
    if (!enabled) return undefined;
    const interval = setInterval(() => {
      setFrame((value) => value + 1);
    }, intervalMs);
    return () => {
      clearInterval(interval);
    };
  }, [enabled, intervalMs]);
  return frame;
}

export function useElapsedMs(enabled: boolean): number {
  const [elapsedMs, setElapsedMs] = useState(0);
  useEffect(() => {
    if (!enabled) {
      setElapsedMs(0);
      return undefined;
    }
    const startedAt = Date.now();
    setElapsedMs(0);
    const interval = setInterval(() => {
      setElapsedMs(Date.now() - startedAt);
    }, MOTION.tickMs);
    return () => {
      clearInterval(interval);
    };
  }, [enabled]);
  return elapsedMs;
}

/**
 * 0→1 ease-out clock. Starts at 1 when disabled so renderToString snapshots
 * stay fully settled. Overlay mounts pass enabled=true to play an entrance.
 */
export function useEnterProgress(
  enabled: boolean,
  durationMs: number = MOTION.enterMs,
  ease: MotionEase = 'outQuad',
): number {
  const [progress, setProgress] = useState(enabled ? 0 : 1);
  useEffect(() => {
    if (!enabled) {
      setProgress(1);
      return undefined;
    }
    const startedAt = Date.now();
    setProgress(0);
    const interval = setInterval(() => {
      const next = applyEase((Date.now() - startedAt) / durationMs, ease);
      setProgress(next);
      if (next >= 1) clearInterval(interval);
    }, MOTION.tickMs);
    return () => {
      clearInterval(interval);
    };
  }, [enabled, durationMs, ease]);
  return progress;
}

export function enterOffsetCells(progress: number, enabled: boolean): number {
  if (!enabled || progress >= 1) return 0;
  return progress < 0.55 ? 1 : 0;
}

export function enterDimmed(progress: number, enabled: boolean): boolean {
  return enabled && progress < 0.4;
}
