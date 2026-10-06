import { useEffect, useState } from 'react';

import { FRAME_TICK_MS, subscribeToFrameClock } from './frame-clock.js';

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
  tickMs: FRAME_TICK_MS,
  splashPulseMs: 180,
  /** Wordmark line-by-line reveal on the splash (per line). */
  splashStageMs: 60,
  /** Underline sweep duration below the splash wordmark. */
  splashSweepMs: 520,
  /** Indeterminate sweep cadence for unknown-duration loads. */
  sweepMs: 90,
  /** Terminal-standard caret blink cadence for input overlays. */
  cursorBlinkMs: 530,
  /** Timed REVEAL window enforced by the backend/session policy. */
  revealWindowMs: 15_000,
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

/**
 * Counts whole `intervalMs` steps on the shared clock. The returned counter
 * advances exactly as a dedicated interval would have, but the process runs one
 * timer instead of one per animation, and no commit happens on ticks where this
 * particular animation has not actually stepped.
 */
export function useMotionFrame(enabled: boolean, intervalMs: number): number {
  const [frame, setFrame] = useState(0);
  useEffect(() => {
    if (!enabled) return undefined;
    let steps = 0;
    let lastStep = -1;
    return subscribeToFrameClock((elapsedMs) => {
      const step = Math.floor(elapsedMs / intervalMs);
      if (step === lastStep) return;
      if (lastStep >= 0) steps += step - lastStep;
      lastStep = step;
      setFrame(steps);
    });
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
    setElapsedMs(0);
    return subscribeToFrameClock((elapsed) => {
      setElapsedMs(Math.round(elapsed));
    });
  }, [enabled]);
  return elapsedMs;
}

/**
 * 0→1 ease-out clock. Starts at 1 when disabled so renderToString snapshots
 * stay fully settled. Overlay mounts pass enabled=true to play an entrance.
 *
 * The clock keeps driving the value once progress saturates; `enterOffsetCells`
 * and `enterDimmed` map every settled value to the same output, so subscribers
 * that only care about the visual result already stopped re-rendering.
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
    setProgress(0);
    return subscribeToFrameClock((elapsed) => {
      const next = applyEase(elapsed / durationMs, ease);
      setProgress(next);
    });
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

/** Integer character cells for a 0..1 progress across `width` cells. */
export function progressCells(progress: number, width: number): number {
  if (width <= 0) return 0;
  return Math.round(clamp01(progress) * width);
}

/**
 * Determinate bar row (OpenTUI ProgressBar pattern on a character grid).
 * Unicode `█`/`░`; printable ASCII `#`/`-` for --ascii / win32.
 */
export function barFill(progress: number, width: number, ascii: boolean): string {
  const size = Math.max(0, Math.floor(width));
  const filled = progressCells(progress, size);
  const head = ascii ? '#' : '\u2588';
  const rest = ascii ? '-' : '\u2591';
  return `${head.repeat(filled)}${rest.repeat(Math.max(0, size - filled))}`;
}

/**
 * Indeterminate sweep segment for unknown-duration work. A short bright
 * segment travels across the track and wraps; it is decorative and never
 * claims a percentage.
 */
export function sweepOffset(
  frame: number,
  trackWidth: number,
  segmentWidth: number,
): number {
  const track = Math.max(0, Math.floor(trackWidth));
  const segment = Math.max(1, Math.min(Math.floor(segmentWidth), track));
  if (track <= segment) return 0;
  return frame % (track - segment + 1);
}

export function sweepBarRow(
  frame: number,
  trackWidth: number,
  segmentWidth: number,
  ascii: boolean,
): string {
  const track = Math.max(0, Math.floor(trackWidth));
  const segment = Math.max(1, Math.min(Math.floor(segmentWidth), track));
  const offset = sweepOffset(frame, track, segment);
  const pad = ' '.repeat(offset);
  const body = ascii
    ? `[${'='.repeat(Math.max(0, segment - 2))}]`
    : `\u2588${'\u2593'.repeat(Math.max(0, segment - 2))}\u2588`;
  const tail = '\u2591'.repeat(Math.max(0, track - offset - segment));
  return `${pad}${body}${ascii ? tail.replace(/\u2591/gu, '-') : tail}`;
}

/** Whole seconds left on a timed reveal; never negative. */
export function revealRemainingMs(expiresAtMs: number, nowMs: number): number {
  return Math.max(0, expiresAtMs - nowMs);
}

/** 1 → just revealed, 0 → expired. Drives the countdown bar width. */
export function revealProgress(
  expiresAtMs: number,
  nowMs: number,
  windowMs: number = MOTION.revealWindowMs,
): number {
  if (expiresAtMs <= 0) return 0;
  return clamp01(revealRemainingMs(expiresAtMs, nowMs) / Math.max(1, windowMs));
}

/** Animated trailing dots for busy labels (`.`, `..`, `...`). */
export function animatedDots(frame: number, max = 3): string {
  if (max <= 0) return '';
  return '.'.repeat((Math.max(0, frame) % max) + 1);
}

/** Caret visibility for masked/plain input overlays; static when disabled. */
export function useCursorVisible(enabled: boolean): boolean {
  const frame = useMotionFrame(enabled, MOTION.cursorBlinkMs);
  return !enabled || frame % 2 === 0;
}
