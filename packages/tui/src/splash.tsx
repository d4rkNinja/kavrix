import { Box, Text } from 'ink';
import type { ReactElement } from 'react';

import {
  applyEase,
  barFill,
  MOTION,
  progressCells,
  resolveMotionPolicy,
  staggerVisibleCount,
  sweepBarRow,
  useElapsedMs,
  useMotionFrame,
} from './motion.js';
import { sanitizeTerminalText } from './terminal-text.js';

/** Braille spinner frames (unicode mode). */
export const SPLASH_SPINNER_FRAMES = [
  '\u280b',
  '\u2819',
  '\u2839',
  '\u2838',
  '\u283c',
  '\u2834',
  '\u2826',
  '\u2827',
  '\u2807',
  '\u2817',
] as const;

/** Printable ASCII spinner for --ascii / win32. */
export const SPLASH_ASCII_SPINNER_FRAMES = ['|', '/', '-', '\\'] as const;

export const SPLASH_MIN_MS = 0;
export const SPLASH_MAX_MS = 1_800;
export const SPLASH_ANIMATION_MS = 100;

const TAGLINE = 'local-first secrets firewall';

/**
 * Multi-line dual-tone wordmark (KAV / RIX). Pure presentation — no mocks.
 * ASCII mode keeps the same letter shapes without box-drawing.
 */
const WORDMARK_KAV = [
  '██╗  ██╗ █████╗ ██╗   ██╗',
  '██║ ██╔╝██╔══██╗██║   ██║',
  '█████╔╝ ███████║██║   ██║',
  '██╔═██╗ ██╔══██║╚██╗ ██╔╝',
  '██║  ██╗██║  ██║ ╚████╔╝ ',
  '╚═╝  ╚═╝╚═╝  ╚═╝  ╚═══╝  ',
] as const;

const WORDMARK_RIX = [
  '██████╗ ██╗██╗  ██╗',
  '██╔══██╗██║╚██╗██╔╝',
  '██████╔╝██║ ╚███╔╝ ',
  '██╔══██╗██║ ██╔██╗ ',
  '██║  ██║██║██╔╝ ██╗',
  '╚═╝  ╚═╝╚═╝╚═╝  ╚═╝',
] as const;

const WORDMARK_KAV_ASCII = [
  'K   K  AAA  V   V',
  'K  K  A   A V   V',
  'KKK   AAAAA V   V',
  'K  K  A   A  V V ',
  'K   K A   A   V  ',
] as const;

const WORDMARK_RIX_ASCII = [
  'RRRR  III X   X',
  'R   R  I   X X ',
  'RRRR   I    X  ',
  'R  R   I   X X ',
  'R   R III X   X',
] as const;

type Accent = 'cyan' | 'magenta' | 'blue' | 'green' | 'gray' | 'yellow' | 'white';

function tint(
  enabled: boolean,
  accent: Accent,
): Readonly<{ color: Accent }> | Readonly<Record<string, never>> {
  return enabled ? { color: accent } : {};
}

export interface SplashScreenProps {
  readonly color?: boolean;
  readonly ascii?: boolean;
  readonly version?: string;
  readonly width?: number;
  readonly height?: number;
  /** When false, still paints once but skips the animation timer (tests). */
  readonly animate?: boolean;
}

/**
 * Full-viewport animated Kavrix splash. Dual-tone KAV/RIX wordmark reveals
 * line-by-line, an eased underline sweeps beneath it, and an indeterminate
 * segment sweeps a track while the backend hydrates (no claimed percentage).
 * ASCII mode keeps the same choreography with printable glyphs.
 */
export function SplashScreen({
  color = true,
  ascii = false,
  version,
  width = 80,
  height: _height = 24,
  animate = true,
}: SplashScreenProps): ReactElement {
  void _height;
  const motion = resolveMotionPolicy({ requested: animate });
  const frame = useMotionFrame(motion.animate, MOTION.splashPulseMs);
  const sweepFrame = useMotionFrame(motion.animate, MOTION.sweepMs);
  const elapsedMs = useElapsedMs(motion.animate);
  const spinnerFrames = ascii ? SPLASH_ASCII_SPINNER_FRAMES : SPLASH_SPINNER_FRAMES;
  const spinner = spinnerFrames[frame % spinnerFrames.length] ?? '|';
  const kavLines = ascii ? WORDMARK_KAV_ASCII : WORDMARK_KAV;
  const rixLines = ascii ? WORDMARK_RIX_ASCII : WORDMARK_RIX;
  const kavAccent: Accent = 'white';
  const rixAccent: Accent = 'yellow';
  const gap = ascii ? '  ' : ' ';
  const safeTagline = sanitizeTerminalText(TAGLINE, ascii);
  const safeVersion =
    version === undefined || version.length === 0
      ? null
      : sanitizeTerminalText(`v${version.replace(/^v/iu, '')}`, ascii);

  const lineCount = kavLines.length;
  const visibleLines = motion.animate
    ? staggerVisibleCount(elapsedMs, lineCount, MOTION.splashStageMs, lineCount)
    : lineCount;
  const wordmarkWidth = kavLines[0].length + gap.length + rixLines[0].length;
  const underlineCells = motion.animate
    ? progressCells(
        applyEase(elapsedMs / MOTION.splashSweepMs, 'outExpo'),
        wordmarkWidth,
      )
    : wordmarkWidth;
  const underline = ascii
    ? '-'.repeat(underlineCells)
    : '\u2500'.repeat(underlineCells);
  const trackWidth = Math.min(28, Math.max(16, Math.floor(width / 2)));
  const track = motion.animate
    ? sweepBarRow(
        sweepFrame,
        trackWidth,
        Math.max(3, Math.floor(trackWidth / 5)),
        ascii,
      )
    : barFill(1, trackWidth, ascii);

  return (
    <Box
      flexDirection="column"
      width={Math.max(40, width)}
      alignItems="center"
      justifyContent="center"
    >
      <Box flexDirection="column" alignItems="flex-start">
        {kavLines.map((kavLine, index) => {
          const rixLine = rixLines[index] ?? '';
          const settled = index < visibleLines;
          return (
            <Box key={`wm-${String(index)}`} flexDirection="row">
              <Text bold {...tint(color, kavAccent)}>
                {settled ? kavLine : ' '.repeat(kavLine.length)}
              </Text>
              <Text>{gap}</Text>
              <Text bold {...tint(color, rixAccent)}>
                {settled ? rixLine : ' '.repeat(rixLine.length)}
              </Text>
            </Box>
          );
        })}
        <Text {...tint(color, rixAccent)}>{underline}</Text>
      </Box>
      <Box marginTop={1}>
        <Text {...tint(color, 'gray')}>{safeTagline}</Text>
      </Box>
      <Box marginTop={1} flexDirection="row" columnGap={1}>
        <Text {...tint(color, kavAccent)}>{spinner}</Text>
        {safeVersion === null ? (
          <Text {...tint(color, 'gray')}>loading</Text>
        ) : (
          <Text {...tint(color, 'gray')}>{safeVersion}</Text>
        )}
      </Box>
      <Box marginTop={1}>
        <Text {...tint(color, rixAccent)}>{track}</Text>
      </Box>
    </Box>
  );
}

/**
 * Whether the startup splash should mount. Skipped when `--no-splash` or
 * `KAVRIX_TUI_NO_SPLASH=1`. NO_COLOR / CI / non-TTY are handled by the CLI
 * mount gate before Ink starts.
 */
export function splashEnabled(
  options: Readonly<{
    noSplash?: boolean;
    env?: NodeJS.ProcessEnv;
  }> = {},
): boolean {
  if (options.noSplash === true) return false;
  const env = options.env ?? process.env;
  const flag = env['KAVRIX_TUI_NO_SPLASH'];
  if (flag !== undefined) {
    const normalized = flag.trim().toLowerCase();
    if (normalized === '1' || normalized === 'true' || normalized === 'yes') {
      return false;
    }
  }
  return resolveMotionPolicy({ env }).animate;
}

/**
 * Auto-dismiss when the backend is ready, or force at max duration.
 * An explicit minimum remains available to callers; the app imposes none.
 */
export function shouldDismissSplash(
  options: Readonly<{
    startedAtMs: number;
    nowMs: number;
    ready: boolean;
    minMs?: number;
    maxMs?: number;
  }>,
): boolean {
  const minMs = options.minMs ?? SPLASH_MIN_MS;
  const maxMs = options.maxMs ?? SPLASH_MAX_MS;
  const elapsed = Math.max(0, options.nowMs - options.startedAtMs);
  if (elapsed >= maxMs) return true;
  return options.ready && elapsed >= minMs;
}
