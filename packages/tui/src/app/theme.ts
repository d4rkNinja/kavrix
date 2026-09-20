import type { AppTone } from './backend.js';

export type AppAccent =
  'cyan' | 'green' | 'yellow' | 'magenta' | 'blue' | 'red' | 'white' | 'gray';

/** Ink `borderStyle` keys we use for OpenTUI-like panels. */
export type PanelBorderStyle = 'round' | 'double' | 'single' | 'classic';

/**
 * Classic-premium chrome tokens. One accent (gold/yellow). Semantic colors
 * stay reserved for success / warning / danger — never rainbow decoration.
 */
export const CHROME = {
  accent: 'yellow',
  heading: 'white',
  muted: 'gray',
  success: 'green',
  warning: 'yellow',
  danger: 'red',
  info: 'cyan',
  paddingX: 1,
  paddingY: 0,
  modalPaddingX: 2,
  modalPaddingY: 1,
  modalMinWidth: 36,
  modalMaxWidth: 56,
} as const;

export function accentColor(
  enabled: boolean,
  accent: AppAccent,
): Readonly<{ color: AppAccent }> | Readonly<Record<string, never>> {
  return enabled ? { color: accent } : {};
}

export function resolveAppPresentation(
  options: Readonly<{
    color?: boolean;
    ascii?: boolean;
    platform?: NodeJS.Platform;
    noColor?: boolean;
    term?: string | undefined;
  }>,
): Readonly<{ color: boolean; ascii: boolean }> {
  const noColor =
    options.noColor === true ||
    process.env['NO_COLOR'] !== undefined ||
    options.term === 'dumb' ||
    process.env['TERM'] === 'dumb';
  const platform = options.platform ?? process.platform;
  const term = options.term ?? process.env['TERM'];
  const asciiDefault =
    options.ascii === true ||
    platform === 'win32' ||
    term === undefined ||
    term === 'dumb' ||
    /vt100|ansi(?!.*utf)/iu.test(term);
  return {
    color: options.color === false || noColor ? false : true,
    ascii: asciiDefault,
  };
}

export function toneAccent(tone: AppTone): AppAccent {
  switch (tone) {
    case 'success':
      return 'green';
    case 'warning':
      return 'yellow';
    case 'error':
      return 'red';
    case 'info':
      return 'cyan';
    case 'muted':
      return 'gray';
  }
}

export function pointerGlyph(ascii: boolean): string {
  return ascii ? '>' : '\u276f';
}

export function boxLine(ascii: boolean, width: number): string {
  const unit = ascii ? '-' : '\u2500';
  return unit.repeat(Math.max(8, width));
}

export function sectionTitle(label: string, ascii: boolean): string {
  return ascii ? `[ ${label.toUpperCase()} ]` : `\u2500 ${label} \u2500`;
}

/**
 * OpenTUI borderStyle mapping for Ink:
 * - unicode panels → `round` (╭─╮)
 * - unicode modals → `double` (╔═╗)
 * - ascii / win32 / --ascii → `classic` (+-+|) — ASCII-safe single border
 */
export function panelBorderStyle(
  ascii: boolean,
  kind: 'panel' | 'modal' = 'panel',
): PanelBorderStyle {
  if (ascii) return 'classic';
  return kind === 'modal' ? 'double' : 'round';
}

/**
 * Per-screen chrome accent. Default is the single gold accent; only
 * recovery (danger) and help (neutral) depart from it.
 */
export function screenAccent(screen: string): AppAccent {
  switch (screen) {
    case 'recovery':
      return CHROME.danger;
    case 'help':
      return CHROME.heading;
    default:
      return CHROME.accent;
  }
}

export function doctorStatusAccent(status: string): AppAccent {
  const normalized = status.toLowerCase();
  if (normalized === 'ok' || normalized === 'pass' || normalized === 'passed') {
    return 'green';
  }
  if (normalized === 'warn' || normalized === 'warning') {
    return 'yellow';
  }
  if (
    normalized === 'fail' ||
    normalized === 'failed' ||
    normalized === 'error' ||
    normalized === 'critical'
  ) {
    return 'red';
  }
  return 'gray';
}
