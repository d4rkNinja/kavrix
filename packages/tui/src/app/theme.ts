import type { AppTone } from './backend.js';

export type AppAccent =
  'cyan' | 'green' | 'yellow' | 'magenta' | 'blue' | 'red' | 'white' | 'gray';

/** Ink `borderStyle` keys we use for OpenTUI-like panels. */
export type PanelBorderStyle = 'round' | 'double' | 'single' | 'classic';

/**
 * Selectable TUI color themes. Each theme is a complete, distinct palette:
 * primary accent, heading, selection highlight, progress-bar color, and a
 * panel border style. Semantic status colors (success / warning / danger /
 * info) stay fixed across themes so `[ok]` / `[!]` / `[x]` rows remain
 * unambiguous everywhere.
 *
 * Themes use the terminal's named ANSI colors rather than hardcoded RGB, so
 * each palette adapts to the host terminal scheme (Windows Terminal Campbell,
 * macOS Terminal.app / iTerm2, Linux terminal palettes) instead of fighting
 * it. `NO_COLOR` and dumb terminals keep the existing colorless behavior.
 */
export type ThemeId = 'gold' | 'ocean' | 'magma' | 'forest' | 'violet';

export interface TuiTheme {
  readonly id: ThemeId;
  readonly label: string;
  readonly description: string;
  readonly accent: AppAccent;
  readonly heading: AppAccent;
  readonly selection: AppAccent;
  readonly bar: AppAccent;
  readonly panelBorder: 'round' | 'single' | 'double';
}

export const THEMES: readonly TuiTheme[] = [
  {
    id: 'gold',
    label: 'Classic Gold',
    description: 'Warm gold accent on quiet white — the Kavrix signature.',
    accent: 'yellow',
    heading: 'white',
    selection: 'cyan',
    bar: 'yellow',
    panelBorder: 'round',
  },
  {
    id: 'ocean',
    label: 'Deep Ocean',
    description: 'Cool cyan accent with blue headings and square panels.',
    accent: 'cyan',
    heading: 'blue',
    selection: 'blue',
    bar: 'cyan',
    panelBorder: 'single',
  },
  {
    id: 'magma',
    label: 'Magma',
    description: 'Hot red accent, magenta highlights, heavy double panels.',
    accent: 'red',
    heading: 'magenta',
    selection: 'magenta',
    bar: 'red',
    panelBorder: 'double',
  },
  {
    id: 'forest',
    label: 'Forest',
    description: 'Calm green accent and green-tinted chrome throughout.',
    accent: 'green',
    heading: 'green',
    selection: 'green',
    bar: 'green',
    panelBorder: 'round',
  },
  {
    id: 'violet',
    label: 'Violet Dusk',
    description: 'Purple accent with blue selection and framed panels.',
    accent: 'magenta',
    heading: 'magenta',
    selection: 'blue',
    bar: 'magenta',
    panelBorder: 'double',
  },
];

export const TUI_THEME_IDS: readonly ThemeId[] = THEMES.map((theme) => theme.id);

export function isThemeId(value: string): value is ThemeId {
  return THEMES.some((theme) => theme.id === value);
}

/**
 * Platform default theme. Windows Terminal's Campbell scheme is
 * blue/cyan-harmonized, so `ocean` is the default there; macOS and Linux
 * terminals keep the brand `gold`. Users override through the TUI picker,
 * `kavrix tui --theme`, or `KAVRIX_TUI_THEME`.
 */
export function defaultThemeForPlatform(platform: NodeJS.Platform): ThemeId {
  return platform === 'win32' ? 'ocean' : 'gold';
}

interface ChromeTokens {
  accent: AppAccent;
  heading: AppAccent;
  muted: AppAccent;
  success: AppAccent;
  warning: AppAccent;
  danger: AppAccent;
  info: AppAccent;
  selection: AppAccent;
  bar: AppAccent;
  paddingX: number;
  paddingY: number;
  modalPaddingX: number;
  modalPaddingY: number;
  modalMinWidth: number;
  modalMaxWidth: number;
}

/**
 * Classic-premium chrome tokens for the active theme. One accent per theme;
 * semantic colors stay reserved for success / warning / danger — never
 * rainbow decoration. Mutable theme fields are swapped only through
 * {@link applyTuiTheme}; layout constants never change.
 */
export const CHROME: ChromeTokens = {
  accent: 'yellow',
  heading: 'white',
  muted: 'gray',
  success: 'green',
  warning: 'yellow',
  danger: 'red',
  info: 'cyan',
  selection: 'cyan',
  bar: 'yellow',
  paddingX: 1,
  paddingY: 0,
  modalPaddingX: 2,
  modalPaddingY: 1,
  modalMinWidth: 36,
  modalMaxWidth: 56,
};

let activeThemeId: ThemeId = defaultThemeForPlatform(process.platform);

applyTuiTheme(activeThemeId);

/** Installs one theme's color tokens as the active chrome. */
export function applyTuiTheme(id: ThemeId): TuiTheme {
  const theme = THEMES.find((candidate) => candidate.id === id);
  if (theme === undefined) {
    throw new Error(`Unknown TUI theme: ${id}`);
  }
  activeThemeId = theme.id;
  CHROME.accent = theme.accent;
  CHROME.heading = theme.heading;
  CHROME.selection = theme.selection;
  CHROME.bar = theme.bar;
  return theme;
}

export function activeTuiThemeId(): ThemeId {
  return activeThemeId;
}

export function activeTuiTheme(): TuiTheme {
  const theme = THEMES.find((candidate) => candidate.id === activeThemeId);
  if (theme === undefined) throw new Error('No active TUI theme is installed.');
  return theme;
}

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
 * OpenTUI borderStyle mapping for Ink. The active theme picks the unicode
 * panel border; modals always frame with `double` so confirmations stay
 * visually distinct from panels; ascii / win32 / --ascii degrade to the
 * `classic` (+-+|) ASCII-safe border regardless of theme.
 */
export function panelBorderStyle(
  ascii: boolean,
  kind: 'panel' | 'modal' = 'panel',
): PanelBorderStyle {
  if (ascii) return 'classic';
  if (kind === 'modal') return 'double';
  return activeTuiTheme().panelBorder;
}

/**
 * Per-screen chrome accent. Default is the active theme accent; only
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

/**
 * Leading status glyph for notice/feedback rows. Unicode keeps wordless
 * shapes; ASCII stays inside `[OK]`-style printable tokens.
 */
export function toneGlyph(tone: AppTone, ascii: boolean): string {
  switch (tone) {
    case 'success':
      return ascii ? '[ok]' : ' \u2713 ';
    case 'warning':
      return ascii ? '[!]' : ' \u26a0 ';
    case 'error':
      return ascii ? '[x]' : ' \u2715 ';
    case 'info':
      return ascii ? '[i]' : ' \u2139 ';
    case 'muted':
      return ascii ? ' - ' : ' \u00b7 ';
  }
}

/** Variable-length masked-input bullets; ASCII mode keeps `*` only. */
export function maskBullets(length: number, ascii: boolean, max = 32): string {
  const unit = ascii ? '*' : '\u2022';
  return unit.repeat(Math.max(0, Math.min(max, Math.floor(length))));
}

/** Full-width horizontal rule used as a soft section divider. */
export function dividerRule(ascii: boolean, width: number): string {
  const unit = ascii ? '-' : '\u2500';
  return unit.repeat(Math.max(0, Math.floor(width)));
}

/**
 * Section title padded to a full rule so headers anchor the whole panel
 * width: `─ LABEL ─────────` / `[ LABEL ]` (ASCII keeps its bracket form,
 * which docs and tests already lock in).
 */
export function sectionTitleWide(label: string, ascii: boolean, width: number): string {
  if (ascii) return sectionTitle(label, ascii);
  const text = ` \u2500 ${label.toUpperCase()} \u2500 `;
  const room = Math.floor(width) - text.length;
  if (room <= 0) return text.trim();
  return `${text}${'\u2500'.repeat(room)}`;
}
