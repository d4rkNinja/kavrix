import type { AppTone } from './backend.js';

export type AppAccent =
  | 'cyan'
  | 'green'
  | 'yellow'
  | 'magenta'
  | 'blue'
  | 'red'
  | 'white'
  | 'gray';

export function resolveAppPresentation(options: Readonly<{
  color?: boolean;
  ascii?: boolean;
  platform?: NodeJS.Platform;
  noColor?: boolean;
  term?: string | undefined;
}>): Readonly<{ color: boolean; ascii: boolean }> {
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
