import type { Writable } from 'node:stream';

const ANSI_ESCAPE = '\u001b';
const ANSI_RESET = `${ANSI_ESCAPE}[0m`;

export type TerminalStatusKind = 'info' | 'success' | 'warning' | 'error';

const STATUS_PRESENTATION: Readonly<
  Record<TerminalStatusKind, Readonly<{ marker: string; color: string }>>
> = Object.freeze({
  info: { marker: '[i]', color: '36' },
  success: { marker: '[OK]', color: '32' },
  warning: { marker: '[!]', color: '33' },
  error: { marker: '[X]', color: '31' },
});

/** Enables ANSI only for a capable TTY and honors the NO_COLOR convention. */
export function terminalColorEnabled(output: Writable): boolean {
  const isTTY = Reflect.get(output, 'isTTY') === true;
  return (
    isTTY && process.env['NO_COLOR'] === undefined && process.env['TERM'] !== 'dumb'
  );
}

/** Renders a status with a textual marker so color is always redundant. */
export function renderTerminalStatus(
  kind: TerminalStatusKind,
  message: string,
  color: boolean,
): string {
  const presentation = STATUS_PRESENTATION[kind];
  const marker = color
    ? `${ANSI_ESCAPE}[${presentation.color}m${presentation.marker}${ANSI_RESET}`
    : presentation.marker;
  return `${marker} ${message}\n`;
}

/** Renders a hidden-input prompt without incorporating secret data. */
export function renderTerminalPrompt(label: string, color: boolean): string {
  const marker = color ? `${ANSI_ESCAPE}[1;36m?${ANSI_RESET}` : '?';
  return `${marker} ${label} (input hidden): `;
}
