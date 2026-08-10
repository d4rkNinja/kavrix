const REPLACEMENT = '\uFFFD';
const ESCAPE = 0x1b;
const BELL = 0x07;
const STRING_TERMINATOR = 0x5c;

export function sanitizeTerminalText(value: string): string {
  const withoutEscapes = replaceEscapeSequences(value);
  let safe = '';
  for (const character of withoutEscapes) {
    const codePoint = character.codePointAt(0);
    if (character === '\r') safe += '\\r';
    else if (character === '\n') safe += '\\n';
    else if (character === '\t') safe += '\\t';
    else if (codePoint !== undefined && isTerminalControl(codePoint)) {
      safe += REPLACEMENT;
    } else safe += character;
  }
  return safe;
}

export function sanitizeTerminalOutput(value: string): string {
  return value
    .replaceAll('\r\n', '\n')
    .replaceAll('\r', '\n')
    .split('\n')
    .map(sanitizeTerminalText)
    .join('\n');
}

export function safeJson(value: unknown): string {
  return `${JSON.stringify(sanitizeJsonValue(value), undefined, 2)}\n`;
}

function replaceEscapeSequences(value: string): string {
  let safe = '';
  for (let index = 0; index < value.length; index += 1) {
    const code = value.charCodeAt(index);
    if (code === ESCAPE) {
      index = consumeEscape(value, index);
      safe += REPLACEMENT;
      continue;
    }
    if (code === 0x9b) {
      index = consumeCsi(value, index + 1);
      safe += REPLACEMENT;
      continue;
    }
    safe += value.slice(index, index + 1);
  }
  return safe;
}

function consumeEscape(value: string, escapeIndex: number): number {
  const kindIndex = escapeIndex + 1;
  const kind = value.charCodeAt(kindIndex);
  if (kind === 0x5b) return consumeCsi(value, kindIndex + 1);
  if (
    kind === 0x5d ||
    kind === 0x50 ||
    kind === 0x58 ||
    kind === 0x5e ||
    kind === 0x5f
  ) {
    return consumeStringSequence(value, kindIndex + 1);
  }
  return Math.min(kindIndex, value.length - 1);
}

function consumeCsi(value: string, startIndex: number): number {
  for (let index = startIndex; index < value.length; index += 1) {
    const code = value.charCodeAt(index);
    if (code >= 0x40 && code <= 0x7e) return index;
  }
  return value.length - 1;
}

function consumeStringSequence(value: string, startIndex: number): number {
  for (let index = startIndex; index < value.length; index += 1) {
    const code = value.charCodeAt(index);
    if (code === BELL) return index;
    if (code === ESCAPE && value.charCodeAt(index + 1) === STRING_TERMINATOR) {
      return index + 1;
    }
  }
  return value.length - 1;
}

function isTerminalControl(codePoint: number): boolean {
  return (
    codePoint <= 0x1f ||
    (codePoint >= 0x7f && codePoint <= 0x9f) ||
    codePoint === 0x061c ||
    codePoint === 0x200e ||
    codePoint === 0x200f ||
    (codePoint >= 0x202a && codePoint <= 0x202e) ||
    (codePoint >= 0x2066 && codePoint <= 0x2069)
  );
}

function sanitizeJsonValue(value: unknown): unknown {
  if (typeof value === 'string') return sanitizeTerminalText(value);
  if (Array.isArray(value)) return value.map(sanitizeJsonValue);
  if (value !== null && typeof value === 'object') {
    return Object.fromEntries(
      Object.entries(value).map(([key, entry]) => [
        sanitizeTerminalText(key),
        sanitizeJsonValue(entry),
      ]),
    );
  }
  return value;
}
