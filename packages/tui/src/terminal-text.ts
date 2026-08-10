const REPLACEMENT = '\uFFFD';

function isAnsiFinal(code: number): boolean {
  return code >= 0x40 && code <= 0x7e;
}

function skipStringEscape(value: string, start: number): number {
  for (let index = start; index < value.length; index += 1) {
    const code = value.charCodeAt(index);
    if (code === 0x07) return index;
    if (code === 0x1b && value.charCodeAt(index + 1) === 0x5c) return index + 1;
  }
  return value.length - 1;
}

function skipEscape(value: string, start: number): number {
  const next = value.charCodeAt(start + 1);
  if (next === 0x5b) {
    for (let index = start + 2; index < value.length; index += 1) {
      if (isAnsiFinal(value.charCodeAt(index))) return index;
    }
    return value.length - 1;
  }
  if (
    next === 0x5d ||
    next === 0x50 ||
    next === 0x58 ||
    next === 0x5e ||
    next === 0x5f
  ) {
    return skipStringEscape(value, start + 2);
  }
  return Math.min(start + 1, value.length - 1);
}

function isBidiControl(codePoint: number): boolean {
  return (
    codePoint === 0x061c ||
    codePoint === 0x200e ||
    codePoint === 0x200f ||
    (codePoint >= 0x202a && codePoint <= 0x202e) ||
    (codePoint >= 0x2066 && codePoint <= 0x2069)
  );
}

/**
 * Makes untrusted decrypted text safe for a terminal cell. Escape/control
 * sequences are removed in linear time and bidi controls are made visible.
 */
export function sanitizeTerminalText(value: string, ascii = false): string {
  let output = '';
  for (let index = 0; index < value.length; index += 1) {
    const code = value.charCodeAt(index);
    if (code === 0x1b) {
      index = skipEscape(value, index);
      continue;
    }
    if (code === 0x09 || code === 0x0a || code === 0x0d) {
      output += ' ';
      continue;
    }
    if (code < 0x20 || code === 0x7f || (code >= 0x80 && code <= 0x9f)) continue;

    const codePoint = value.codePointAt(index);
    if (codePoint === undefined) continue;
    if (codePoint > 0xffff) index += 1;
    if (isBidiControl(codePoint)) {
      output += ascii ? '?' : REPLACEMENT;
      continue;
    }
    output += ascii && codePoint > 0x7e ? '?' : String.fromCodePoint(codePoint);
  }
  return output;
}

export function truncateTerminalText(value: string, width: number): string {
  if (width <= 0) return '';
  const glyphs = Array.from(value);
  if (glyphs.length <= width) return value;
  if (width === 1) return '\u2026';
  return `${glyphs.slice(0, width - 1).join('')}\u2026`;
}

export function secretMask(ascii: boolean): string {
  return ascii ? '********' : '\u2022\u2022\u2022\u2022\u2022\u2022\u2022\u2022';
}
