import { LocalCliError } from './cli-error.js';

export const RESERVED_CREDENTIAL_NAMES = new Set([
  '__proto__',
  'constructor',
  'prototype',
]);

export function validateCredentialName(name: string): void {
  if (RESERVED_CREDENTIAL_NAMES.has(name)) {
    throw new LocalCliError('That credential name is reserved.');
  }
  // Names become record keys and terminal output; ambiguous or hostile
  // spellings are refused rather than silently accepted.
  if (
    name.length === 0 ||
    name.length > 256 ||
    // Control characters cannot appear in safe credential names.
    // eslint-disable-next-line no-control-regex
    /[\u0000-\u001f\u007f]/u.test(name) ||
    /\s/u.test(name)
  ) {
    throw new LocalCliError(
      'Credential names must be 1-256 characters without whitespace or control characters.',
    );
  }
  if (
    name.startsWith('/') ||
    name.endsWith('/') ||
    name.includes('//') ||
    name === '.' ||
    name === '..'
  ) {
    throw new LocalCliError(
      'Credential names must not start or end with "/", contain "//", or be a dot segment.',
    );
  }
}
