import { Readable, Writable } from 'node:stream';

import { describe, expect, it } from 'vitest';

import { LocalSecretInput } from '../src/local-secrets.js';

function secretInput(value: string): LocalSecretInput {
  const input = Readable.from([value]);
  const output = new Writable({
    write(_chunk, _encoding, callback) {
      callback();
    },
  });
  return new LocalSecretInput(input, output);
}

describe('local secret input policy', () => {
  it('rejects short passphrases before key derivation', async () => {
    await expect(secretInput('too-short\n').read(['passphrase'], true)).rejects.toThrow(
      'Passphrases must contain at least 16 bytes.',
    );
  });

  it('keeps non-passphrase stdin values governed by their own validation', async () => {
    await expect(
      secretInput('mongodb://localhost\n').read(['database-url'], true),
    ).resolves.toEqual(['mongodb://localhost']);
  });

  it('accepts a sufficiently long passphrase', async () => {
    await expect(
      secretInput('correct horse battery staple\n').read(['passphrase'], true),
    ).resolves.toEqual(['correct horse battery staple']);
  });
});
