import { generateVaultRootKey, zeroize } from '@kavrix/crypto';
import {
  keySlotIdSchema,
  sha256DigestSchema,
  vaultIdSchema,
  vaultRevisionSchema,
} from '@kavrix/schemas';
import { mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import { join } from 'node:path';
import { tmpdir } from 'node:os';

import { afterEach, beforeEach, describe, expect, it } from 'vitest';

import {
  copyRevisionAnchor,
  readRevisionAnchor,
  writeRevisionAnchor,
} from '../src/index.js';

let directory = '';

beforeEach(async () => {
  directory = await mkdtemp(join(tmpdir(), 'kavrix-revision-anchor-'));
});

afterEach(async () => {
  await rm(directory, { recursive: true, force: true });
});

function anchor(revision = 4) {
  return {
    vaultId: vaultIdSchema.parse('vault'),
    keySlotId: keySlotIdSchema.parse('slot'),
    revision: vaultRevisionSchema.parse(revision),
    metadataDigest: sha256DigestSchema.parse('A'.repeat(43)),
  } as const;
}

describe('trusted local revision anchor', () => {
  it('authenticates, reads, and securely copies an anchor', async () => {
    const rootKey = generateVaultRootKey();
    const source = join(directory, 'source.anchor');
    const copy = join(directory, 'copy.anchor');
    try {
      await writeRevisionAnchor(source, rootKey, anchor(), 'create');
      await expect(readRevisionAnchor(source, rootKey, anchor())).resolves.toEqual(
        anchor(),
      );
      await copyRevisionAnchor(source, copy, 'create');
      await expect(readRevisionAnchor(copy, rootKey, anchor())).resolves.toEqual(
        anchor(),
      );
    } finally {
      zeroize(rootKey);
    }
  });

  it('rejects tampering and a mismatched vault binding', async () => {
    const rootKey = generateVaultRootKey();
    const path = join(directory, 'anchor');
    try {
      await writeRevisionAnchor(path, rootKey, anchor(), 'create');
      const contents = await readFile(path, 'utf8');
      await writeFile(path, contents.replace('"revision":4', '"revision":3'), 'utf8');
      await expect(readRevisionAnchor(path, rootKey, anchor())).rejects.toMatchObject({
        code: 'KEY_FILE_UNSAFE',
      });
      await expect(
        readRevisionAnchor(path, rootKey, {
          ...anchor(),
          vaultId: vaultIdSchema.parse('other-vault'),
        }),
      ).rejects.toMatchObject({ code: 'KEY_FILE_UNSAFE' });
    } finally {
      zeroize(rootKey);
    }
  });
});
