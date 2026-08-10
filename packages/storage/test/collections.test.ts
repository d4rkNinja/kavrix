import { describe, expect, it } from 'vitest';

import {
  mongoStorageCollectionNames,
  mongoStorageCollectionOptions,
  mongoStorageIndexes,
} from '../src/index.js';

describe('Mongo collection definitions', () => {
  it('defines strict validators for every collection', () => {
    const names = Object.values(mongoStorageCollectionNames);
    expect(Object.keys(mongoStorageCollectionOptions).sort()).toEqual(
      [...names].sort(),
    );
    for (const name of names) {
      const options = mongoStorageCollectionOptions[name];
      expect(options.validationAction).toBe('error');
      expect(options.validationLevel).toBe('strict');
      const jsonSchema = options.validator?.['$jsonSchema'] as
        | {
            additionalProperties?: boolean;
            oneOf?: { additionalProperties?: boolean }[];
          }
        | undefined;
      expect(
        jsonSchema?.additionalProperties === false ||
          jsonSchema?.oneOf?.every(
            ({ additionalProperties }) => additionalProperties === false,
          ),
      ).toBe(true);
    }
  });

  it('contains no plaintext credential fields in persisted validator shapes', () => {
    const validators = JSON.stringify(mongoStorageCollectionOptions);
    for (const forbidden of [
      '"title"',
      '"username"',
      '"password"',
      '"secretValue"',
      '"decrypted"',
    ]) {
      expect(validators).not.toContain(forbidden);
    }
    expect(validators).toContain('"ciphertext"');
    expect(validators).toContain('"authenticationTag"');
  });

  it('uniquely indexes revision, idempotency, and contiguous staging identities', () => {
    expect(mongoStorageIndexes.changes).toContainEqual(
      expect.objectContaining({
        key: { vaultId: 1, serverSequence: 1 },
        unique: true,
      }),
    );
    expect(mongoStorageIndexes.idempotency_commits).toContainEqual(
      expect.objectContaining({
        key: { vaultId: 1, idempotencyKey: 1 },
        unique: true,
      }),
    );
    expect(mongoStorageIndexes.attachment_staging_chunks).toContainEqual(
      expect.objectContaining({
        key: { stagingId: 1, chunkIndex: 1 },
        unique: true,
      }),
    );
    expect(mongoStorageIndexes.backup_restore_entries).toContainEqual(
      expect.objectContaining({
        key: { restoreSessionId: 1, ordinal: 1 },
        unique: true,
      }),
    );
  });
});
