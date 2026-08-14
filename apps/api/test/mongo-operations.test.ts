import type { Db } from 'mongodb';
import { describe, expect, it, vi } from 'vitest';

import {
  assertMongoApiDatabaseCompatibility,
  MONGO_SCHEMA_STATE_COLLECTION,
  MONGO_SCHEMA_VERSION,
} from '../src/mongo-operations.js';

describe('Mongo operational schema contract', () => {
  it('freezes the baseline state identity', () => {
    expect(MONGO_SCHEMA_VERSION).toBe(1);
    expect(MONGO_SCHEMA_STATE_COLLECTION).toBe('_kavrix_schema_state');
  });

  it('validates the state before scanning opaque application documents', async () => {
    const find = vi.fn(() => emptyCursor());
    const database = fakeDatabase(
      {
        _id: 'kavrix',
        schemaVersion: 1,
        migrationId: 'baseline-contracts-v1',
        appliedAt: '2026-08-14T00:00:00.000Z',
      },
      find,
    );

    await expect(
      assertMongoApiDatabaseCompatibility(database),
    ).resolves.toBeUndefined();
    expect(find).toHaveBeenCalled();
  });

  it.each([
    null,
    { _id: 'kavrix', schemaVersion: 2 },
    { _id: 'kavrix', schemaVersion: 1, migrationId: 'tampered' },
  ])('rejects a %j state before touching application documents', async (state) => {
    const find = vi.fn(() => emptyCursor());
    const database = fakeDatabase(state, find);

    await expect(assertMongoApiDatabaseCompatibility(database)).rejects.toThrow(
      'Mongo schema compatibility check failed',
    );
    expect(find).not.toHaveBeenCalled();
  });
});

function fakeDatabase(state: unknown, find: ReturnType<typeof vi.fn>): Db {
  return {
    collection: () => ({
      findOne: () => Promise.resolve(state),
      find,
    }),
  } as unknown as Db;
}

function emptyCursor(): {
  hasNext(): Promise<boolean>;
  next(): Promise<null>;
  close(): Promise<void>;
} {
  return {
    hasNext: () => Promise.resolve(false),
    next: () => Promise.resolve(null),
    close: () => Promise.resolve(),
  };
}
