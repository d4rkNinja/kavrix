import { describe, expect, it, vi } from 'vitest';
import { ReadPreference } from 'mongodb';

import {
  MAX_MONGO_BACKUP_SOURCE_BYTES,
  MAX_MONGO_BACKUP_SOURCE_RECORDS,
  MongoBackupSource,
  MongoBackupSourceError,
} from '../src/mongo-backup-source.js';
import { mongoStorageCollectionNames } from '../src/collections.js';
import { toVaultDocument } from '../src/documents.js';
import { vaultRecord } from './fixtures.js';

const vaultId = 'vault.1' as never;

describe('MongoBackupSource input and cleanup boundary', () => {
  it.each([
    { maximumBytes: 0 },
    { maximumBytes: MAX_MONGO_BACKUP_SOURCE_BYTES + 1 },
    { maximumRecords: 0 },
    { maximumRecords: MAX_MONGO_BACKUP_SOURCE_RECORDS + 1 },
  ])('rejects unsupported limits before opening a session', async (options) => {
    const startSession = vi.fn();
    const source = new MongoBackupSource({ startSession } as never, {} as never);

    await expect(source.open(vaultId, options)).rejects.toEqual(
      expect.objectContaining({ code: 'BACKUP_SOURCE_FAILED' }),
    );
    expect(startSession).not.toHaveBeenCalled();
  });

  it('rejects an already-aborted operation before opening a session', async () => {
    const startSession = vi.fn();
    const signal = AbortSignal.abort('plaintext-cleanup-canary');
    const source = new MongoBackupSource({ startSession } as never, {} as never);

    const caught = await source
      .open(vaultId, { signal })
      .catch((error: unknown) => error);

    expect(caught).toBeInstanceOf(MongoBackupSourceError);
    expect(caught).toEqual(expect.objectContaining({ code: 'BACKUP_SOURCE_ABORTED' }));
    expect(String(caught)).not.toContain('plaintext-cleanup-canary');
    expect(startSession).not.toHaveBeenCalled();
  });

  it('aborts and ends a snapshot transaction after a generic open failure', async () => {
    const abortTransaction = vi.fn(() => Promise.resolve());
    const endSession = vi.fn(() => Promise.resolve());
    const session = {
      startTransaction: vi.fn(),
      inTransaction: vi.fn(() => true),
      abortTransaction,
      endSession,
    };
    const source = new MongoBackupSource(
      { startSession: vi.fn(() => session) } as never,
      {
        collection: vi.fn(() => ({
          findOne: vi.fn(() => Promise.resolve(null)),
        })),
      } as never,
    );

    const caught = await source.open(vaultId).catch((error: unknown) => error);

    expect(caught).toEqual(expect.objectContaining({ code: 'BACKUP_SOURCE_FAILED' }));
    expect(String(caught)).toBe(
      'MongoBackupSourceError: The encrypted backup source could not be read safely.',
    );
    expect(session.startTransaction).toHaveBeenCalledWith({
      readConcern: { level: 'snapshot' },
      readPreference: ReadPreference.primary,
    });
    expect(abortTransaction).toHaveBeenCalledOnce();
    expect(endSession).toHaveBeenCalledOnce();
  });

  it.each([
    { counter: null, transaction: false },
    {
      counter: { _id: 'vault.1', changeSequence: 0, vaultRevision: 1 },
      transaction: true,
    },
  ])('fails closed for a missing or revision-divergent counter', async (variant) => {
    const record = vaultRecord();
    const session = {
      startTransaction: vi.fn(),
      inTransaction: vi.fn(() => variant.transaction),
      abortTransaction: vi.fn(() => Promise.resolve()),
      endSession: vi.fn(() => Promise.resolve()),
    };
    const source = new MongoBackupSource(
      { startSession: vi.fn(() => session) } as never,
      {
        collection: vi.fn((name: string) => ({
          findOne: vi.fn(() =>
            Promise.resolve(
              name === mongoStorageCollectionNames.vaults
                ? toVaultDocument(record)
                : variant.counter,
            ),
          ),
        })),
      } as never,
    );

    await expect(source.open(vaultId)).rejects.toEqual(
      expect.objectContaining({ code: 'BACKUP_SOURCE_FAILED' }),
    );
    expect(session.endSession).toHaveBeenCalledOnce();
    expect(session.abortTransaction).toHaveBeenCalledTimes(variant.transaction ? 1 : 0);
  });

  it.each(['abort', 'end'] as const)(
    'turns a session %s failure into a generic source error',
    async (failure) => {
      const session = {
        startTransaction: vi.fn(),
        inTransaction: vi.fn(() => true),
        abortTransaction: vi.fn(() =>
          failure === 'abort'
            ? Promise.reject(new Error('release-secret-canary'))
            : Promise.resolve(),
        ),
        endSession: vi.fn(() =>
          failure === 'end'
            ? Promise.reject(new Error('release-secret-canary'))
            : Promise.resolve(),
        ),
      };
      const source = new MongoBackupSource(
        { startSession: vi.fn(() => session) } as never,
        {
          collection: vi.fn(() => ({
            findOne: vi.fn(() => Promise.resolve(null)),
          })),
        } as never,
      );

      const caught = await source.open(vaultId).catch((error: unknown) => error);

      expect(caught).toEqual(expect.objectContaining({ code: 'BACKUP_SOURCE_FAILED' }));
      expect(String(caught)).not.toContain('release-secret-canary');
      expect(session.endSession).toHaveBeenCalledOnce();
    },
  );
});
