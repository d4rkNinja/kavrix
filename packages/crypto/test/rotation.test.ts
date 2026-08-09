import { createHash } from 'node:crypto';

import { describe, expect, it } from 'vitest';

import { sha256DigestSchema, type Sha256Digest } from '@kavrix/schemas';

import {
  AuthenticationError,
  CryptoInputError,
  advanceRotationCheckpoint,
  createRotationCheckpoint,
  encodeBase64Url,
  generateVaultRootKey,
  resumeRotationCheckpoint,
  verifyRotationCheckpoint,
  type RotationReplacement,
} from '../src/index.js';
import { vaultId } from './helpers.js';

const expectation = {
  vaultId,
  rotationId: 'rotation-1',
  orderedRecords: [
    { recordId: 'record-a', sourceDigest: digest('source-a') },
    { recordId: 'record-b', sourceDigest: digest('source-b') },
    { recordId: 'record-c', sourceDigest: digest('source-c') },
  ],
} as const;

describe('authenticated rotation checkpoints', () => {
  it('advances one durably verified record and resumes authenticated progress', () => {
    const rootKey = generateVaultRootKey();
    const created = createRotationCheckpoint(
      {
        ...expectation,
        kind: 'vault-root',
        fromKeyVersion: 1,
        toKeyVersion: 2,
      },
      rootKey,
    );
    const running = resumeRotationCheckpoint(created, rootKey, expectation);

    // Required integration order: persist and read-back verify replacement,
    // then persist the newly authenticated checkpoint.
    const durableReplacements = new Map<string, string>();
    const replacementA = replacement('record-a', 'replacement-a');
    durableReplacements.set(replacementA.recordId, replacementA.replacementDigest);
    expect(durableReplacements.get('record-a')).toBe(replacementA.replacementDigest);
    const interrupted = advanceRotationCheckpoint(
      running,
      replacementA,
      rootKey,
      expectation,
    );
    const persisted = JSON.parse(JSON.stringify(interrupted)) as typeof interrupted;
    const verified = verifyRotationCheckpoint(persisted, rootKey, expectation);
    expect(verified.nextRecordIndex).toBe(1);
    expect(verified.processedTranscriptDigest).not.toBe(
      running.payload.processedTranscriptDigest,
    );
    expect(resumeRotationCheckpoint(persisted, rootKey, expectation)).toBe(persisted);

    const second = advanceRotationCheckpoint(
      persisted,
      replacement('record-b', 'replacement-b'),
      rootKey,
      expectation,
    );
    expect(second.payload).toMatchObject({ nextRecordIndex: 2, state: 'running' });
  });

  it('rejects forged progress, reordered records, and changed source envelopes', () => {
    const rootKey = generateVaultRootKey();
    const checkpoint = createRotationCheckpoint(
      {
        ...expectation,
        kind: 'group',
        fromKeyVersion: 3,
        toKeyVersion: 4,
      },
      rootKey,
    );
    const forged = {
      ...checkpoint,
      payload: {
        ...checkpoint.payload,
        nextRecordIndex: 1,
        state: 'running',
        processedTranscriptDigest: digest('forged-transcript'),
      },
    } as typeof checkpoint;
    expect(() => verifyRotationCheckpoint(forged, rootKey, expectation)).toThrow(
      AuthenticationError,
    );
    expect(() =>
      verifyRotationCheckpoint(checkpoint, rootKey, {
        ...expectation,
        orderedRecords: [
          expectation.orderedRecords[1],
          expectation.orderedRecords[0],
          expectation.orderedRecords[2],
        ],
      }),
    ).toThrow(AuthenticationError);
    expect(() =>
      verifyRotationCheckpoint(checkpoint, rootKey, {
        ...expectation,
        orderedRecords: [
          { ...expectation.orderedRecords[0], sourceDigest: digest('changed-source') },
          expectation.orderedRecords[1],
          expectation.orderedRecords[2],
        ],
      }),
    ).toThrow(AuthenticationError);
    expect(() =>
      verifyRotationCheckpoint(checkpoint, generateVaultRootKey(), expectation),
    ).toThrow(AuthenticationError);
  });

  it('rejects skipped, duplicate, wrong, and malformed replacement advances', () => {
    const rootKey = generateVaultRootKey();
    const running = resumeRotationCheckpoint(
      createRotationCheckpoint(
        {
          ...expectation,
          kind: 'item',
          fromKeyVersion: 7,
          toKeyVersion: 8,
        },
        rootKey,
      ),
      rootKey,
      expectation,
    );
    expect(() =>
      advanceRotationCheckpoint(
        running,
        replacement('record-b', 'replacement-b'),
        rootKey,
        expectation,
      ),
    ).toThrow(CryptoInputError);
    const first = advanceRotationCheckpoint(
      running,
      replacement('record-a', 'replacement-a'),
      rootKey,
      expectation,
    );
    expect(() =>
      advanceRotationCheckpoint(
        first,
        replacement('record-a', 'replacement-a-again'),
        rootKey,
        expectation,
      ),
    ).toThrow(CryptoInputError);
    expect(() =>
      advanceRotationCheckpoint(
        first,
        {
          recordId: 'record-b',
          replacementDigest: 'not-canonical',
        } as RotationReplacement,
        rootKey,
        expectation,
      ),
    ).toThrow(CryptoInputError);
  });

  it('requires resume and will not reopen authenticated completion', () => {
    const rootKey = generateVaultRootKey();
    const created = createRotationCheckpoint(
      {
        ...expectation,
        kind: 'item',
        fromKeyVersion: 7,
        toKeyVersion: 8,
      },
      rootKey,
    );
    expect(() =>
      advanceRotationCheckpoint(
        created,
        replacement('record-a', 'replacement-a'),
        rootKey,
        expectation,
      ),
    ).toThrow(CryptoInputError);
    let checkpoint = resumeRotationCheckpoint(created, rootKey, expectation);
    for (const [index, source] of expectation.orderedRecords.entries()) {
      checkpoint = advanceRotationCheckpoint(
        checkpoint,
        replacement(source.recordId, `replacement-${String(index)}`),
        rootKey,
        expectation,
      );
    }
    expect(checkpoint.payload.state).toBe('completed');
    expect(resumeRotationCheckpoint(checkpoint, rootKey, expectation)).toBe(checkpoint);
    expect(() =>
      advanceRotationCheckpoint(
        checkpoint,
        replacement('record-c', 'replacement-c-again'),
        rootKey,
        expectation,
      ),
    ).toThrow(CryptoInputError);
  });
});

function replacement(recordId: string, value: string): RotationReplacement {
  return { recordId, replacementDigest: digest(value) };
}

function digest(value: string): Sha256Digest {
  return sha256DigestSchema.parse(
    encodeBase64Url(createHash('sha256').update(value, 'utf8').digest()),
  );
}
