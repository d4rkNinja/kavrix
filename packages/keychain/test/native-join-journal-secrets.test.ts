import { describe, expect, it } from 'vitest';

import {
  JOIN_LIFECYCLE_JOURNAL_MAX_SERIALIZED_BYTES,
  joinPreparedJournalRecordSchema,
  lifecycleOperationIdSchema,
  type JoinActiveJournalRecord,
  type JoinPreparedJournalRecord,
} from '@kavrix/client';

import { NativeJoinJournalSecrets, type NativeEntryFactory } from '../src/index.js';

const OPERATION_ID = lifecycleOperationIdSchema.parse('operation.join.test.0001');

function record(fill = 1): JoinPreparedJournalRecord {
  return joinPreparedJournalRecordSchema.parse({
    version: 1,
    kind: 'vault-join',
    operationId: OPERATION_ID,
    state: 'prepared',
    expectedVaultId: 'vault.join.test',
    deviceId: 'device.join.test',
    completionRequest: {
      vaultId: 'vault.join.test',
      deviceId: 'device.join.test',
      schemaVersion: 1,
    },
    sessionLocator: {
      version: 1,
      vaultId: 'vault.join.test',
      deviceId: 'device.join.test',
      purpose: 'api-session',
    },
    inviteBearer: new Uint8Array(32).fill(fill),
    enrollmentSuccessor: new Uint8Array(32).fill(fill + 1),
    sessionSuccessor: new Uint8Array(32).fill(fill + 2),
  });
}

function memoryEntries(): {
  createEntry: NativeEntryFactory;
  values: Map<string, Uint8Array>;
} {
  const values = new Map<string, Uint8Array>();
  return {
    values,
    createEntry: (service, account) => ({
      setSecret(value): Promise<void> {
        values.set(`${service}/${account}`, Uint8Array.from(value));
        return Promise.resolve();
      },
      getSecret(): Promise<Uint8Array | undefined> {
        const value = values.get(`${service}/${account}`);
        return Promise.resolve(
          value === undefined ? undefined : Uint8Array.from(value),
        );
      },
      deleteCredential(): Promise<boolean> {
        return Promise.resolve(values.delete(`${service}/${account}`));
      },
    }),
  };
}

function wipe(value: JoinActiveJournalRecord | null): void {
  value?.inviteBearer.fill(0);
  value?.enrollmentSuccessor.fill(0);
  value?.sessionSuccessor.fill(0);
}

describe('NativeJoinJournalSecrets', () => {
  it('round-trips all active states in a bounded versioned operation account', async () => {
    const memory = memoryEntries();
    const secrets = new NativeJoinJournalSecrets(memory.createEntry);
    for (const state of [
      'prepared',
      'redeem-attempted',
      'completion-attempted',
    ] as const) {
      const input = { ...record(), state };
      await secrets.store(input);
      const loaded = await secrets.load(OPERATION_ID);
      expect(loaded).toEqual(input);
      wipe(loaded);
    }

    const [account, encoded] = [...memory.values.entries()][0] ?? [];
    expect(account).toContain('/v1:vault-join-operation:operation.join.test.0001');
    expect(encoded?.subarray(0, 5)).toEqual(Uint8Array.of(0x4b, 0x4a, 0x4a, 0x52, 1));
    expect(encoded?.byteLength).toBeLessThanOrEqual(
      JOIN_LIFECYCLE_JOURNAL_MAX_SERIALIZED_BYTES,
    );
    expect(encoded?.byteLength).toBeLessThanOrEqual(2_560);
  });

  it('copies caller bytes and wipes the adapter-owned write buffer on success', async () => {
    let received: Uint8Array | undefined;
    const secrets = new NativeJoinJournalSecrets(() => ({
      setSecret(value): Promise<void> {
        received = value;
        value.fill(91);
        return Promise.resolve();
      },
      getSecret(): Promise<undefined> {
        return Promise.resolve(undefined);
      },
      deleteCredential(): Promise<void> {
        return Promise.resolve();
      },
    }));
    const input = record(7);
    await secrets.store(input);
    expect(input.inviteBearer).toEqual(new Uint8Array(32).fill(7));
    expect(input.enrollmentSuccessor).toEqual(new Uint8Array(32).fill(8));
    expect(input.sessionSuccessor).toEqual(new Uint8Array(32).fill(9));
    expect(received?.every((value) => value === 0)).toBe(true);
  });

  it('wipes the adapter-owned write buffer on failure without leaking its cause', async () => {
    let received: Uint8Array | undefined;
    const secrets = new NativeJoinJournalSecrets(() => ({
      setSecret(value): Promise<never> {
        received = value;
        value.fill(92);
        return Promise.reject(new Error('bearer-canary'));
      },
      getSecret(): Promise<undefined> {
        return Promise.resolve(undefined);
      },
      deleteCredential(): Promise<void> {
        return Promise.resolve();
      },
    }));
    const operation = secrets.store(record(4));
    await expect(operation).rejects.toMatchObject({
      code: 'KEYCHAIN_OPERATION_FAILED',
    });
    await expect(operation).rejects.not.toThrow(/bearer-canary/u);
    expect(received?.every((value) => value === 0)).toBe(true);
  });

  it('wipes native load bytes and returns fresh bearer arrays', async () => {
    const memory = memoryEntries();
    const writer = new NativeJoinJournalSecrets(memory.createEntry);
    await writer.store(record(11));
    const stored = [...memory.values.values()][0];
    const returned = Uint8Array.from(stored ?? []);
    const reader = new NativeJoinJournalSecrets(() => ({
      setSecret(): Promise<void> {
        return Promise.resolve();
      },
      getSecret(): Promise<Uint8Array> {
        return Promise.resolve(returned);
      },
      deleteCredential(): Promise<void> {
        return Promise.resolve();
      },
    }));

    const loaded = await reader.load(OPERATION_ID);
    expect(loaded).toEqual(record(11));
    expect(returned.every((value) => value === 0)).toBe(true);
    loaded?.inviteBearer.fill(0);
    expect(stored?.every((value) => value === 0)).toBe(false);
    wipe(loaded);
  });

  it('rejects corrupt and cross-operation native values generically', async () => {
    const memory = memoryEntries();
    const secrets = new NativeJoinJournalSecrets(memory.createEntry);
    await secrets.store(record());
    const key = [...memory.values.keys()][0];
    expect(key).toBeDefined();
    memory.values.set(key ?? '', Uint8Array.of(0x4b, 0x4a, 0x4a, 0x52, 9));
    await expect(secrets.load(OPERATION_ID)).rejects.toMatchObject({
      code: 'KEYCHAIN_CORRUPTED',
    });

    const otherId = lifecycleOperationIdSchema.parse('operation.join.other.0002');
    const other = joinPreparedJournalRecordSchema.parse({
      ...record(),
      operationId: otherId,
    });
    await secrets.store(other);
    const otherBytes = memory.values.get(
      `dev.kavrix.credentials/v1:vault-join-operation:${otherId}`,
    );
    memory.values.set(
      `dev.kavrix.credentials/v1:vault-join-operation:${OPERATION_ID}`,
      Uint8Array.from(otherBytes ?? []),
    );
    await expect(secrets.load(OPERATION_ID)).rejects.toMatchObject({
      code: 'KEYCHAIN_CORRUPTED',
    });
  });

  it('rejects invalid state codes and malformed canonical public frames', async () => {
    const memory = memoryEntries();
    const secrets = new NativeJoinJournalSecrets(memory.createEntry);
    await secrets.store(record());
    const key = [...memory.values.keys()][0];
    const canonical = Uint8Array.from(memory.values.get(key ?? '') ?? []);

    const invalidState = Uint8Array.from(canonical);
    invalidState[5] = 99;
    memory.values.set(key ?? '', invalidState);
    await expect(secrets.load(OPERATION_ID)).rejects.toMatchObject({
      code: 'KEYCHAIN_CORRUPTED',
    });

    for (const publicJson of ['null', '[]', '{']) {
      const publicBytes = new TextEncoder().encode(publicJson);
      const malformed = new Uint8Array(8 + publicBytes.byteLength + 96);
      malformed.set(canonical.subarray(0, 6));
      malformed[5] = 1;
      new DataView(malformed.buffer).setUint16(6, publicBytes.byteLength, false);
      malformed.set(publicBytes, 8);
      malformed.set(
        canonical.subarray(canonical.byteLength - 96),
        8 + publicBytes.length,
      );
      memory.values.set(key ?? '', malformed);
      await expect(secrets.load(OPERATION_ID)).rejects.toMatchObject({
        code: 'KEYCHAIN_CORRUPTED',
      });
    }

    memory.values.set(key ?? '', new Uint8Array(1_537));
    await expect(secrets.load(OPERATION_ID)).rejects.toMatchObject({
      code: 'KEYCHAIN_CORRUPTED',
    });
    canonical.fill(0);
  });

  it('normalizes native deletion failures without exposing their cause', async () => {
    const secrets = new NativeJoinJournalSecrets(() => ({
      setSecret(): Promise<void> {
        return Promise.resolve();
      },
      getSecret(): Promise<undefined> {
        return Promise.resolve(undefined);
      },
      deleteCredential(): Promise<never> {
        return Promise.reject(new Error('delete-bearer-canary'));
      },
    }));
    const operation = secrets.delete(OPERATION_ID);
    await expect(operation).rejects.toMatchObject({
      code: 'KEYCHAIN_OPERATION_FAILED',
    });
    await expect(operation).rejects.not.toThrow(/delete-bearer-canary/u);
  });

  it('deletes idempotently and rejects invalid operation locators', async () => {
    const memory = memoryEntries();
    const secrets = new NativeJoinJournalSecrets(memory.createEntry);
    await secrets.store(record());
    await expect(secrets.delete(OPERATION_ID)).resolves.toBeUndefined();
    await expect(secrets.delete(OPERATION_ID)).resolves.toBeUndefined();
    await expect(secrets.load(OPERATION_ID)).resolves.toBeNull();
    await expect(secrets.load('../unsafe' as never)).rejects.toMatchObject({
      code: 'KEYCHAIN_OPERATION_FAILED',
    });
  });
});
