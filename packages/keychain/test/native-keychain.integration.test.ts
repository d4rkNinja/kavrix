import { randomBytes, randomUUID } from 'node:crypto';

import { describe, expect, it } from 'vitest';
import {
  joinPreparedJournalRecordSchema,
  lifecycleOperationIdSchema,
} from '@kavrix/client';
import {
  deviceUnlockSecretSchema,
  keychainLocatorSchema,
  protectedLocalDeviceStateSchema,
  sessionCredentialLocatorSchema,
  sessionCredentialSecretSchema,
} from '@kavrix/schemas';

import {
  createNativeJoinJournalSecrets,
  createNativeKeychain,
  createNativeProtectedSyncState,
  createNativeSessionCredentials,
} from '../src/index.js';

const runNativeIntegration = process.env['KAVRIX_KEYCHAIN_INTEGRATION'] === '1';

describe.runIf(runNativeIntegration)('native operating-system keychain', () => {
  it('round-trips and removes remembered material', async () => {
    const keychain = await createNativeKeychain('dev.kavrix.integration');
    const key = keychainLocatorSchema.parse({
      version: 1,
      vaultId: `vault_${randomUUID()}`,
      deviceId: `device_${randomUUID()}`,
      keySlotId: `slot_${randomUUID()}`,
    });
    const secret = deviceUnlockSecretSchema.parse(randomBytes(32));

    try {
      await keychain.store(key, secret, AbortSignal.timeout(5_000));
      const loaded = await keychain.load(key, AbortSignal.timeout(5_000));
      expect(loaded).toEqual(Uint8Array.from(secret));
      loaded?.fill(0);
    } finally {
      secret.fill(0);
      await keychain.delete(key, AbortSignal.timeout(5_000));
    }

    await expect(keychain.load(key, AbortSignal.timeout(5_000))).resolves.toBeNull();
  }, 30_000);

  it('round-trips a device-scoped session credential independently', async () => {
    const sessions = await createNativeSessionCredentials('dev.kavrix.integration');
    const key = sessionCredentialLocatorSchema.parse({
      version: 1,
      vaultId: `vault_${randomUUID()}`,
      deviceId: `device_${randomUUID()}`,
      purpose: 'api-session',
    });
    const secret = sessionCredentialSecretSchema.parse(randomBytes(32));

    try {
      await sessions.store(key, secret, AbortSignal.timeout(5_000));
      const loaded = await sessions.load(key, AbortSignal.timeout(5_000));
      expect(loaded).toEqual(Uint8Array.from(secret));
      loaded?.fill(0);
    } finally {
      secret.fill(0);
      await sessions.delete(key, AbortSignal.timeout(5_000));
    }

    await expect(sessions.load(key, AbortSignal.timeout(5_000))).resolves.toBeNull();
  }, 30_000);

  it('round-trips a monotonic protected sync rollback anchor', async () => {
    const protectedState = await createNativeProtectedSyncState(
      'dev.kavrix.integration',
    );
    const vaultId = `vault_${randomUUID()}` as never;
    const deviceId = `device_${randomUUID()}` as never;
    const state = protectedLocalDeviceStateSchema.parse({
      vaultId,
      deviceId,
      highestSeenVaultRevision: 7,
      updatedAt: new Date().toISOString(),
    });

    try {
      await protectedState.save(state);
      await expect(protectedState.load(state.vaultId, state.deviceId)).resolves.toEqual(
        state,
      );
    } finally {
      await protectedState.delete(state.vaultId, state.deviceId);
    }
  }, 30_000);

  it('round-trips and removes a protected join recovery record', async () => {
    const protectedJoin = await createNativeJoinJournalSecrets(
      'dev.kavrix.integration',
    );
    const operationId = lifecycleOperationIdSchema.parse(`join.${randomUUID()}`);
    const vaultId = `vault_${randomUUID()}`;
    const deviceId = `device_${randomUUID()}`;
    const record = joinPreparedJournalRecordSchema.parse({
      version: 1,
      kind: 'vault-join',
      operationId,
      state: 'prepared',
      expectedVaultId: vaultId,
      deviceId,
      completionRequest: { vaultId, deviceId, schemaVersion: 1 },
      sessionLocator: {
        version: 1,
        vaultId,
        deviceId,
        purpose: 'api-session',
      },
      inviteBearer: randomBytes(32),
      enrollmentSuccessor: randomBytes(32),
      sessionSuccessor: randomBytes(32),
    });

    try {
      await protectedJoin.store(record);
      const loaded = await protectedJoin.load(operationId);
      if (loaded === null) throw new Error('Missing native integration record');
      expect({
        ...loaded,
        inviteBearer: undefined,
        enrollmentSuccessor: undefined,
        sessionSuccessor: undefined,
      }).toEqual({
        ...record,
        inviteBearer: undefined,
        enrollmentSuccessor: undefined,
        sessionSuccessor: undefined,
      });
      expect(Buffer.compare(loaded.inviteBearer, record.inviteBearer)).toBe(0);
      expect(
        Buffer.compare(loaded.enrollmentSuccessor, record.enrollmentSuccessor),
      ).toBe(0);
      expect(Buffer.compare(loaded.sessionSuccessor, record.sessionSuccessor)).toBe(0);
      loaded.inviteBearer.fill(0);
      loaded.enrollmentSuccessor.fill(0);
      loaded.sessionSuccessor.fill(0);
    } finally {
      record.inviteBearer.fill(0);
      record.enrollmentSuccessor.fill(0);
      record.sessionSuccessor.fill(0);
      await protectedJoin.delete(operationId);
      await expect(protectedJoin.load(operationId)).resolves.toBeNull();
    }
  }, 30_000);
});
