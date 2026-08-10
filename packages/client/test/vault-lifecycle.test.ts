import type { IncomingMessage, ServerResponse } from 'node:http';

import { afterEach, describe, expect, it } from 'vitest';

import type {
  ClockPort,
  IdGeneratorPort,
  KeychainPort,
  SessionCredentialPort,
} from '@kavrix/core';
import {
  constantTimeEqual,
  createPortableKeySlot,
  decryptPayload,
  encodeBase64Url,
  encryptPayload,
  formatPortableKey,
  formatRecoveryKey,
  generatePortableKey,
  generateRecoveryKey,
  generateVaultRootKey,
  parsePortableKey,
  parseRecoveryKey,
  unlockDeviceKeySlot,
  unlockPortableKeySlot,
  unlockRecoveryKeySlot,
  zeroize,
} from '@kavrix/crypto';
import {
  apiBearerTokenSchema,
  associatedDataSchema,
  deviceIdSchema,
  deviceUnlockSecretSchema,
  keySlotIdSchema,
  sessionCredentialSecretSchema,
  timestampSchema,
  vaultBootstrapRequestSchema,
  vaultIdSchema,
  vaultPreferencesSchema,
  vaultRecordSchema,
  type DeviceUnlockSecret,
  type ApiBearerToken,
  type KeychainLocator,
  type SessionCredentialLocator,
  type SessionCredentialSecret,
  type VaultBootstrapRequest,
  type VaultRecord,
} from '@kavrix/schemas';

import {
  ControlPlaneClient,
  JOIN_LIFECYCLE_JOURNAL_MAX_SERIALIZED_BYTES,
  VaultInitializationCoordinator,
  VaultJoinCoordinator,
  VaultLifecycleError,
  initializationJournalRecordSchema,
  joinJournalRecordSchema,
  joinLifecycleJournalSerializedBytes,
  joinPreparedJournalRecordSchema,
  lifecycleOperationIdSchema,
  type InitializationActiveJournalRecord,
  type InitializationCommittedJournalRecord,
  type InitializationJournalPort,
  type InitializationJournalRecord,
  type JoinActiveJournalRecord,
  type JoinCommittedJournalRecord,
  type JoinJournalRecord,
  type JoinLifecycleJournalPort,
  type JoinPreparedJournalRecord,
  type LifecycleOperationId,
  type VaultInitializationInput,
} from '../src/index.js';
import {
  readRequest,
  startLoopbackServer,
  type LoopbackServer,
} from './loopback-server.js';

const NOW = new Date('2026-08-10T00:00:00.000Z');
const EXPIRES = timestampSchema.parse('2026-08-10T01:00:00.000Z');
const servers: LoopbackServer[] = [];

afterEach(async () => {
  await Promise.all(servers.splice(0).map((server) => server.close()));
});

describe('VaultInitializationCoordinator', () => {
  it('fails closed for invalid initialization input and unknown recovery IDs', async () => {
    const server = await lifecycleServer([]);
    const harness = initializationHarness(server.url);
    expect(() =>
      harness.coordinator.begin({
        ...initializationInput(),
        deviceKeyProvider: '',
      }),
    ).toThrow(VaultLifecycleError);
    await expect(
      harness.coordinator.resume(
        lifecycleOperationIdSchema.parse('operation.init.unknown'),
      ),
    ).rejects.toMatchObject({ kind: 'operation-unavailable' });
  });

  it('rejects malformed imported portable material before IDs or side effects', async () => {
    const requests: CapturedRequest[] = [];
    const server = await lifecycleServer(requests);
    let idCalls = 0;
    const operationIds: IdGeneratorPort<LifecycleOperationId> = {
      next() {
        idCalls += 1;
        return lifecycleOperationIdSchema.parse('operation.init.import.invalid');
      },
    };
    const harness = initializationHarness(server.url, '.import.invalid', operationIds);

    expect(() =>
      harness.coordinator.beginImportedPortable(
        initializationInput(),
        'KAVRIX-PORTABLE-INVALID-CANARY',
      ),
    ).toThrow(VaultLifecycleError);

    expect(idCalls).toBe(0);
    expect(requests).toHaveLength(0);
    expect(harness.keychain.size).toBe(0);
    expect(harness.sessions.size).toBe(0);
    expect(harness.initializationJournal.record).toBeNull();
    expect(harness.initializationJournal.capturedCreateRecords).toHaveLength(0);
  });

  it('imports a portable key, displays only fresh recovery, and binds both to one VRK', async () => {
    const requests: CapturedRequest[] = [];
    const server = await lifecycleServer(requests);
    const harness = initializationHarness(server.url, '.import');
    const importedBytes = generatePortableKey();
    const importedPortable = formatPortableKey(importedBytes);
    const importedCanary = encodeBase64Url(importedBytes);
    const creation = harness.coordinator.beginImportedPortable(
      initializationInput(),
      importedPortable,
    );
    zeroize(importedBytes);

    const display = creation.takeDisplayMaterial();
    expect(typeof display.recoveryKey).toBe('string');
    expect(display.recoveryKey.length).toBeGreaterThan(0);
    expect(Object.keys(display)).toEqual(['recoveryKey']);
    expect(JSON.stringify(display)).not.toContain(importedPortable);
    expect(() => creation.takeDisplayMaterial()).toThrow(VaultLifecycleError);

    const portableCandidate = parsePortableKey(importedPortable);
    const recoveryCandidate = parseRecoveryKey(display.recoveryKey);
    try {
      expect(constantTimeEqual(portableCandidate, recoveryCandidate)).toBe(false);
    } finally {
      zeroize(portableCandidate);
      zeroize(recoveryCandidate);
    }

    const confirmation = {
      portableKey: importedPortable,
      recoveryKey: display.recoveryKey,
    };
    const receipt = await creation.confirm(confirmation);
    expect(receipt).toMatchObject({
      vaultId: vaultIdSchema.parse('vault.lifecycle'),
      deviceId: deviceIdSchema.parse('device.lifecycle'),
    });
    const captured = required(requests[0]);
    const request = vaultBootstrapRequestSchema.parse(JSON.parse(captured.body));
    await expectSameRootKey(request, confirmation, harness.keychain);

    const protectedSurfaces = [
      captured.path,
      captured.body,
      JSON.stringify(harness.initializationJournal.capturedCreateRecords),
      JSON.stringify(receipt),
    ];
    for (const surface of protectedSurfaces) {
      expect(surface).not.toContain(importedPortable);
      expect(surface).not.toContain(importedCanary);
      expect(surface).not.toContain(display.recoveryKey);
    }
  });

  it('terminally rejects wrong imported-portable confirmation without persistence', async () => {
    const requests: CapturedRequest[] = [];
    const server = await lifecycleServer(requests);
    const harness = initializationHarness(server.url, '.import.wrong');
    const importedBytes = generatePortableKey();
    const importedPortable = formatPortableKey(importedBytes);
    zeroize(importedBytes);
    const otherBytes = generatePortableKey();
    const wrongPortable = formatPortableKey(otherBytes);
    zeroize(otherBytes);
    const creation = harness.coordinator.beginImportedPortable(
      initializationInput(),
      importedPortable,
    );
    const display = creation.takeDisplayMaterial();

    const failure = await rejected(
      creation.confirm({
        portableKey: wrongPortable,
        recoveryKey: display.recoveryKey,
      }),
    );
    expect(failure).toMatchObject({ kind: 'confirmation-failed' });
    expect(String(failure)).not.toContain(importedPortable);
    expect(JSON.stringify(failure)).not.toContain(importedPortable);
    await expect(
      creation.confirm({
        portableKey: importedPortable,
        recoveryKey: display.recoveryKey,
      }),
    ).rejects.toMatchObject({ kind: 'operation-unavailable' });
    expect(requests).toHaveLength(0);
    expect(harness.initializationJournal.record).toBeNull();
    expect(harness.initializationJournal.capturedCreateRecords).toHaveLength(0);
    expect(harness.keychain.size).toBe(0);
    expect(harness.sessions.size).toBe(0);
  });

  it('confirms both canonical display keys before creating one bound encrypted vault', async () => {
    const requests: CapturedRequest[] = [];
    const server = await lifecycleServer(requests);
    const harness = initializationHarness(server.url);
    const creation = harness.coordinator.begin(initializationInput());
    const display = creation.takeDisplayMaterial();

    const receipt = await creation.confirm(display);

    expect(receipt).toEqual({
      operationId: lifecycleOperationIdSchema.parse('operation.init.0001'),
      vaultId: vaultIdSchema.parse('vault.lifecycle'),
      deviceId: deviceIdSchema.parse('device.lifecycle'),
    });
    expect(requests).toHaveLength(1);
    const request = required(requests[0]);
    expect(request.path).toBe('/v1/vaults');
    expect(request.authorization).toMatch(/^Bearer [A-Za-z0-9_-]{43}$/u);
    expect(request.body).not.toContain(display.portableKey);
    expect(request.body).not.toContain(display.recoveryKey);
    expect(request.path).not.toContain('?');
    expect(request.successor).toBeUndefined();

    const body = vaultBootstrapRequestSchema.parse(JSON.parse(request.body));
    expect(body.vault.revision).toBe(0);
    expect(body.vault.keySlots.map(({ type }) => type).sort()).toEqual([
      'device-key',
      'portable-key',
      'recovery-key',
    ]);
    await expectSameRootKey(body, display, harness.keychain);
    expect(harness.initializationJournal.record?.state).toBe('committed');
    await expect(harness.coordinator.listOperations()).resolves.toEqual([
      creation.operationId,
    ]);
    expect(harness.keychain.capturedStoreInputs[0]).toSatisfy(allZero);
    expect(harness.sessions.capturedStoreInputs[0]).toSatisfy(allZero);
    expect(() => creation.takeDisplayMaterial()).toThrow(VaultLifecycleError);
    await expect(creation.confirm(display)).rejects.toMatchObject({
      kind: 'operation-unavailable',
    });
  });

  it('does not journal, store, or call bootstrap for noncanonical or unequal confirmation', async () => {
    const requests: CapturedRequest[] = [];
    const server = await lifecycleServer(requests);
    const harness = initializationHarness(server.url);
    const creation = harness.coordinator.begin(initializationInput());
    const display = creation.takeDisplayMaterial();
    const otherRecovery = generateRecoveryKey();
    const wrongRecovery = formatRecoveryKey(otherRecovery);
    zeroize(otherRecovery);

    await expect(
      creation.confirm({ portableKey: display.portableKey, recoveryKey: 'invalid' }),
    ).rejects.toMatchObject({ kind: 'confirmation-failed' });
    await expect(creation.confirm(display)).rejects.toMatchObject({
      kind: 'operation-unavailable',
    });

    const unequal = initializationHarness(server.url, '.unequal');
    const unequalCreation = unequal.coordinator.begin(initializationInput());
    const unequalDisplay = unequalCreation.takeDisplayMaterial();
    await expect(
      unequalCreation.confirm({
        portableKey: unequalDisplay.portableKey,
        recoveryKey: wrongRecovery,
      }),
    ).rejects.toMatchObject({ kind: 'confirmation-failed' });

    expect(requests).toHaveLength(0);
    expect(harness.initializationJournal.record).toBeNull();
    expect(unequal.initializationJournal.record).toBeNull();
    expect(harness.keychain.size).toBe(0);
    expect(harness.sessions.size).toBe(0);
    creation.cancel();
  });

  it('replays the exact encrypted bootstrap after an uncertain response', async () => {
    const requests: CapturedRequest[] = [];
    let disconnect = true;
    const server = await lifecycleServer(requests, {
      bootstrap: (_body, request) => {
        if (disconnect) {
          disconnect = false;
          request.socket.destroy();
          return 'disconnected';
        }
        return undefined;
      },
    });
    const harness = initializationHarness(server.url);
    const creation = harness.coordinator.begin(initializationInput());
    const display = creation.takeDisplayMaterial();

    await expect(creation.confirm(display)).rejects.toThrow();
    expect(harness.initializationJournal.record?.state).toBe('network-attempted');
    await expect(
      harness.coordinator.cancel(creation.operationId),
    ).rejects.toMatchObject({
      kind: 'unsafe-cancel',
    });

    await expect(
      harness.coordinator.resume(creation.operationId),
    ).resolves.toMatchObject({
      vaultId: vaultIdSchema.parse('vault.lifecycle'),
    });
    expect(requests).toHaveLength(2);
    expect(requests[1]).toEqual(requests[0]);
  });

  it('fails closed for partial prepared stores and resumes after both durable stores', async () => {
    const requests: CapturedRequest[] = [];
    const server = await lifecycleServer(requests);
    const source = initializationHarness(server.url, '.source');
    const creation = source.coordinator.begin(initializationInput());
    await creation.confirm(creation.takeDisplayMaterial());
    const request = vaultBootstrapRequestSchema.parse(
      JSON.parse(required(requests[0]).body),
    );
    const deviceSlot = required(
      request.vault.keySlots.find((slot) => slot.type === 'device-key'),
    );
    const deviceLocator = {
      version: 1 as const,
      vaultId: request.vault.id,
      deviceId: request.device.id,
      keySlotId: deviceSlot.id,
    };
    const sessionLocator = {
      version: 1 as const,
      vaultId: request.vault.id,
      deviceId: request.device.id,
      purpose: 'api-session' as const,
    };
    const deviceSecret = await source.keychain.load(deviceLocator);
    const sessionSecret = await source.sessions.load(sessionLocator);
    if (deviceSecret === null || sessionSecret === null) {
      throw new Error('missing protected fixture');
    }
    try {
      const partial = initializationHarness(server.url, '.partial');
      const partialOperation = lifecycleOperationIdSchema.parse(
        'operation.init.partial',
      );
      partial.initializationJournal.record = initializationJournalRecordSchema.parse({
        version: 1,
        kind: 'vault-initialization',
        operationId: partialOperation,
        state: 'prepared',
        request,
        deviceLocator,
        sessionLocator,
      });
      await partial.keychain.store(deviceLocator, deviceSecret);
      await expect(partial.coordinator.resume(partialOperation)).rejects.toMatchObject({
        kind: 'restart-required',
      });
      expect(partial.initializationJournal.record).toBeNull();
      expect(partial.keychain.size).toBe(0);
      expect(requests).toHaveLength(1);

      const complete = initializationHarness(server.url, '.prepared');
      const completeOperation = lifecycleOperationIdSchema.parse(
        'operation.init.prepared',
      );
      complete.initializationJournal.record = initializationJournalRecordSchema.parse({
        version: 1,
        kind: 'vault-initialization',
        operationId: completeOperation,
        state: 'prepared',
        request,
        deviceLocator,
        sessionLocator,
      });
      await complete.keychain.store(deviceLocator, deviceSecret);
      await complete.sessions.store(sessionLocator, sessionSecret);
      await expect(
        complete.coordinator.resume(completeOperation),
      ).resolves.toMatchObject({
        operationId: completeOperation,
      });
      expect(requests).toHaveLength(2);
      expect(requests[1]).toEqual(requests[0]);
    } finally {
      zeroize(deviceSecret);
      zeroize(sessionSecret);
    }
  });

  it('cleans partial protected writes before network and resumes a committed journal', async () => {
    const requests: CapturedRequest[] = [];
    const server = await lifecycleServer(requests);
    const preNetwork = initializationHarness(server.url);
    preNetwork.sessions.failStore = 'before';
    const failedCreation = preNetwork.coordinator.begin(initializationInput());
    const failedDisplay = failedCreation.takeDisplayMaterial();
    await expect(failedCreation.confirm(failedDisplay)).rejects.toMatchObject({
      kind: 'protected-storage',
    });
    expect(requests).toHaveLength(0);
    expect(preNetwork.keychain.size).toBe(0);
    expect(preNetwork.sessions.size).toBe(0);
    expect(preNetwork.initializationJournal.record).toBeNull();

    const committed = initializationHarness(server.url, '.committed');
    committed.initializationJournal.failCommitAfterMutation = true;
    const creation = committed.coordinator.begin(initializationInput());
    const display = creation.takeDisplayMaterial();
    await expect(creation.confirm(display)).rejects.toMatchObject({ kind: 'journal' });
    expect(committed.initializationJournal.record?.state).toBe('committed');
    await expect(
      committed.coordinator.resume(creation.operationId),
    ).resolves.toMatchObject({
      operationId: creation.operationId,
    });
    expect(requests).toHaveLength(1);
  });

  it('serializes concurrent resume with the live confirmation attempt', async () => {
    const requests: CapturedRequest[] = [];
    const entered = deferred<undefined>();
    const release = deferred<undefined>();
    const server = await lifecycleServer(requests, {
      bootstrap: async () => {
        entered.resolve(undefined);
        await release.promise;
        return undefined;
      },
    });
    const harness = initializationHarness(server.url);
    const creation = harness.coordinator.begin(initializationInput());
    const pending = creation.confirm(creation.takeDisplayMaterial());
    await entered.promise;

    await expect(
      harness.coordinator.resume(creation.operationId),
    ).rejects.toMatchObject({
      kind: 'operation-busy',
    });
    release.resolve(undefined);
    await expect(pending).resolves.toMatchObject({ operationId: creation.operationId });
  });
});

describe('VaultJoinCoordinator', () => {
  it('fails closed for invalid join input and unknown recovery IDs', async () => {
    const server = await lifecycleServer([]);
    const harness = joinHarness(server.url, '.invalid');
    await expect(
      harness.coordinator.begin({
        inviteBearer: 'not-a-bearer' as ApiBearerToken,
        expectedVaultId: vaultIdSchema.parse('vault.lifecycle'),
      }),
    ).rejects.toMatchObject({ kind: 'invalid-input' });
    await expect(
      harness.coordinator.resume(
        lifecycleOperationIdSchema.parse('operation.join.unknown'),
        'not-a-portable-key',
      ),
    ).rejects.toMatchObject({ kind: 'operation-unavailable' });
  });

  it('persists independent successors before exchange and authenticates locally before complete', async () => {
    const fixture = await portableVault();
    const requests: CapturedRequest[] = [];
    const server = await lifecycleServer(requests, { redeemVault: fixture.vault });
    const harness = joinHarness(server.url);
    const preparation = await harness.coordinator.begin({
      inviteBearer: bearer(71),
      expectedVaultId: fixture.vault.id,
    });
    expect(requests).toHaveLength(0);
    await expect(harness.coordinator.listOperations()).resolves.toEqual([
      preparation.operationId,
    ]);
    expect(harness.joinJournal.capturedCreateInputs).toHaveLength(3);
    expect(harness.joinJournal.capturedCreateInputs.every(allZero)).toBe(true);

    const wrongKey = generatePortableKey();
    const wrongFormatted = formatPortableKey(wrongKey);
    zeroize(wrongKey);
    await expect(
      harness.coordinator.resume(preparation.operationId, wrongFormatted),
    ).rejects.toMatchObject({ kind: 'protocol' });
    expect(paths(requests, '/v1/invites/redeem')).toHaveLength(1);
    expect(paths(requests, '/v1/enrollments/complete')).toHaveLength(0);

    const receipt = await harness.coordinator.resume(
      preparation.operationId,
      fixture.formattedPortableKey,
    );
    expect(receipt).toEqual({
      operationId: preparation.operationId,
      vaultId: fixture.vault.id,
      deviceId: preparation.deviceId,
    });
    const redeems = paths(requests, '/v1/invites/redeem');
    expect(redeems).toHaveLength(2);
    expect(redeems[1]).toEqual(redeems[0]);
    const firstRedeem = required(redeems[0]);
    const complete = required(paths(requests, '/v1/enrollments/complete')[0]);
    expect(complete.authorization).toBe(`Bearer ${String(firstRedeem.successor)}`);
    expect(complete.successor).toMatch(/^[A-Za-z0-9_-]{43}$/u);
    expect(complete.successor).not.toBe(firstRedeem.authorization?.slice(7));
    expect(complete.successor).not.toBe(firstRedeem.successor);
    const wire = JSON.stringify(requests);
    expect(wire).not.toContain(fixture.formattedPortableKey);
    expect(wire).not.toContain(fixture.portableCanary);
    expect(wire).not.toContain(fixture.rootCanary);
    expect(JSON.stringify(receipt)).not.toContain(complete.successor);
    expect(harness.sessions.size).toBe(1);
    expect(harness.joinJournal.record?.state).toBe('committed');
  });

  it('fails tampered and cross-vault redemption before completeEnrollment', async () => {
    const fixture = await portableVault();
    const tampered = tamperPortableSlot(fixture.vault);
    const requests: CapturedRequest[] = [];
    const server = await lifecycleServer(requests, { redeemVault: tampered });
    const harness = joinHarness(server.url, '.tampered');
    const preparation = await harness.coordinator.begin({
      inviteBearer: bearer(72),
      expectedVaultId: fixture.vault.id,
    });
    await expect(
      harness.coordinator.resume(preparation.operationId, fixture.formattedPortableKey),
    ).rejects.toMatchObject({ kind: 'protocol' });
    expect(paths(requests, '/v1/enrollments/complete')).toHaveLength(0);
    expect(JSON.stringify(requests)).not.toContain(fixture.formattedPortableKey);

    const other = await portableVault('vault.other');
    const crossRequests: CapturedRequest[] = [];
    const crossServer = await lifecycleServer(crossRequests, {
      redeemVault: other.vault,
    });
    const crossHarness = joinHarness(crossServer.url, '.cross');
    const crossPreparation = await crossHarness.coordinator.begin({
      inviteBearer: bearer(73),
      expectedVaultId: fixture.vault.id,
    });
    await expect(
      crossHarness.coordinator.resume(
        crossPreparation.operationId,
        fixture.formattedPortableKey,
      ),
    ).rejects.toThrow();
    expect(paths(crossRequests, '/v1/enrollments/complete')).toHaveLength(0);
  });

  it('replays exact exchanges across each durable crash boundary', async () => {
    const fixture = await portableVault();
    const requests: CapturedRequest[] = [];
    const server = await lifecycleServer(requests, { redeemVault: fixture.vault });
    const harness = joinHarness(server.url, '.crash');
    const preparation = await harness.coordinator.begin({
      inviteBearer: bearer(74),
      expectedVaultId: fixture.vault.id,
    });

    harness.joinJournal.failMarkRedeemAfterMutation = true;
    await expect(
      harness.coordinator.resume(preparation.operationId, fixture.formattedPortableKey),
    ).rejects.toMatchObject({ kind: 'journal' });
    expect(requests).toHaveLength(0);

    harness.joinJournal.failMarkCompletionAfterMutation = true;
    await expect(
      harness.coordinator.resume(preparation.operationId, fixture.formattedPortableKey),
    ).rejects.toMatchObject({ kind: 'journal' });
    expect(paths(requests, '/v1/invites/redeem')).toHaveLength(1);
    expect(paths(requests, '/v1/enrollments/complete')).toHaveLength(0);

    harness.sessions.failStore = 'after';
    await expect(
      harness.coordinator.resume(preparation.operationId, fixture.formattedPortableKey),
    ).rejects.toMatchObject({ kind: 'protected-storage' });
    harness.joinJournal.failCommitAfterMutation = true;
    await expect(
      harness.coordinator.resume(preparation.operationId, fixture.formattedPortableKey),
    ).rejects.toMatchObject({ kind: 'journal' });
    await expect(
      harness.coordinator.resume(preparation.operationId, fixture.formattedPortableKey),
    ).resolves.toMatchObject({ operationId: preparation.operationId });

    const redeems = paths(requests, '/v1/invites/redeem');
    const completes = paths(requests, '/v1/enrollments/complete');
    expect(redeems).toHaveLength(2);
    expect(redeems.every((request) => sameExchange(request, redeems[0]))).toBe(true);
    expect(completes).toHaveLength(1);
  });

  it('recovers a committed session after a lost completion response and expiry', async () => {
    const fixture = await portableVault();
    const requests: CapturedRequest[] = [];
    let disconnectCompletion = true;
    const server = await lifecycleServer(requests, {
      redeemVault: fixture.vault,
      complete: (request) => {
        if (!disconnectCompletion) return undefined;
        disconnectCompletion = false;
        request.socket.destroy();
        return 'disconnected';
      },
    });
    let current = new Date(NOW);
    const harness = joinHarness(server.url, '.lost-response', {
      now: () => new Date(current),
    });
    const preparation = await harness.coordinator.begin({
      inviteBearer: bearer(78),
      expectedVaultId: fixture.vault.id,
    });

    await expect(
      harness.coordinator.resume(preparation.operationId, fixture.formattedPortableKey),
    ).rejects.toThrow();
    expect(harness.joinJournal.record?.state).toBe('completion-attempted');
    current = new Date('2026-08-10T02:00:00.000Z');

    await expect(
      harness.coordinator.resume(preparation.operationId, fixture.formattedPortableKey),
    ).resolves.toMatchObject({ operationId: preparation.operationId });
    expect(paths(requests, '/v1/invites/redeem')).toHaveLength(1);
    expect(paths(requests, '/v1/enrollments/complete')).toHaveLength(1);
    expect(paths(requests, '/v1/session')).toHaveLength(1);
    expect(harness.sessions.size).toBe(1);
    expect(harness.joinJournal.record?.state).toBe('committed');
  });

  it('bounds replay by redemption expiry and only cancels before network use', async () => {
    const fixture = await portableVault();
    const requests: CapturedRequest[] = [];
    const server = await lifecycleServer(requests, {
      redeemVault: fixture.vault,
      expiresAt: timestampSchema.parse('2026-08-09T23:59:59.000Z'),
    });
    const harness = joinHarness(server.url, '.expired');
    const cancellable = await harness.coordinator.begin({
      inviteBearer: bearer(75),
      expectedVaultId: fixture.vault.id,
    });
    await harness.coordinator.cancel(cancellable.operationId);
    expect(harness.joinJournal.record).toBeNull();

    const preparation = await harness.coordinator.begin({
      inviteBearer: bearer(76),
      expectedVaultId: fixture.vault.id,
    });
    await expect(
      harness.coordinator.resume(preparation.operationId, fixture.formattedPortableKey),
    ).rejects.toMatchObject({ kind: 'expired' });
    expect(paths(requests, '/v1/enrollments/complete')).toHaveLength(0);
    await expect(
      harness.coordinator.cancel(preparation.operationId),
    ).rejects.toMatchObject({
      kind: 'unsafe-cancel',
    });
  });

  it('does not treat matching local bytes as proof after a revoked session', async () => {
    const fixture = await portableVault();
    const requests: CapturedRequest[] = [];
    const server = await lifecycleServer(requests, {
      redeemVault: fixture.vault,
      expiresAt: timestampSchema.parse('2026-08-09T23:59:59.000Z'),
    });
    const harness = joinHarness(server.url, '.revoked');
    const preparation = await harness.coordinator.begin({
      inviteBearer: bearer(79),
      expectedVaultId: fixture.vault.id,
    });
    await harness.joinJournal.markRedeemAttempted(preparation.operationId);
    await harness.joinJournal.markCompletionAttempted(preparation.operationId);
    const active = harness.joinJournal.active(preparation.operationId);
    await harness.sessions.store(
      active.sessionLocator,
      sessionCredentialSecretSchema.parse(active.sessionSuccessor),
    );

    await expect(
      harness.coordinator.resume(preparation.operationId, fixture.formattedPortableKey),
    ).rejects.toMatchObject({ kind: 'expired' });
    expect(paths(requests, '/v1/session')).toHaveLength(1);
    expect(paths(requests, '/v1/enrollments/complete')).toHaveLength(0);
    expect(harness.joinJournal.record?.state).toBe('completion-attempted');
  });

  it('keeps a 128-slot redemption outside the fixed protected journal', async () => {
    const fixture = await portableVault('vault.many-slots', 128);
    expect(Buffer.byteLength(JSON.stringify(fixture.vault), 'utf8')).toBeGreaterThan(
      2_560,
    );
    const requests: CapturedRequest[] = [];
    const server = await lifecycleServer(requests, { redeemVault: fixture.vault });
    const harness = joinHarness(server.url, '.many');
    const preparation = await harness.coordinator.begin({
      inviteBearer: bearer(77),
      expectedVaultId: fixture.vault.id,
    });
    const active = harness.joinJournal.record;
    if (active === null || active.state === 'committed') throw new Error('missing');
    expect(joinLifecycleJournalSerializedBytes(asPrepared(active))).toBeLessThanOrEqual(
      JOIN_LIFECYCLE_JOURNAL_MAX_SERIALIZED_BYTES,
    );
    expect(JSON.stringify(active)).not.toContain('keySlots');
    const maximumIdRecord = joinPreparedJournalRecordSchema.parse({
      ...active,
      state: 'prepared',
      operationId: `o${'a'.repeat(127)}`,
      expectedVaultId: `v${'a'.repeat(127)}`,
      deviceId: `d${'a'.repeat(127)}`,
      completionRequest: {
        vaultId: `v${'a'.repeat(127)}`,
        deviceId: `d${'a'.repeat(127)}`,
        schemaVersion: 1,
      },
      sessionLocator: {
        version: 1,
        vaultId: `v${'a'.repeat(127)}`,
        deviceId: `d${'a'.repeat(127)}`,
        purpose: 'api-session',
      },
    });
    expect(joinLifecycleJournalSerializedBytes(maximumIdRecord)).toBeLessThanOrEqual(
      JOIN_LIFECYCLE_JOURNAL_MAX_SERIALIZED_BYTES,
    );

    await expect(
      harness.coordinator.resume(preparation.operationId, fixture.formattedPortableKey),
    ).resolves.toMatchObject({ vaultId: fixture.vault.id });
  }, 30_000);
});

function initializationInput(): VaultInitializationInput {
  return {
    preferences: vaultPreferencesSchema.parse({
      productLabel: 'CredVault',
      executableName: 'creds',
      clipboardClearSeconds: 30,
      revealHideSeconds: 15,
      historyRetentionDays: 365,
      telemetryEnabled: false,
    }),
    deviceKeyProvider: 'test-native-provider',
  };
}

function initializationHarness(
  baseUrl: string,
  suffix = '',
  operationIds: IdGeneratorPort<LifecycleOperationId> = ids(
    lifecycleOperationIdSchema.parse(`operation.init.0001${suffix}`),
  ),
): Readonly<{
  coordinator: VaultInitializationCoordinator;
  keychain: MemoryKeychain;
  sessions: MemorySessions;
  initializationJournal: MemoryInitializationJournal;
}> {
  const keychain = new MemoryKeychain();
  const sessions = new MemorySessions();
  const initializationJournal = new MemoryInitializationJournal();
  const coordinator = new VaultInitializationCoordinator({
    controlPlane: developmentClient(baseUrl),
    journal: initializationJournal,
    keychain,
    sessions,
    clock: fixedClock(),
    ids: {
      operation: operationIds,
      vault: ids(vaultIdSchema.parse('vault.lifecycle')),
      device: ids(deviceIdSchema.parse('device.lifecycle')),
      keySlot: ids(
        keySlotIdSchema.parse('slot.portable'),
        keySlotIdSchema.parse('slot.recovery'),
        keySlotIdSchema.parse('slot.device'),
      ),
    },
  });
  return { coordinator, keychain, sessions, initializationJournal };
}

function joinHarness(
  baseUrl: string,
  suffix = '',
  clock: ClockPort = fixedClock(),
): Readonly<{
  coordinator: VaultJoinCoordinator;
  sessions: MemorySessions;
  joinJournal: MemoryJoinJournal;
}> {
  const sessions = new MemorySessions();
  const joinJournal = new MemoryJoinJournal();
  const coordinator = new VaultJoinCoordinator({
    controlPlane: developmentClient(baseUrl),
    journal: joinJournal,
    sessions,
    clock,
    ids: {
      operation: ids(
        lifecycleOperationIdSchema.parse(`operation.join.0001${suffix}`),
        lifecycleOperationIdSchema.parse(`operation.join.0002${suffix}`),
      ),
      device: ids(
        deviceIdSchema.parse(`device.join.1${suffix}`),
        deviceIdSchema.parse(`device.join.2${suffix}`),
      ),
    },
  });
  return { coordinator, sessions, joinJournal };
}

async function expectSameRootKey(
  request: VaultBootstrapRequest,
  display: { readonly portableKey: string; readonly recoveryKey: string },
  keychain: MemoryKeychain,
): Promise<void> {
  const portable = required(
    request.vault.keySlots.find((slot) => slot.type === 'portable-key'),
  );
  const recovery = required(
    request.vault.keySlots.find((slot) => slot.type === 'recovery-key'),
  );
  const device = required(
    request.vault.keySlots.find((slot) => slot.type === 'device-key'),
  );
  const binding = {
    vaultId: request.vault.id,
    schemaVersion: request.vault.schemaVersion,
    keyVersion: request.vault.currentKeyVersion,
  };
  const [portableRoot, recoveryRoot] = await Promise.all([
    unlockPortableKeySlot(portable, display.portableKey, {
      ...binding,
      slotId: portable.id,
    }),
    unlockRecoveryKeySlot(recovery, display.recoveryKey, {
      ...binding,
      slotId: recovery.id,
    }),
  ]);
  const deviceSecret = await keychain.load({
    version: 1,
    vaultId: request.vault.id,
    deviceId: device.deviceId,
    keySlotId: device.id,
  });
  if (deviceSecret === null) throw new Error('missing device key');
  const deviceRoot = await unlockDeviceKeySlot(device, deviceSecret, {
    ...binding,
    slotId: device.id,
  });
  try {
    expect(constantTimeEqual(portableRoot, recoveryRoot)).toBe(true);
    expect(constantTimeEqual(portableRoot, deviceRoot)).toBe(true);
    const plaintext = await decryptPayload(
      request.vault.encryptedPreferences,
      portableRoot,
      request.vault.encryptedPreferences.aad,
    );
    try {
      expect(
        vaultPreferencesSchema.parse(JSON.parse(Buffer.from(plaintext).toString())),
      ).toEqual(initializationInput().preferences);
    } finally {
      zeroize(plaintext);
    }
  } finally {
    zeroize(portableRoot);
    zeroize(recoveryRoot);
    zeroize(deviceRoot);
    zeroize(deviceSecret);
  }
}

async function portableVault(
  requestedVaultId = 'vault.lifecycle',
  slotCount = 1,
): Promise<{
  vault: VaultRecord;
  formattedPortableKey: string;
  portableCanary: string;
  rootCanary: string;
}> {
  const vaultId = vaultIdSchema.parse(requestedVaultId);
  const createdAt = timestampSchema.parse(NOW.toISOString());
  const portableKey = generatePortableKey();
  const rootKey = generateVaultRootKey();
  const formattedPortableKey = formatPortableKey(portableKey);
  const portableCanary = encodeBase64Url(portableKey);
  const rootCanary = encodeBase64Url(rootKey);
  let plaintext: Uint8Array | undefined;
  try {
    const slots = await Promise.all(
      Array.from({ length: slotCount }, (_, index) =>
        createPortableKeySlot(
          {
            vaultId,
            slotId: keySlotIdSchema.parse(`slot.portable.${String(index + 1)}`),
            schemaVersion: 1,
            keyVersion: 1,
            createdAt,
          },
          portableKey,
          rootKey,
        ),
      ),
    );
    plaintext = new TextEncoder().encode(
      JSON.stringify(initializationInput().preferences),
    );
    const encryptedPreferences = await encryptPayload(
      plaintext,
      rootKey,
      associatedDataSchema.parse({
        version: 1,
        schemaVersion: 1,
        keyVersion: 1,
        vaultId,
        entityType: 'vault-preferences',
        entityId: vaultId,
        purpose: 'vault-preferences',
      }),
    );
    return {
      vault: vaultRecordSchema.parse({
        id: vaultId,
        schemaVersion: 1,
        cryptographicVersion: 1,
        keySlots: slots,
        currentKeyVersion: 1,
        revision: 0,
        encryptedPreferences,
        createdAt,
        updatedAt: createdAt,
      }),
      formattedPortableKey,
      portableCanary,
      rootCanary,
    };
  } finally {
    zeroize(plaintext);
    zeroize(portableKey);
    zeroize(rootKey);
  }
}

function tamperPortableSlot(vault: VaultRecord): VaultRecord {
  const slot = required(vault.keySlots[0]);
  const ciphertext = Buffer.from(slot.wrappedRootKey.ciphertext, 'base64url');
  ciphertext[0] = (ciphertext[0] ?? 0) ^ 1;
  return vaultRecordSchema.parse({
    ...vault,
    keySlots: [
      {
        ...slot,
        wrappedRootKey: {
          ...slot.wrappedRootKey,
          ciphertext: ciphertext.toString('base64url'),
        },
      },
      ...vault.keySlots.slice(1),
    ],
  });
}

type CapturedRequest = Readonly<{
  method: string;
  path: string;
  authorization: string | undefined;
  successor: string | undefined;
  body: string;
}>;

async function lifecycleServer(
  captured: CapturedRequest[],
  options: {
    readonly redeemVault?: VaultRecord;
    readonly expiresAt?: string;
    readonly bootstrap?: (
      body: VaultBootstrapRequest,
      request: IncomingMessage,
    ) => undefined | 'disconnected' | Promise<undefined | 'disconnected'>;
    readonly complete?: (
      request: IncomingMessage,
    ) => undefined | 'disconnected' | Promise<undefined | 'disconnected'>;
  } = {},
): Promise<LoopbackServer> {
  let bootstrapped: VaultBootstrapRequest | undefined;
  let activeSessionBearer: string | undefined;
  const server = await startLoopbackServer(async (request, response) => {
    const bodyText = await readRequest(request);
    const seen = {
      method: request.method ?? '',
      path: new URL(request.url ?? '/', 'http://loopback').pathname,
      authorization: request.headers.authorization,
      successor: header(request, 'x-kavrix-successor-token'),
      body: bodyText,
    };
    captured.push(seen);
    if (seen.path === '/v1/vaults' && seen.method === 'POST') {
      const body = vaultBootstrapRequestSchema.parse(JSON.parse(bodyText));
      bootstrapped ??= body;
      const result = await options.bootstrap?.(body, request);
      if (result === 'disconnected') return;
      json(response, 201, { vaultId: body.vault.id, deviceId: body.device.id });
      return;
    }
    if (seen.path === '/v1/invites/redeem' && seen.method === 'POST') {
      const vault = options.redeemVault ?? bootstrapped?.vault;
      if (vault === undefined) {
        json(response, 404, { error: { code: 'NOT_FOUND', message: 'missing' } });
        return;
      }
      json(response, 200, {
        vaultId: vault.id,
        expiresAt: options.expiresAt ?? EXPIRES,
        vault,
      });
      return;
    }
    if (seen.path === '/v1/enrollments/complete' && seen.method === 'POST') {
      const body = JSON.parse(bodyText) as { vaultId?: unknown; deviceId?: unknown };
      activeSessionBearer = seen.successor;
      const result = await options.complete?.(request);
      if (result === 'disconnected') return;
      json(response, 201, { vaultId: body.vaultId, deviceId: body.deviceId });
      return;
    }
    if (seen.path === '/v1/session' && seen.method === 'GET') {
      if (seen.authorization !== `Bearer ${activeSessionBearer ?? ''}`) {
        json(response, 401, { error: { code: 'UNAUTHORIZED', message: 'denied' } });
        return;
      }
      const vaultId = options.redeemVault?.id ?? bootstrapped?.vault.id;
      const completion = [...captured]
        .reverse()
        .find((candidate) => candidate.path === '/v1/enrollments/complete');
      const completionBody = JSON.parse(completion?.body ?? '{}') as {
        deviceId?: unknown;
      };
      json(response, 200, {
        vaultId,
        deviceId: completionBody.deviceId,
        scopes: ['sync:read', 'sync:write', 'device:manage'],
      });
      return;
    }
    json(response, 404, { error: { code: 'NOT_FOUND', message: 'missing' } });
  });
  servers.push(server);
  return server;
}

function developmentClient(baseUrl: string): ControlPlaneClient {
  return new ControlPlaneClient({
    baseUrl,
    allowInsecureLoopbackDevelopment: true,
    timeoutMs: 2_000,
    maximumResponseBytes: 2 * 1024 * 1024,
  });
}

class MemoryKeychain implements KeychainPort {
  readonly #records = new Map<string, Uint8Array>();
  readonly capturedStoreInputs: Uint8Array[] = [];

  get size(): number {
    return this.#records.size;
  }

  load(locator: KeychainLocator): Promise<DeviceUnlockSecret | null> {
    const value = this.#records.get(locatorKey(locator));
    return Promise.resolve(
      value === undefined
        ? null
        : deviceUnlockSecretSchema.parse(Uint8Array.from(value)),
    );
  }

  store(locator: KeychainLocator, secret: DeviceUnlockSecret): Promise<void> {
    this.capturedStoreInputs.push(secret);
    this.#records.set(locatorKey(locator), Uint8Array.from(secret));
    return Promise.resolve();
  }

  delete(locator: KeychainLocator): Promise<void> {
    const value = this.#records.get(locatorKey(locator));
    zeroize(value);
    this.#records.delete(locatorKey(locator));
    return Promise.resolve();
  }
}

class MemorySessions implements SessionCredentialPort {
  readonly #records = new Map<string, Uint8Array>();
  readonly capturedStoreInputs: Uint8Array[] = [];
  failStore: 'before' | 'after' | undefined;

  get size(): number {
    return this.#records.size;
  }

  load(locator: SessionCredentialLocator): Promise<SessionCredentialSecret | null> {
    const value = this.#records.get(locatorKey(locator));
    return Promise.resolve(
      value === undefined
        ? null
        : sessionCredentialSecretSchema.parse(Uint8Array.from(value)),
    );
  }

  store(
    locator: SessionCredentialLocator,
    secret: SessionCredentialSecret,
  ): Promise<void> {
    if (this.failStore === 'before') {
      this.failStore = undefined;
      return Promise.reject(new Error('store failed'));
    }
    this.capturedStoreInputs.push(secret);
    this.#records.set(locatorKey(locator), Uint8Array.from(secret));
    if (this.failStore === 'after') {
      this.failStore = undefined;
      return Promise.reject(new Error('store acknowledgement failed'));
    }
    return Promise.resolve();
  }

  delete(locator: SessionCredentialLocator): Promise<void> {
    const value = this.#records.get(locatorKey(locator));
    zeroize(value);
    this.#records.delete(locatorKey(locator));
    return Promise.resolve();
  }
}

class MemoryInitializationJournal implements InitializationJournalPort {
  record: InitializationJournalRecord | null = null;
  readonly capturedCreateRecords: InitializationActiveJournalRecord[] = [];
  failCommitAfterMutation = false;

  createPrepared(record: InitializationActiveJournalRecord): Promise<void> {
    if (this.record !== null) return Promise.reject(new Error('duplicate'));
    this.capturedCreateRecords.push(structuredClone(record));
    this.record = cloneInitialization(record);
    return Promise.resolve();
  }

  listOperationIds(): Promise<readonly LifecycleOperationId[]> {
    return Promise.resolve(this.record === null ? [] : [this.record.operationId]);
  }

  load(operationId: LifecycleOperationId): Promise<InitializationJournalRecord | null> {
    return Promise.resolve(
      this.record?.operationId === operationId
        ? cloneInitialization(this.record)
        : null,
    );
  }

  markNetworkAttempted(operationId: LifecycleOperationId): Promise<void> {
    const record = this.active(operationId);
    this.record = cloneInitialization({ ...record, state: 'network-attempted' });
    return Promise.resolve();
  }

  commit(
    operationId: LifecycleOperationId,
    receipt: InitializationCommittedJournalRecord['receipt'],
    committedAt: InitializationCommittedJournalRecord['committedAt'],
  ): Promise<void> {
    const record = this.active(operationId);
    if (record.state !== 'network-attempted') return Promise.reject(new Error('state'));
    this.record = initializationJournalRecordSchema.parse({
      version: 1,
      kind: 'vault-initialization',
      operationId,
      state: 'committed',
      receipt,
      committedAt,
    });
    if (this.failCommitAfterMutation) {
      this.failCommitAfterMutation = false;
      return Promise.reject(new Error('commit acknowledgement failed'));
    }
    return Promise.resolve();
  }

  deletePrepared(operationId: LifecycleOperationId): Promise<void> {
    const record = this.active(operationId);
    if (record.state !== 'prepared') return Promise.reject(new Error('state'));
    this.record = null;
    return Promise.resolve();
  }

  active(operationId: LifecycleOperationId): InitializationActiveJournalRecord {
    const record = this.record;
    if (record?.operationId !== operationId || record.state === 'committed') {
      throw new Error('missing');
    }
    return record;
  }
}

class MemoryJoinJournal implements JoinLifecycleJournalPort {
  record: JoinJournalRecord | null = null;
  readonly capturedCreateInputs: Uint8Array[] = [];
  failMarkRedeemAfterMutation = false;
  failMarkCompletionAfterMutation = false;
  failCommitAfterMutation = false;

  createPrepared(record: JoinPreparedJournalRecord): Promise<void> {
    if (this.record !== null) return Promise.reject(new Error('duplicate'));
    this.capturedCreateInputs.push(
      record.inviteBearer,
      record.enrollmentSuccessor,
      record.sessionSuccessor,
    );
    this.record = cloneJoin(record);
    return Promise.resolve();
  }

  listOperationIds(): Promise<readonly LifecycleOperationId[]> {
    return Promise.resolve(this.record === null ? [] : [this.record.operationId]);
  }

  load(operationId: LifecycleOperationId): Promise<JoinJournalRecord | null> {
    return Promise.resolve(
      this.record?.operationId === operationId ? cloneJoin(this.record) : null,
    );
  }

  markRedeemAttempted(operationId: LifecycleOperationId): Promise<void> {
    const record = this.active(operationId);
    this.record = cloneJoin({ ...record, state: 'redeem-attempted' });
    if (this.failMarkRedeemAfterMutation) {
      this.failMarkRedeemAfterMutation = false;
      return Promise.reject(new Error('mark acknowledgement failed'));
    }
    return Promise.resolve();
  }

  markCompletionAttempted(operationId: LifecycleOperationId): Promise<void> {
    const record = this.active(operationId);
    this.record = cloneJoin({ ...record, state: 'completion-attempted' });
    if (this.failMarkCompletionAfterMutation) {
      this.failMarkCompletionAfterMutation = false;
      return Promise.reject(new Error('mark acknowledgement failed'));
    }
    return Promise.resolve();
  }

  commit(
    operationId: LifecycleOperationId,
    vaultId: JoinCommittedJournalRecord['vaultId'],
    deviceId: JoinCommittedJournalRecord['deviceId'],
    committedAt: JoinCommittedJournalRecord['committedAt'],
  ): Promise<void> {
    const record = this.active(operationId);
    if (record.state !== 'completion-attempted') {
      return Promise.reject(new Error('state'));
    }
    wipeJoin(record);
    this.record = joinJournalRecordSchema.parse({
      version: 1,
      kind: 'vault-join',
      operationId,
      state: 'committed',
      vaultId,
      deviceId,
      committedAt,
    });
    if (this.failCommitAfterMutation) {
      this.failCommitAfterMutation = false;
      return Promise.reject(new Error('commit acknowledgement failed'));
    }
    return Promise.resolve();
  }

  deletePrepared(operationId: LifecycleOperationId): Promise<void> {
    const record = this.active(operationId);
    if (record.state !== 'prepared') return Promise.reject(new Error('state'));
    wipeJoin(record);
    this.record = null;
    return Promise.resolve();
  }

  active(operationId: LifecycleOperationId): JoinActiveJournalRecord {
    const record = this.record;
    if (record?.operationId !== operationId || record.state === 'committed') {
      throw new Error('missing');
    }
    return record;
  }
}

function cloneInitialization(
  record: InitializationJournalRecord,
): InitializationJournalRecord {
  return initializationJournalRecordSchema.parse(structuredClone(record));
}

function cloneJoin(record: JoinJournalRecord): JoinJournalRecord {
  return joinJournalRecordSchema.parse(structuredClone(record));
}

function wipeJoin(record: JoinActiveJournalRecord): void {
  zeroize(record.inviteBearer);
  zeroize(record.enrollmentSuccessor);
  zeroize(record.sessionSuccessor);
}

function asPrepared(record: JoinActiveJournalRecord): JoinPreparedJournalRecord {
  return joinJournalRecordSchema.parse({
    ...record,
    state: 'prepared',
  }) as JoinPreparedJournalRecord;
}

function fixedClock(): ClockPort {
  return { now: () => new Date(NOW) };
}

function ids<Id extends string>(...values: readonly Id[]): IdGeneratorPort<Id> {
  let index = 0;
  return {
    next(): Id {
      const value = values[index];
      index += 1;
      if (value === undefined) throw new Error('ID sequence exhausted');
      return value;
    },
  };
}

function bearer(fill: number): ApiBearerToken {
  return apiBearerTokenSchema.parse(Buffer.alloc(32, fill).toString('base64url'));
}

function locatorKey(locator: KeychainLocator | SessionCredentialLocator): string {
  return JSON.stringify(locator);
}

function paths(requests: CapturedRequest[], path: string): CapturedRequest[] {
  return requests.filter((request) => request.path === path);
}

function header(request: IncomingMessage, name: string): string | undefined {
  const value = request.headers[name];
  return Array.isArray(value) ? value[0] : value;
}

function json(response: ServerResponse, status: number, value: unknown): void {
  const body = JSON.stringify(value);
  response.writeHead(status, {
    'content-type': 'application/json',
    'content-length': Buffer.byteLength(body),
  });
  response.end(body);
}

function allZero(value: Uint8Array | undefined): boolean {
  return value?.every((byte) => byte === 0) === true;
}

function sameExchange(
  left: CapturedRequest,
  right: CapturedRequest | undefined,
): boolean {
  if (right === undefined) return false;
  return (
    left.authorization === right.authorization &&
    left.successor === right.successor &&
    left.body === right.body
  );
}

function required<Value>(value: Value | null | undefined): Value {
  if (value === undefined || value === null) throw new Error('Missing test value');
  return value;
}

async function rejected(promise: Promise<unknown>): Promise<unknown> {
  try {
    await promise;
  } catch (error) {
    return error;
  }
  throw new Error('Expected rejection');
}

function deferred<Value>(): Readonly<{
  promise: Promise<Value>;
  resolve: (value: Value | PromiseLike<Value>) => void;
}> {
  let resolver: ((value: Value | PromiseLike<Value>) => void) | null = null;
  const promise = new Promise<Value>((fulfill) => {
    resolver = fulfill;
  });
  return {
    promise,
    resolve: (value) => {
      if (resolver === null) throw new Error('Deferred resolver is unavailable');
      resolver(value);
    },
  };
}
