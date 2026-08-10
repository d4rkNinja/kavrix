import { randomFillSync } from 'node:crypto';

import type {
  ClockPort,
  IdGeneratorPort,
  KeychainPort,
  SessionCredentialPort,
} from '@kavrix/core';
import {
  constantTimeEqual,
  createDeviceKeySlot,
  createPortableKeySlot,
  createRecoveryKeySlot,
  decryptPayload,
  encryptPayload,
  formatPortableKey,
  formatRecoveryKey,
  generateDeviceKey,
  generatePortableKey,
  generateRecoveryKey,
  generateVaultRootKey,
  parsePortableKey,
  parseRecoveryKey,
  unlockDeviceKeySlot,
  zeroize,
  type DeviceKey,
  type PortableKey,
  type RecoveryKey,
} from '@kavrix/crypto';
import {
  apiBearerTokenSchema,
  associatedDataSchema,
  canonicalJson,
  deviceIdSchema,
  deviceUnlockSecretSchema,
  keySlotIdSchema,
  sessionCredentialSecretSchema,
  timestampSchema,
  vaultBootstrapRequestSchema,
  vaultIdSchema,
  vaultPreferencesSchema,
  type DeviceId,
  type KeySlotId,
  type ApiBearerToken,
  type Timestamp,
  type VaultBootstrapResponse,
  type VaultId,
  type VaultPreferences,
} from '@kavrix/schemas';
import { z } from 'zod';

import type { ControlPlaneClient } from './control-plane-client.js';
import { ControlPlaneFailure, VaultLifecycleError } from './errors.js';
import {
  initializationJournalRecordSchema,
  lifecycleOperationIdListSchema,
  lifecycleOperationIdSchema,
  type InitializationActiveJournalRecord,
  type InitializationJournalPort,
  type LifecycleOperationId,
} from './vault-lifecycle-journals.js';
import {
  vaultProfileSchema,
  type VaultProfile,
  type VaultProfileStorePort,
} from './vault-profile.js';

const initializationInputSchema = z
  .object({
    preferences: vaultPreferencesSchema,
    deviceKeyProvider: z.string().trim().min(1).max(128),
  })
  .strict();

export interface VaultInitializationIds {
  readonly operation: IdGeneratorPort<LifecycleOperationId>;
  readonly vault: IdGeneratorPort<VaultId>;
  readonly device: IdGeneratorPort<DeviceId>;
  readonly keySlot: IdGeneratorPort<KeySlotId>;
}

export interface VaultInitializationCoordinatorOptions {
  readonly controlPlane: ControlPlaneClient;
  readonly journal: InitializationJournalPort;
  readonly profiles: VaultProfileStorePort;
  readonly keychain: KeychainPort;
  readonly sessions: SessionCredentialPort;
  readonly clock: ClockPort;
  readonly ids: VaultInitializationIds;
}

export interface VaultInitializationInput {
  readonly preferences: VaultPreferences;
  readonly deviceKeyProvider: string;
}

export interface VaultInitializationConfirmation {
  readonly portableKey: string;
  readonly recoveryKey: string;
}

export interface VaultInitializationDisplayMaterial {
  readonly portableKey: string;
  readonly recoveryKey: string;
}

export interface VaultImportedPortableDisplayMaterial {
  readonly recoveryKey: string;
}

export interface VaultLifecycleReceipt {
  readonly operationId: LifecycleOperationId;
  readonly vaultId: VaultId;
  readonly deviceId: DeviceId;
}

export interface VaultInitializationReceipt extends VaultLifecycleReceipt {
  readonly profile: VaultProfile;
}

type AttemptState = 'created' | 'displayed' | 'running' | 'terminal';

type OwnedDisplayMaterial = Readonly<{
  portableKey?: string;
  recoveryKey: string;
}>;

/** Shared one-shot owner of confirmation keys and optional generated display material. */
class VaultInitializationAttempt {
  readonly operationId: LifecycleOperationId;
  #state: AttemptState = 'created';
  #portableDisplay: string | undefined;
  #recoveryDisplay: string | undefined;
  #portableKey: PortableKey | undefined;
  #recoveryKey: RecoveryKey | undefined;
  readonly #confirmOperation: (
    portableKey: PortableKey,
    recoveryKey: RecoveryKey,
  ) => Promise<VaultInitializationReceipt>;

  constructor(
    operationId: LifecycleOperationId,
    portableKey: PortableKey,
    recoveryKey: RecoveryKey,
    displayMaterial: OwnedDisplayMaterial,
    confirmOperation: (
      portableKey: PortableKey,
      recoveryKey: RecoveryKey,
    ) => Promise<VaultInitializationReceipt>,
  ) {
    this.operationId = operationId;
    this.#portableKey = portableKey;
    this.#recoveryKey = recoveryKey;
    this.#portableDisplay = displayMaterial.portableKey;
    this.#recoveryDisplay = displayMaterial.recoveryKey;
    this.#confirmOperation = confirmOperation;
  }

  protected takeOwnedDisplayMaterial(): OwnedDisplayMaterial {
    if (this.#state !== 'created')
      throw new VaultLifecycleError('operation-unavailable');
    const recoveryKey = this.#recoveryDisplay;
    if (recoveryKey === undefined) {
      throw new VaultLifecycleError('operation-unavailable');
    }
    const portableKey = this.#portableDisplay;
    this.#portableDisplay = undefined;
    this.#recoveryDisplay = undefined;
    this.#state = 'displayed';
    return {
      ...(portableKey === undefined ? {} : { portableKey }),
      recoveryKey,
    };
  }

  async confirm(
    confirmation: VaultInitializationConfirmation,
  ): Promise<VaultInitializationReceipt> {
    if (this.#state === 'running') throw new VaultLifecycleError('operation-busy');
    if (this.#state !== 'displayed') {
      throw new VaultLifecycleError('operation-unavailable');
    }
    const portableKey = this.#portableKey;
    const recoveryKey = this.#recoveryKey;
    if (portableKey === undefined || recoveryKey === undefined) {
      throw new VaultLifecycleError('operation-unavailable');
    }
    if (!confirmationMatches(confirmation, portableKey, recoveryKey)) {
      zeroize(portableKey);
      zeroize(recoveryKey);
      this.#portableKey = undefined;
      this.#recoveryKey = undefined;
      this.#state = 'terminal';
      throw new VaultLifecycleError('confirmation-failed');
    }
    this.#state = 'running';
    this.#portableKey = undefined;
    this.#recoveryKey = undefined;
    try {
      return await this.#confirmOperation(portableKey, recoveryKey);
    } finally {
      zeroize(portableKey);
      zeroize(recoveryKey);
      this.#state = 'terminal';
    }
  }

  cancel(): void {
    if (this.#state === 'running') throw new VaultLifecycleError('unsafe-cancel');
    if (this.#state === 'terminal') return;
    zeroize(this.#portableKey);
    zeroize(this.#recoveryKey);
    this.#portableKey = undefined;
    this.#recoveryKey = undefined;
    this.#portableDisplay = undefined;
    this.#recoveryDisplay = undefined;
    this.#state = 'terminal';
  }
}

/** One-shot owner of newly generated portable and recovery display material. */
export class VaultInitializationCreation extends VaultInitializationAttempt {
  constructor(
    operationId: LifecycleOperationId,
    portableKey: PortableKey,
    recoveryKey: RecoveryKey,
    confirmOperation: (
      portableKey: PortableKey,
      recoveryKey: RecoveryKey,
    ) => Promise<VaultInitializationReceipt>,
  ) {
    super(
      operationId,
      portableKey,
      recoveryKey,
      {
        portableKey: formatPortableKey(portableKey),
        recoveryKey: formatRecoveryKey(recoveryKey),
      },
      confirmOperation,
    );
  }

  takeDisplayMaterial(): VaultInitializationDisplayMaterial {
    const display = this.takeOwnedDisplayMaterial();
    if (display.portableKey === undefined) {
      throw new VaultLifecycleError('operation-unavailable');
    }
    return { portableKey: display.portableKey, recoveryKey: display.recoveryKey };
  }
}

/** One-shot owner that never formats or displays the caller-imported portable key. */
export class VaultImportedPortableInitializationCreation extends VaultInitializationAttempt {
  constructor(
    operationId: LifecycleOperationId,
    portableKey: PortableKey,
    recoveryKey: RecoveryKey,
    confirmOperation: (
      portableKey: PortableKey,
      recoveryKey: RecoveryKey,
    ) => Promise<VaultInitializationReceipt>,
  ) {
    super(
      operationId,
      portableKey,
      recoveryKey,
      { recoveryKey: formatRecoveryKey(recoveryKey) },
      confirmOperation,
    );
  }

  takeDisplayMaterial(): VaultImportedPortableDisplayMaterial {
    const display = this.takeOwnedDisplayMaterial();
    if (display.portableKey !== undefined) {
      throw new VaultLifecycleError('operation-unavailable');
    }
    return { recoveryKey: display.recoveryKey };
  }
}

export class VaultInitializationCoordinator {
  readonly #options: VaultInitializationCoordinatorOptions;
  readonly #serverUrl: VaultProfile['serverUrl'];
  readonly #busy = new Set<LifecycleOperationId>();

  constructor(options: VaultInitializationCoordinatorOptions) {
    this.#options = options;
    try {
      this.#serverUrl = vaultProfileSchema.shape.serverUrl.parse(
        options.controlPlane.baseUrl,
      );
    } catch {
      throw new VaultLifecycleError('invalid-input');
    }
  }

  begin(input: VaultInitializationInput): VaultInitializationCreation {
    const parsed = parseInitializationInput(input);
    const operationId = parseId(
      lifecycleOperationIdSchema,
      this.#options.ids.operation.next(),
    );
    const portableKey = generatePortableKey();
    const recoveryKey = generateRecoveryKey();
    try {
      return new VaultInitializationCreation(
        operationId,
        portableKey,
        recoveryKey,
        this.#confirmationOperation(operationId, parsed),
      );
    } catch {
      zeroize(portableKey);
      zeroize(recoveryKey);
      throw new VaultLifecycleError('invalid-input');
    }
  }

  beginImportedPortable(
    input: VaultInitializationInput,
    formattedPortableKey: string,
  ): VaultImportedPortableInitializationCreation {
    let portableKey: PortableKey;
    try {
      portableKey = parsePortableKey(formattedPortableKey);
    } catch {
      throw new VaultLifecycleError('invalid-input');
    }
    let recoveryKey: RecoveryKey | undefined;
    try {
      const parsed = parseInitializationInput(input);
      const operationId = parseId(
        lifecycleOperationIdSchema,
        this.#options.ids.operation.next(),
      );
      recoveryKey = generateRecoveryKey();
      return new VaultImportedPortableInitializationCreation(
        operationId,
        portableKey,
        recoveryKey,
        this.#confirmationOperation(operationId, parsed),
      );
    } catch {
      zeroize(portableKey);
      zeroize(recoveryKey);
      throw new VaultLifecycleError('invalid-input');
    }
  }

  async listOperations(): Promise<readonly LifecycleOperationId[]> {
    try {
      return lifecycleOperationIdListSchema.parse(
        await this.#options.journal.listOperationIds(),
      );
    } catch {
      throw new VaultLifecycleError('journal');
    }
  }

  async resume(operationId: LifecycleOperationId): Promise<VaultInitializationReceipt> {
    const id = parseId(lifecycleOperationIdSchema, operationId);
    return this.#exclusive(id, async () => {
      const record = await this.#load(id);
      if (record === null) throw new VaultLifecycleError('operation-unavailable');
      if (record.state === 'committed') {
        const profile = await this.#persistProfile(record.profile);
        return receiptFromBootstrap(record.operationId, record.receipt, profile);
      }
      return this.#resumeActive(record);
    });
  }

  async cancel(operationId: LifecycleOperationId): Promise<void> {
    const id = parseId(lifecycleOperationIdSchema, operationId);
    await this.#exclusive(id, async () => {
      const record = await this.#load(id);
      if (record === null || record.state === 'committed') return;
      if (record.state !== 'prepared') throw new VaultLifecycleError('unsafe-cancel');
      await this.#deletePrepared(record);
    });
  }

  #confirmationOperation(
    operationId: LifecycleOperationId,
    input: z.infer<typeof initializationInputSchema>,
  ): (
    portableKey: PortableKey,
    recoveryKey: RecoveryKey,
  ) => Promise<VaultInitializationReceipt> {
    return (portableKey, recoveryKey) =>
      this.#exclusive(operationId, () =>
        this.#prepareAndBootstrap(
          operationId,
          input.preferences,
          input.deviceKeyProvider,
          portableKey,
          recoveryKey,
        ),
      );
  }

  async #prepareAndBootstrap(
    operationId: LifecycleOperationId,
    preferences: VaultPreferences,
    deviceKeyProvider: string,
    portableKey: PortableKey,
    recoveryKey: RecoveryKey,
  ): Promise<VaultInitializationReceipt> {
    const vaultId = parseId(vaultIdSchema, this.#options.ids.vault.next());
    const deviceId = parseId(deviceIdSchema, this.#options.ids.device.next());
    const slotIds = [
      parseId(keySlotIdSchema, this.#options.ids.keySlot.next()),
      parseId(keySlotIdSchema, this.#options.ids.keySlot.next()),
      parseId(keySlotIdSchema, this.#options.ids.keySlot.next()),
    ] as const;
    if (new Set(slotIds).size !== slotIds.length) {
      throw new VaultLifecycleError('invalid-input');
    }
    const createdAt = nowTimestamp(this.#options.clock);
    const rootKey = generateVaultRootKey();
    const deviceKey = generateDeviceKey();
    const sessionSecret = sessionCredentialSecretSchema.parse(
      randomFillSync(new Uint8Array(32)),
    );
    let plaintext: Uint8Array | undefined;
    try {
      const identity = {
        vaultId,
        schemaVersion: 1,
        keyVersion: 1,
        createdAt,
      } as const;
      const [portableSlot, recoverySlot, deviceSlot] = await Promise.all([
        createPortableKeySlot(
          { ...identity, slotId: slotIds[0] },
          portableKey,
          rootKey,
        ),
        createRecoveryKeySlot(
          { ...identity, slotId: slotIds[1] },
          recoveryKey,
          rootKey,
        ),
        createDeviceKeySlot(
          {
            ...identity,
            slotId: slotIds[2],
            deviceId,
            provider: deviceKeyProvider,
          },
          deviceKey,
          rootKey,
        ),
      ]);
      plaintext = new TextEncoder().encode(JSON.stringify(preferences));
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
      const request = vaultBootstrapRequestSchema.parse({
        vault: {
          id: vaultId,
          schemaVersion: 1,
          cryptographicVersion: 1,
          keySlots: [portableSlot, recoverySlot, deviceSlot],
          currentKeyVersion: 1,
          revision: 0,
          encryptedPreferences,
          createdAt,
          updatedAt: createdAt,
        },
        device: { id: deviceId, schemaVersion: 1 },
      });
      const active = initializationJournalRecordSchema.parse({
        version: 1,
        kind: 'vault-initialization',
        operationId,
        state: 'prepared',
        request,
        deviceLocator: {
          version: 1,
          vaultId,
          deviceId,
          keySlotId: slotIds[2],
        },
        sessionLocator: {
          version: 1,
          vaultId,
          deviceId,
          purpose: 'api-session',
        },
        profile: {
          version: 1,
          serverUrl: this.#serverUrl,
          vaultId,
          deviceId,
          deviceLocator: {
            version: 1,
            vaultId,
            deviceId,
            keySlotId: slotIds[2],
          },
          sessionLocator: {
            version: 1,
            vaultId,
            deviceId,
            purpose: 'api-session',
          },
        },
      });
      if (active.state === 'committed') throw new VaultLifecycleError('journal');
      return await this.#persistAndBootstrap(active, deviceKey, sessionSecret);
    } catch (error) {
      throw lifecycleError(error);
    } finally {
      zeroize(plaintext);
      zeroize(rootKey);
      zeroize(deviceKey);
      zeroize(sessionSecret);
    }
  }

  async #persistAndBootstrap(
    record: InitializationActiveJournalRecord,
    deviceKey: DeviceKey,
    sessionSecret: z.infer<typeof sessionCredentialSecretSchema>,
  ): Promise<VaultInitializationReceipt> {
    await this.#assertProtectedLocatorsUnused(record);
    try {
      await this.#options.journal.createPrepared(record);
    } catch {
      throw new VaultLifecycleError('journal');
    }
    try {
      await this.#storeProtected(record, deviceKey, sessionSecret);
      await this.#markNetworkAttempted(record);
      await this.#persistProfile(record.profile);
      return await this.#bootstrap(record, sessionSecret);
    } catch (error) {
      await this.#deletePreparedBestEffort(record.operationId);
      throw error;
    }
  }

  async #resumeActive(
    record: InitializationActiveJournalRecord,
  ): Promise<VaultInitializationReceipt> {
    const profile = this.#parseBoundProfile(record.profile);
    if (record.state === 'network-attempted') {
      await this.#persistProfile(profile);
    }
    let deviceSecret: Awaited<ReturnType<KeychainPort['load']>>;
    let sessionSecret: Awaited<ReturnType<SessionCredentialPort['load']>>;
    try {
      [deviceSecret, sessionSecret] = await Promise.all([
        this.#options.keychain.load(record.deviceLocator),
        this.#options.sessions.load(record.sessionLocator),
      ]);
    } catch {
      throw new VaultLifecycleError('protected-storage');
    }
    if (deviceSecret === null || sessionSecret === null) {
      zeroize(deviceSecret ?? undefined);
      zeroize(sessionSecret ?? undefined);
      if (record.state === 'prepared') {
        await this.#deletePrepared(record);
        throw new VaultLifecycleError('restart-required');
      }
      throw new VaultLifecycleError('protected-storage');
    }
    try {
      await verifyDeviceBinding(record, deviceSecret);
      if (record.state === 'prepared') {
        await this.#markNetworkAttempted(record);
        await this.#persistProfile(profile);
      }
      return await this.#bootstrap(record, sessionSecret);
    } finally {
      zeroize(deviceSecret);
      zeroize(sessionSecret);
    }
  }

  async #storeProtected(
    record: InitializationActiveJournalRecord,
    deviceKey: DeviceKey,
    sessionSecret: z.infer<typeof sessionCredentialSecretSchema>,
  ): Promise<void> {
    try {
      await this.#options.keychain.store(
        record.deviceLocator,
        deviceUnlockSecretSchema.parse(deviceKey),
      );
      await this.#options.sessions.store(record.sessionLocator, sessionSecret);
    } catch (error) {
      throw lifecycleError(error, 'protected-storage');
    }
  }

  async #assertProtectedLocatorsUnused(
    record: InitializationActiveJournalRecord,
  ): Promise<void> {
    let existingDevice: Awaited<ReturnType<KeychainPort['load']>>;
    let existingSession: Awaited<ReturnType<SessionCredentialPort['load']>>;
    try {
      [existingDevice, existingSession] = await Promise.all([
        this.#options.keychain.load(record.deviceLocator),
        this.#options.sessions.load(record.sessionLocator),
      ]);
    } catch {
      throw new VaultLifecycleError('protected-storage');
    }
    try {
      if (existingDevice !== null || existingSession !== null) {
        throw new VaultLifecycleError('protected-storage');
      }
    } finally {
      zeroize(existingDevice ?? undefined);
      zeroize(existingSession ?? undefined);
    }
  }

  async #bootstrap(
    record: InitializationActiveJournalRecord,
    sessionSecret: Uint8Array,
  ): Promise<VaultInitializationReceipt> {
    const bearer = bearerFromBytes(sessionSecret);
    const receipt = await this.#options.controlPlane.bootstrap(bearer, record.request);
    try {
      await this.#options.journal.commit(
        record.operationId,
        receipt,
        record.profile,
        nowTimestamp(this.#options.clock),
      );
    } catch {
      throw new VaultLifecycleError('journal');
    }
    return receiptFromBootstrap(record.operationId, receipt, record.profile);
  }

  async #persistProfile(profileInput: VaultProfile): Promise<VaultProfile> {
    try {
      const profile = this.#parseBoundProfile(profileInput);
      await this.#options.profiles.store(structuredClone(profile));
      const loaded = await this.#options.profiles.load(
        profile.vaultId,
        profile.deviceId,
      );
      const persisted = vaultProfileSchema.parse(loaded);
      if (canonicalJson(persisted) !== canonicalJson(profile)) {
        throw new VaultLifecycleError('profile');
      }
      return persisted;
    } catch {
      throw new VaultLifecycleError('profile');
    }
  }

  #parseBoundProfile(profileInput: VaultProfile): VaultProfile {
    try {
      const profile = vaultProfileSchema.parse(profileInput);
      if (profile.serverUrl !== this.#serverUrl) {
        throw new VaultLifecycleError('profile');
      }
      return profile;
    } catch {
      throw new VaultLifecycleError('profile');
    }
  }

  async #markNetworkAttempted(
    record: InitializationActiveJournalRecord,
  ): Promise<void> {
    try {
      await this.#options.journal.markNetworkAttempted(record.operationId);
    } catch {
      const afterFailure = await this.#loadOrNull(record.operationId);
      if (afterFailure?.state === 'prepared') {
        await this.#deletePrepared(afterFailure);
      }
      throw new VaultLifecycleError('journal');
    }
  }

  async #load(
    operationId: LifecycleOperationId,
  ): Promise<ReturnType<typeof initializationJournalRecordSchema.parse> | null> {
    try {
      const record = await this.#options.journal.load(operationId);
      return record === null ? null : initializationJournalRecordSchema.parse(record);
    } catch {
      throw new VaultLifecycleError('journal');
    }
  }

  async #loadOrNull(
    operationId: LifecycleOperationId,
  ): Promise<ReturnType<typeof initializationJournalRecordSchema.parse> | null> {
    try {
      return await this.#load(operationId);
    } catch {
      return null;
    }
  }

  async #deletePrepared(record: InitializationActiveJournalRecord): Promise<void> {
    if (record.state !== 'prepared') throw new VaultLifecycleError('unsafe-cancel');
    const results = await Promise.allSettled([
      this.#options.keychain.delete(record.deviceLocator),
      this.#options.sessions.delete(record.sessionLocator),
    ]);
    if (results.some((result) => result.status === 'rejected')) {
      throw new VaultLifecycleError('protected-storage');
    }
    try {
      await this.#options.journal.deletePrepared(record.operationId);
    } catch {
      throw new VaultLifecycleError('journal');
    }
  }

  async #deletePreparedBestEffort(operationId: LifecycleOperationId): Promise<void> {
    const record = await this.#loadOrNull(operationId);
    if (record?.state !== 'prepared') return;
    try {
      await this.#deletePrepared(record);
    } catch {
      // A durable prepared record remains cancellable/resumable; never hide the
      // original generic failure with cleanup detail.
    }
  }

  async #exclusive<Output>(
    operationId: LifecycleOperationId,
    operation: () => Promise<Output>,
  ): Promise<Output> {
    if (this.#busy.has(operationId)) throw new VaultLifecycleError('operation-busy');
    this.#busy.add(operationId);
    try {
      return await operation();
    } finally {
      this.#busy.delete(operationId);
    }
  }
}

function confirmationMatches(
  confirmation: VaultInitializationConfirmation,
  expectedPortable: PortableKey,
  expectedRecovery: RecoveryKey,
): boolean {
  let portableCandidate: Uint8Array = new Uint8Array(32);
  let recoveryCandidate: Uint8Array = new Uint8Array(32);
  let portableValid = false;
  let recoveryValid = false;
  try {
    try {
      portableCandidate = parsePortableKey(confirmation.portableKey);
      portableValid = true;
    } catch {
      // Constant-time comparisons still run against an equal-length zero value.
    }
    try {
      recoveryCandidate = parseRecoveryKey(confirmation.recoveryKey);
      recoveryValid = true;
    } catch {
      // Constant-time comparisons still run against an equal-length zero value.
    }
    const portableMatches = constantTimeEqual(portableCandidate, expectedPortable);
    const recoveryMatches = constantTimeEqual(recoveryCandidate, expectedRecovery);
    return portableValid && recoveryValid && portableMatches && recoveryMatches;
  } finally {
    zeroize(portableCandidate);
    zeroize(recoveryCandidate);
  }
}

async function verifyDeviceBinding(
  record: InitializationActiveJournalRecord,
  deviceSecret: Uint8Array,
): Promise<void> {
  const slot = record.request.vault.keySlots.find(
    (candidate) => candidate.id === record.deviceLocator.keySlotId,
  );
  if (slot?.type !== 'device-key') throw new VaultLifecycleError('protocol');
  let rootKey: Awaited<ReturnType<typeof unlockDeviceKeySlot>> | undefined;
  let plaintext: Uint8Array | undefined;
  try {
    rootKey = await unlockDeviceKeySlot(slot, deviceSecret, {
      vaultId: record.request.vault.id,
      slotId: slot.id,
      schemaVersion: record.request.vault.schemaVersion,
      keyVersion: record.request.vault.currentKeyVersion,
    });
    plaintext = await decryptPayload(
      record.request.vault.encryptedPreferences,
      rootKey,
      associatedDataSchema.parse({
        version: 1,
        schemaVersion: record.request.vault.schemaVersion,
        keyVersion: record.request.vault.currentKeyVersion,
        vaultId: record.request.vault.id,
        entityType: 'vault-preferences',
        entityId: record.request.vault.id,
        purpose: 'vault-preferences',
      }),
    );
    const decoded = new TextDecoder('utf-8', { fatal: true }).decode(plaintext);
    vaultPreferencesSchema.parse(JSON.parse(decoded) as unknown);
  } catch {
    throw new VaultLifecycleError('protocol');
  } finally {
    zeroize(plaintext);
    zeroize(rootKey);
  }
}

function bearerFromBytes(value: Uint8Array): ApiBearerToken {
  return apiBearerTokenSchema.parse(
    Buffer.from(value.buffer, value.byteOffset, value.byteLength).toString('base64url'),
  );
}

function nowTimestamp(clock: ClockPort): Timestamp {
  try {
    return timestampSchema.parse(clock.now().toISOString());
  } catch {
    throw new VaultLifecycleError('invalid-input');
  }
}

function parseInitializationInput(
  input: VaultInitializationInput,
): z.infer<typeof initializationInputSchema> {
  try {
    return initializationInputSchema.parse(input);
  } catch {
    throw new VaultLifecycleError('invalid-input');
  }
}

function parseId<Output>(
  schema: Readonly<{ parse(value: unknown): Output }>,
  value: unknown,
): Output {
  try {
    return schema.parse(value);
  } catch {
    throw new VaultLifecycleError('invalid-input');
  }
}

function receiptFromBootstrap(
  operationId: LifecycleOperationId,
  receipt: VaultBootstrapResponse,
  profileInput: VaultProfile,
): VaultInitializationReceipt {
  try {
    const profile = vaultProfileSchema.parse(profileInput);
    if (profile.vaultId !== receipt.vaultId || profile.deviceId !== receipt.deviceId) {
      throw new VaultLifecycleError('profile');
    }
    return {
      operationId,
      vaultId: receipt.vaultId,
      deviceId: receipt.deviceId,
      profile,
    };
  } catch {
    throw new VaultLifecycleError('profile');
  }
}

function lifecycleError(
  error: unknown,
  fallback: ConstructorParameters<typeof VaultLifecycleError>[0] = 'protocol',
): Error {
  return error instanceof VaultLifecycleError || error instanceof ControlPlaneFailure
    ? error
    : new VaultLifecycleError(fallback);
}
