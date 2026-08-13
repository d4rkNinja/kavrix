import { createHash } from 'node:crypto';

import {
  ControlPlaneClient,
  ControlPlaneFailure,
  FetchSyncTransport,
  isInsecureLoopbackProfile,
  slotBinding,
  VaultJoinCoordinator,
  VaultLifecycleError,
  vaultProfileSchema,
  type ControlPlaneClientOptions,
  type LifecycleOperationId,
  type VaultJoinInput,
  type VaultLifecycleReceipt,
  type VaultProfile,
} from '@kavrix/client';
import {
  AuthenticationError,
  CryptoInputError,
  constantTimeEqual,
  createDeviceKeySlot,
  encodeBase64Url,
  generateDeviceKey,
  unlockDeviceKeySlot,
  unlockPortableKeySlot,
  zeroize,
  type DeviceKey,
  type VaultRootKey,
} from '@kavrix/crypto';
import {
  apiBearerTokenSchema,
  canonicalJson,
  deviceIdSchema,
  deviceUnlockSecretSchema,
  keySlotIdSchema,
  sessionCredentialSecretSchema,
  timestampSchema,
  vaultIdSchema,
  vaultRecordSchema,
  type ApiBearerToken,
  type ApiSessionResponse,
  type DeviceId,
  type DeviceUnlockSecret,
  type KeySlotId,
  type VaultId,
  type VaultRecord,
} from '@kavrix/schemas';
import {
  SyncEngine,
  type SyncEngineOptions,
  type SyncLocalStorePort,
} from '@kavrix/sync';
import { validatePortableKeyFile } from '@kavrix/key-files';
import type { KeychainPort, SessionCredentialPort } from '@kavrix/core';
import type { ProtectedSyncStatePort } from '@kavrix/sync';

import type { CliRecoverRequest, CliRecoverResult } from '../contracts.js';
import { CliUsageError } from '../errors.js';
import { acquiredSecretSchema, type SecretInputPort } from '../secret-input.js';
import {
  openProductionEnvironment,
  type ProductionEnvironment,
} from './environment.js';
import { resolveCliDataPaths } from './paths.js';
import {
  productionClock,
  randomIdGenerator,
  randomIdempotencyKeys,
} from './runtime-adapters.js';
import {
  createProductionPortableKeyFileReader,
  type ProductionPortableKeyFileReaderDependencies,
} from './portable-key-files.js';
import {
  createSecretBackend,
  type SecretBackend,
  type SecretBackendPolicy,
} from './secret-backend.js';

const REQUIRED_RECOVERY_SCOPES = ['sync:read', 'sync:write', 'device:manage'] as const;
const DEVICE_KEY_PROVIDER = 'native';

export interface RecoveryControlPlane {
  getSession(
    bearerToken: ApiBearerToken,
    expectedVaultId: VaultId,
    expectedDeviceId: DeviceId,
  ): Promise<Pick<ApiSessionResponse, 'vaultId' | 'deviceId' | 'scopes'>>;
  fetchVault(bearerToken: ApiBearerToken, vaultId: VaultId): Promise<VaultRecord>;
  publishKeySlot(
    bearerToken: ApiBearerToken,
    vaultId: VaultId,
    slotId: KeySlotId,
    request: Readonly<{
      expectedVaultRevision: number;
      idempotencyKey: string;
      record: VaultRecord;
    }>,
  ): Promise<void>;
}

export interface RecoveryCoordinator {
  begin(input: VaultJoinInput): Promise<{
    readonly operationId: LifecycleOperationId;
    readonly vaultId: VaultId;
    readonly deviceId: DeviceId;
  }>;
  resume(
    operationId: LifecycleOperationId,
    formattedPortableKey: string,
  ): Promise<VaultLifecycleReceipt>;
  cancel(operationId: LifecycleOperationId): Promise<void>;
}

export interface RecoveryEnvironment {
  readonly profiles: {
    listProfiles(): Promise<readonly VaultProfile[]>;
    load(vaultId: VaultId, deviceId: DeviceId): Promise<VaultProfile | null>;
    store(profile: VaultProfile): Promise<void>;
  };
  readonly joinJournal: ConstructorParameters<
    typeof VaultJoinCoordinator
  >[0]['journal'];
  openSyncStore(profile: VaultProfile): Promise<SyncLocalStorePort>;
}

export type RecoveryBackend = Pick<
  {
    readonly sessions: SessionCredentialPort;
    readonly keychain: KeychainPort;
    readonly protectedSyncState: ProtectedSyncStatePort;
  },
  'sessions' | 'keychain' | 'protectedSyncState'
>;

export interface RecoverExistingVaultOptions {
  readonly environment: RecoveryEnvironment;
  readonly backend: RecoveryBackend;
  readonly controlPlane: RecoveryControlPlane;
  readonly coordinator: RecoveryCoordinator;
  readonly request: CliRecoverRequest;
  readonly operationId?: LifecycleOperationId;
  readonly inviteToken?: string;
  readonly portableKey?: string;
  readonly allowInsecureLoopbackDevelopment?: boolean;
  readonly syncEngineFactory?: ProductionRecoveryDependencies['syncEngineFactory'];
}

export interface ProductionRecoveryRequest {
  readonly environment: Readonly<Record<string, string | undefined>>;
  readonly secrets: SecretInputPort;
  readonly backendPolicy: SecretBackendPolicy;
  readonly request: CliRecoverRequest;
  readonly inviteFromStdin?: boolean;
  readonly portableKeyFromStdin?: boolean;
  readonly keyFilePath?: string;
  readonly keyFilePassphraseFromStdin?: boolean;
  readonly operationId?: LifecycleOperationId;
  readonly allowInsecureLoopbackDevelopment?: boolean;
}

export interface ProductionRecoveryCancelRequest {
  readonly environment: Readonly<Record<string, string | undefined>>;
  readonly secrets: SecretInputPort;
  readonly backendPolicy: SecretBackendPolicy;
  readonly request: CliRecoverRequest;
  readonly operationId: LifecycleOperationId;
  readonly allowInsecureLoopbackDevelopment?: boolean;
}

export interface ProductionRecoveryDependencies {
  readonly resolvePaths: typeof resolveCliDataPaths;
  readonly validateKeyFile: typeof validatePortableKeyFile;
  readonly createBackend: typeof createSecretBackend;
  readonly openEnvironment: typeof openProductionEnvironment;
  readonly controlPlaneFactory: (
    options: ControlPlaneClientOptions,
  ) => RecoveryControlPlane;
  readonly coordinatorFactory: (
    options: ConstructorParameters<typeof VaultJoinCoordinator>[0],
  ) => RecoveryCoordinator;
  readonly syncEngineFactory: (options: SyncEngineOptions) => {
    synchronize(
      input: Readonly<{ vaultId: VaultId; deviceId: DeviceId }>,
    ): Promise<unknown>;
  };
  readonly keyFileReaderFactory: (
    options: Parameters<typeof createProductionPortableKeyFileReader>[0],
    dependencies?: ProductionPortableKeyFileReaderDependencies,
  ) => ReturnType<typeof createProductionPortableKeyFileReader>;
}

const DEFAULT_DEPENDENCIES: ProductionRecoveryDependencies = {
  resolvePaths: resolveCliDataPaths,
  validateKeyFile: validatePortableKeyFile,
  createBackend: createSecretBackend,
  openEnvironment: openProductionEnvironment,
  controlPlaneFactory: (options) => new ControlPlaneClient(options),
  coordinatorFactory: (options) => new VaultJoinCoordinator(options),
  syncEngineFactory: (options) => new SyncEngine(options),
  keyFileReaderFactory: createProductionPortableKeyFileReader,
};

/**
 * Completes a fresh-home recovery after the join coordinator has authenticated
 * the portable slot and persisted the enrollment session. The returned object
 * contains only opaque identifiers; root/device/session material is owned and
 * wiped inside this operation.
 */
export async function recoverExistingVault(
  options: RecoverExistingVaultOptions,
): Promise<CliRecoverResult> {
  const identity = validateRecoveryIdentity(
    options.request,
    options.allowInsecureLoopbackDevelopment === true,
  );
  const profiles = await options.environment.profiles.listProfiles();
  if (profiles.length > 0) {
    throw new CliUsageError('A vault profile already exists on this device.');
  }

  let receipt: VaultLifecycleReceipt;
  try {
    if (options.operationId === undefined) {
      const inviteToken = options.inviteToken;
      const portableKey = options.portableKey;
      if (inviteToken === undefined || portableKey === undefined) {
        throw new CliUsageError('Recovery requires an invite and portable key.');
      }
      const inviteBearer = apiBearerTokenSchema.parse(inviteToken);
      const preparation = await options.coordinator.begin({
        inviteBearer,
        expectedVaultId: identity.vaultId,
      });
      receipt = await options.coordinator.resume(preparation.operationId, portableKey);
    } else {
      receipt = await options.coordinator.resume(
        options.operationId,
        options.portableKey ?? '',
      );
    }
  } catch (error) {
    throw mapRecoveryError(error);
  }

  if (receipt.vaultId !== identity.vaultId) {
    throw new VaultLifecycleError('protocol');
  }
  return finalizeRecovery(options, identity.serverUrl, receipt).catch(
    (error: unknown) => {
      throw mapRecoveryError(error);
    },
  );
}

/** Runs recovery with the real protected backend, journals, stores, and HTTPS client. */
export async function executeProductionRecovery(
  request: ProductionRecoveryRequest,
  overrides: Partial<ProductionRecoveryDependencies> = {},
): Promise<CliRecoverResult> {
  const dependencies = { ...DEFAULT_DEPENDENCIES, ...overrides };
  const identity = validateRecoveryIdentity(
    request.request,
    request.allowInsecureLoopbackDevelopment === true,
  );
  const paths = dependencies.resolvePaths(request.environment);
  if (request.keyFilePath !== undefined) {
    await dependencies.validateKeyFile(request.keyFilePath);
  }

  const backend = await dependencies.createBackend(
    paths,
    request.secrets,
    request.backendPolicy,
  );
  let environment: ProductionEnvironment;
  try {
    environment = await dependencies.openEnvironment(paths, backend);
  } catch (openFailure) {
    await backend.close();
    throw openFailure;
  }

  let outcome:
    | Readonly<{ succeeded: true; value: CliRecoverResult }>
    | Readonly<{ succeeded: false; error: unknown }>;
  try {
    const controlPlane = dependencies.controlPlaneFactory({
      baseUrl: identity.serverUrl,
      ...(request.allowInsecureLoopbackDevelopment === true
        ? { allowInsecureLoopbackDevelopment: true }
        : {}),
    });
    const coordinator = dependencies.coordinatorFactory({
      controlPlane: controlPlane as ConstructorParameters<
        typeof VaultJoinCoordinator
      >[0]['controlPlane'],
      journal: environment.joinJournal,
      sessions: backend.sessions,
      clock: productionClock(),
      ids: {
        operation: randomIdGenerator(),
        device: randomIdGenerator(),
      },
    });
    const sources = await acquireRecoverySources(
      request,
      request.secrets,
      dependencies,
    );
    outcome = {
      succeeded: true,
      value: await recoverExistingVault({
        environment,
        backend,
        controlPlane,
        coordinator,
        request: {
          ...request.request,
        },
        ...(request.operationId === undefined
          ? {}
          : { operationId: request.operationId }),
        ...(sources.inviteToken === undefined
          ? {}
          : { inviteToken: sources.inviteToken }),
        ...(sources.portableKey === undefined
          ? {}
          : { portableKey: sources.portableKey }),
        ...(request.allowInsecureLoopbackDevelopment === undefined
          ? {}
          : {
              allowInsecureLoopbackDevelopment:
                request.allowInsecureLoopbackDevelopment,
            }),
        syncEngineFactory: dependencies.syncEngineFactory,
      }),
    };
  } catch (error) {
    outcome = { succeeded: false, error };
  }

  let cleanup:
    Readonly<{ succeeded: true }> | Readonly<{ succeeded: false; error: unknown }>;
  try {
    await environment.close();
    cleanup = { succeeded: true };
  } catch (error) {
    cleanup = { succeeded: false, error };
  }

  if (!cleanup.succeeded) {
    if (!outcome.succeeded) {
      throw new AggregateError(
        [outcome.error, cleanup.error],
        'The recovery operation and cleanup both failed.',
        { cause: outcome.error },
      );
    }
    throw cleanup.error;
  }
  if (!outcome.succeeded) throw outcome.error;
  return outcome.value;
}

/** Cancels only a locally prepared recovery journal; it never contacts the server. */
export async function executeProductionRecoveryCancel(
  request: ProductionRecoveryCancelRequest,
  overrides: Partial<ProductionRecoveryDependencies> = {},
): Promise<void> {
  const dependencies = { ...DEFAULT_DEPENDENCIES, ...overrides };
  const identity = validateRecoveryIdentity(
    request.request,
    request.allowInsecureLoopbackDevelopment === true,
  );
  const paths = dependencies.resolvePaths(request.environment);
  const backend = await dependencies.createBackend(
    paths,
    request.secrets,
    request.backendPolicy,
  );
  let environment: ProductionEnvironment;
  try {
    environment = await dependencies.openEnvironment(paths, backend);
  } catch (openFailure) {
    await backend.close();
    throw openFailure;
  }

  let operationFailure: unknown;
  try {
    const controlPlane = dependencies.controlPlaneFactory({
      baseUrl: identity.serverUrl,
      ...(request.allowInsecureLoopbackDevelopment === true
        ? { allowInsecureLoopbackDevelopment: true }
        : {}),
    });
    const coordinator = dependencies.coordinatorFactory({
      controlPlane: controlPlane as ConstructorParameters<
        typeof VaultJoinCoordinator
      >[0]['controlPlane'],
      journal: environment.joinJournal,
      sessions: backend.sessions,
      clock: productionClock(),
      ids: {
        operation: randomIdGenerator(),
        device: randomIdGenerator(),
      },
    });
    await coordinator.cancel(request.operationId);
  } catch (error) {
    operationFailure = error;
  }

  let cleanupFailure: unknown;
  try {
    await environment.close();
  } catch (error) {
    cleanupFailure = error;
  }
  if (operationFailure !== undefined && cleanupFailure !== undefined) {
    throw new AggregateError(
      [operationFailure, cleanupFailure],
      'The recovery cancellation and cleanup both failed.',
      { cause: operationFailure },
    );
  }
  if (operationFailure !== undefined) throw operationFailure;
  if (cleanupFailure !== undefined) throw cleanupFailure;
}

async function finalizeRecovery(
  options: RecoverExistingVaultOptions,
  serverUrl: string,
  receipt: VaultLifecycleReceipt,
): Promise<CliRecoverResult> {
  const sessionLocator = {
    version: 1 as const,
    vaultId: receipt.vaultId,
    deviceId: receipt.deviceId,
    purpose: 'api-session' as const,
  };
  let sessionSecret: Uint8Array | null = null;
  let deviceSecret: DeviceUnlockSecret | null = null;
  let deviceKey: DeviceKey | undefined;
  let rootKey: VaultRootKey | undefined;
  let bearer: ApiBearerToken | undefined;
  try {
    sessionSecret = await options.backend.sessions.load(sessionLocator);
    if (sessionSecret === null) throw new VaultLifecycleError('protected-storage');
    const parsedSession = sessionCredentialSecretSchema.safeParse(sessionSecret);
    if (!parsedSession.success) throw new VaultLifecycleError('protected-storage');
    bearer = apiBearerTokenSchema.parse(encodeBase64Url(parsedSession.data));

    const remoteSession = await options.controlPlane.getSession(
      bearer,
      receipt.vaultId,
      receipt.deviceId,
    );
    if (
      remoteSession.vaultId !== receipt.vaultId ||
      remoteSession.deviceId !== receipt.deviceId
    ) {
      throw new VaultLifecycleError('protocol');
    }
    assertRecoveryScopes(remoteSession);

    let vault = parseRecoveryVault(
      await options.controlPlane.fetchVault(bearer, receipt.vaultId),
      receipt.vaultId,
    );
    const slotId = recoveryDeviceSlotId(receipt.operationId);
    const deviceLocator = {
      version: 1 as const,
      vaultId: receipt.vaultId,
      deviceId: receipt.deviceId,
      keySlotId: slotId,
    };
    const matchingSlots = vault.keySlots.filter((slot) => slot.id === slotId);
    if (matchingSlots.length > 1) throw new VaultLifecycleError('protocol');
    const currentSlot = matchingSlots[0];

    if (currentSlot !== undefined) {
      if (
        currentSlot.type !== 'device-key' ||
        currentSlot.deviceId !== receipt.deviceId ||
        currentSlot.state !== 'active' ||
        currentSlot.keyVersion !== vault.currentKeyVersion
      ) {
        throw new VaultLifecycleError('protocol');
      }
      deviceSecret = await options.backend.keychain.load(deviceLocator);
      if (deviceSecret === null) throw new VaultLifecycleError('protected-storage');
      const parsedDevice = deviceUnlockSecretSchema.safeParse(deviceSecret);
      if (!parsedDevice.success) throw new VaultLifecycleError('protected-storage');
      rootKey = await unlockDeviceKeySlot(
        currentSlot,
        parsedDevice.data,
        slotBinding(vault, currentSlot),
      );
    } else {
      const portableKey = options.portableKey;
      if (portableKey === undefined || portableKey.length === 0) {
        throw new CliUsageError(
          'A portable key is required to finish this recovery operation.',
        );
      }
      rootKey = await unlockPortableSlot(vault, portableKey);
      deviceKey = generateDeviceKey();
      const createdAt = recoveryTimestamp(vault.updatedAt);
      const slot = await createDeviceKeySlot(
        {
          vaultId: vault.id,
          slotId,
          schemaVersion: vault.schemaVersion,
          keyVersion: vault.currentKeyVersion,
          createdAt,
          deviceId: receipt.deviceId,
          provider: DEVICE_KEY_PROVIDER,
        },
        deviceKey,
        rootKey,
      );
      deviceSecret = deviceUnlockSecretSchema.parse(deviceKey);
      await options.backend.keychain.store(deviceLocator, deviceSecret);
      const storedDevice = await options.backend.keychain.load(deviceLocator);
      try {
        if (storedDevice === null || !constantTimeEqual(storedDevice, deviceSecret)) {
          throw new VaultLifecycleError('protected-storage');
        }
      } finally {
        zeroize(storedDevice ?? undefined);
      }

      const next = vaultRecordSchema.parse({
        ...vault,
        keySlots: [...vault.keySlots, slot],
        revision: vault.revision + 1,
        updatedAt: createdAt,
      });
      await options.controlPlane.publishKeySlot(bearer, vault.id, slotId, {
        expectedVaultRevision: vault.revision,
        idempotencyKey: recoverySlotIdempotencyKey(receipt.operationId),
        record: next,
      });
      vault = parseRecoveryVault(
        await options.controlPlane.fetchVault(bearer, receipt.vaultId),
        receipt.vaultId,
      );
      const published = vault.keySlots.find((candidate) => candidate.id === slotId);
      if (
        published?.type !== 'device-key' ||
        published.deviceId !== receipt.deviceId ||
        published.state !== 'active' ||
        published.keyVersion !== vault.currentKeyVersion
      ) {
        throw new VaultLifecycleError('protocol');
      }
      const verifiedRoot = await unlockDeviceKeySlot(
        published,
        deviceSecret,
        slotBinding(vault, published),
      );
      try {
        if (!constantTimeEqual(rootKey, verifiedRoot)) {
          throw new VaultLifecycleError('confirmation-failed');
        }
      } finally {
        zeroize(verifiedRoot);
      }
    }

    const profile = vaultProfileSchema.parse({
      version: 1,
      serverUrl,
      vaultId: receipt.vaultId,
      deviceId: receipt.deviceId,
      deviceLocator,
      sessionLocator,
    });
    await persistProfile(options.environment, profile);

    const local = await options.environment.openSyncStore(profile);
    const sync = (
      options.syncEngineFactory ?? ((configuration) => new SyncEngine(configuration))
    )({
      transport: new FetchSyncTransport({
        baseUrl: serverUrl,
        bearerToken: bearer,
        ...(options.allowInsecureLoopbackDevelopment === true
          ? { allowInsecureLoopbackDevelopment: true }
          : {}),
      }),
      local,
      protectedState: options.backend.protectedSyncState,
      status: { set: () => Promise.resolve() },
      clock: productionClock(),
      idempotencyKeys: randomIdempotencyKeys(),
    });
    await sync.synchronize({
      vaultId: receipt.vaultId,
      deviceId: receipt.deviceId,
    });

    return {
      operationId: receipt.operationId,
      vaultId: receipt.vaultId,
      deviceId: receipt.deviceId,
    };
  } finally {
    zeroize(rootKey);
    zeroize(deviceKey);
    zeroize(deviceSecret ?? undefined);
    zeroize(sessionSecret ?? undefined);
  }
}

async function acquireRecoverySources(
  request: ProductionRecoveryRequest,
  secrets: SecretInputPort,
  dependencies: ProductionRecoveryDependencies,
): Promise<Readonly<{ inviteToken?: string; portableKey?: string }>> {
  if (request.operationId !== undefined) {
    if (request.keyFilePath !== undefined) {
      return {
        portableKey: await readPortableKeyFileSource(request, secrets, dependencies),
      };
    }
    if (request.portableKeyFromStdin === true) {
      return {
        portableKey: await secrets.read({ kind: 'portable-key', fromStdin: true }),
      };
    }
    return {};
  }

  if (
    request.inviteFromStdin === true &&
    request.keyFilePath !== undefined &&
    request.keyFilePassphraseFromStdin === true
  ) {
    const frames = await secrets.readBatch({
      kinds: ['invite', 'passphrase'],
      fromStdin: true,
      requireEnd: true,
    });
    return {
      inviteToken: requiredSourceFrame(frames, 0),
      portableKey: await readPortableKeyFileSource(
        request,
        secrets,
        dependencies,
        requiredSourceFrame(frames, 1),
      ),
    };
  }

  if (
    request.inviteFromStdin === true &&
    request.keyFilePath === undefined &&
    request.portableKeyFromStdin === true
  ) {
    const frames = await secrets.readBatch({
      kinds: ['invite', 'portable-key'],
      fromStdin: true,
      requireEnd: true,
    });
    return {
      inviteToken: requiredSourceFrame(frames, 0),
      portableKey: requiredSourceFrame(frames, 1),
    };
  }

  const inviteToken = await secrets.read({
    kind: 'invite',
    fromStdin: request.inviteFromStdin === true,
  });
  return {
    inviteToken,
    portableKey:
      request.keyFilePath === undefined
        ? await secrets.read({
            kind: 'portable-key',
            fromStdin: request.portableKeyFromStdin === true,
          })
        : await readPortableKeyFileSource(request, secrets, dependencies),
  };
}

async function readPortableKeyFileSource(
  request: ProductionRecoveryRequest,
  secrets: SecretInputPort,
  dependencies: ProductionRecoveryDependencies,
  stagedPassphrase?: string,
): Promise<string> {
  const path = request.keyFilePath;
  if (path === undefined) throw new CliUsageError('A portable key file is required.');
  const readerSecrets: SecretInputPort =
    stagedPassphrase === undefined
      ? secrets
      : {
          read: async ({ kind, fromStdin }) => {
            if (kind !== 'passphrase' || !fromStdin) {
              throw new CliUsageError('Secret input used invalid framing.');
            }
            return acquiredSecretSchema.parse(stagedPassphrase);
          },
          readBatch: () =>
            Promise.reject(new CliUsageError('Secret input used invalid framing.')),
        };
  const reader = dependencies.keyFileReaderFactory({
    secrets: readerSecrets,
    passphraseFromStdin: request.keyFilePassphraseFromStdin === true,
  });
  return String(await reader.readFormattedPortableKey(path));
}

async function persistProfile(
  environment: RecoveryEnvironment,
  profile: VaultProfile,
): Promise<void> {
  try {
    await environment.profiles.store(structuredClone(profile));
    const loaded = await environment.profiles.load(profile.vaultId, profile.deviceId);
    const parsed = vaultProfileSchema.parse(loaded);
    if (canonicalJson(parsed) !== canonicalJson(profile)) {
      throw new VaultLifecycleError('profile');
    }
  } catch (error) {
    if (error instanceof VaultLifecycleError) throw error;
    throw new VaultLifecycleError('profile');
  }
}

async function unlockPortableSlot(
  vault: VaultRecord,
  formattedPortableKey: string,
): Promise<VaultRootKey> {
  const candidates = vault.keySlots.filter(
    (
      slot,
    ): slot is Extract<VaultRecord['keySlots'][number], { type: 'portable-key' }> =>
      slot.type === 'portable-key' &&
      slot.state === 'active' &&
      slot.keyVersion === vault.currentKeyVersion,
  );
  if (candidates.length === 0) throw new VaultLifecycleError('confirmation-failed');
  for (const slot of candidates) {
    try {
      return await unlockPortableKeySlot(
        slot,
        formattedPortableKey,
        slotBinding(vault, slot),
      );
    } catch (error) {
      if (
        !(error instanceof AuthenticationError) &&
        !(error instanceof CryptoInputError)
      ) {
        throw new VaultLifecycleError('confirmation-failed');
      }
    }
  }
  throw new VaultLifecycleError('confirmation-failed');
}

function assertRecoveryScopes(
  session: Pick<ApiSessionResponse, 'vaultId' | 'deviceId' | 'scopes'>,
): void {
  if (!REQUIRED_RECOVERY_SCOPES.every((scope) => session.scopes.includes(scope))) {
    throw new VaultLifecycleError('confirmation-failed');
  }
}

function parseRecoveryVault(value: unknown, expectedVaultId: VaultId): VaultRecord {
  const vault = vaultRecordSchema.parse(value);
  if (vault.id !== expectedVaultId) throw new VaultLifecycleError('protocol');
  return vault;
}

function validateRecoveryIdentity(
  request: CliRecoverRequest,
  allowInsecureLoopbackDevelopment: boolean,
): Readonly<{ serverUrl: string; vaultId: VaultId }> {
  const validationSlotId = keySlotIdSchema.parse('slot.recovery.validation');
  let profile: VaultProfile;
  try {
    profile = vaultProfileSchema.parse({
      version: 1,
      serverUrl: request.serverUrl,
      vaultId: vaultIdSchema.parse(request.vaultId),
      deviceId: deviceIdSchema.parse('device.recovery.validation'),
      deviceLocator: {
        version: 1,
        vaultId: vaultIdSchema.parse(request.vaultId),
        deviceId: deviceIdSchema.parse('device.recovery.validation'),
        keySlotId: validationSlotId,
      },
      sessionLocator: {
        version: 1,
        vaultId: vaultIdSchema.parse(request.vaultId),
        deviceId: deviceIdSchema.parse('device.recovery.validation'),
        purpose: 'api-session',
      },
    });
  } catch {
    throw new CliUsageError('The recovery request is invalid.');
  }
  if (isInsecureLoopbackProfile(profile) && !allowInsecureLoopbackDevelopment) {
    throw new CliUsageError('The server URL is invalid.');
  }
  return { serverUrl: profile.serverUrl, vaultId: profile.vaultId };
}

function recoveryDeviceSlotId(operationId: LifecycleOperationId): KeySlotId {
  const digest = createHash('sha256').update(operationId, 'utf8').digest('hex');
  return keySlotIdSchema.parse(`recover.${digest}`);
}

function recoverySlotIdempotencyKey(operationId: LifecycleOperationId): string {
  const digest = createHash('sha256').update(operationId, 'utf8').digest('hex');
  return `recover-slot-${digest}`;
}

function recoveryTimestamp(current: string): ReturnType<typeof timestampSchema.parse> {
  const now = productionClock().now().getTime();
  const currentMillis = Date.parse(current);
  if (!Number.isFinite(now) || !Number.isFinite(currentMillis)) {
    throw new VaultLifecycleError('protocol');
  }
  return timestampSchema.parse(new Date(Math.max(now, currentMillis)).toISOString());
}

function requiredSourceFrame(values: readonly string[], index: number): string {
  const value = values[index];
  if (value === undefined)
    throw new CliUsageError('Secret input used invalid framing.');
  return value;
}

function mapRecoveryError(error: unknown): Error {
  if (error instanceof CliUsageError || error instanceof VaultLifecycleError) {
    return error;
  }
  if (error instanceof ControlPlaneFailure) {
    return new VaultLifecycleError('protocol');
  }
  return new VaultLifecycleError('protocol');
}
