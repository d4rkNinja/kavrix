import {
  ControlPlaneClient,
  ControlPlaneFailure,
  FetchSyncTransport,
  isInsecureLoopbackProfile,
  slotBinding,
  VaultLifecycleError,
  vaultProfileSchema,
  type ControlPlaneClientOptions,
  type VaultProfile,
} from '@kavrix/client';
import {
  encodeBase64Url,
  unlockDeviceKeySlot,
  zeroize,
  type VaultRootKey,
} from '@kavrix/crypto';
import {
  apiBearerTokenSchema,
  deviceIdSchema,
  deviceUnlockSecretSchema,
  keySlotIdSchema,
  sessionCredentialSecretSchema,
  vaultIdSchema,
  vaultRecordSchema,
  type ApiBearerToken,
  type ApiSessionResponse,
  type DeviceId,
  type VaultId,
  type VaultRecord,
} from '@kavrix/schemas';
import {
  SyncEngine,
  type SyncEngineOptions,
  type SyncLocalStorePort,
} from '@kavrix/sync';

import type { CliConnectRequest, CliConnectResult } from '../contracts.js';
import { CliUsageError } from '../errors.js';
import type { SecretInputPort } from '../secret-input.js';
import {
  openProductionEnvironment,
  type ProductionEnvironment,
} from './environment.js';
import { resolveCliDataPaths } from './paths.js';
import { productionClock, randomIdempotencyKeys } from './runtime-adapters.js';
import {
  createSecretBackend,
  type SecretBackend,
  type SecretBackendPolicy,
} from './secret-backend.js';

type ConnectSession = Pick<ApiSessionResponse, 'vaultId' | 'deviceId' | 'scopes'>;

export interface ConnectControlPlane {
  getSession(
    bearerToken: ApiBearerToken,
    expectedVaultId: VaultId,
    expectedDeviceId: DeviceId,
  ): Promise<ConnectSession>;
  fetchVault(bearerToken: ApiBearerToken, vaultId: VaultId): Promise<VaultRecord>;
}

export interface ConnectSyncEngine {
  synchronize(
    input: Readonly<{ vaultId: VaultId; deviceId: DeviceId }>,
  ): Promise<unknown>;
}

export interface ExistingVaultConnectEnvironment {
  readonly profiles: {
    listProfiles: () => Promise<readonly VaultProfile[]>;
    store: (profile: VaultProfile) => Promise<void>;
  };
  openSyncStore: (profile: VaultProfile) => Promise<SyncLocalStorePort>;
}

export type ExistingVaultConnectBackend = Pick<
  SecretBackend,
  'sessions' | 'keychain' | 'protectedSyncState'
>;

export interface ExistingVaultConnectOptions {
  readonly environment: ExistingVaultConnectEnvironment;
  readonly backend: ExistingVaultConnectBackend;
  readonly request: CliConnectRequest;
  readonly allowInsecureLoopbackDevelopment?: boolean;
}

export interface ProductionConnectRequest {
  readonly environment: Readonly<Record<string, string | undefined>>;
  readonly secrets: SecretInputPort;
  readonly backendPolicy: SecretBackendPolicy;
  readonly request: CliConnectRequest;
  readonly allowInsecureLoopbackDevelopment?: boolean;
}

export interface ProductionConnectDependencies {
  readonly resolvePaths: typeof resolveCliDataPaths;
  readonly createBackend: typeof createSecretBackend;
  readonly openEnvironment: typeof openProductionEnvironment;
  readonly controlPlaneFactory: (
    options: ControlPlaneClientOptions,
  ) => ConnectControlPlane;
  readonly syncEngineFactory: (options: SyncEngineOptions) => ConnectSyncEngine;
}

const DEFAULT_DEPENDENCIES: ProductionConnectDependencies = {
  resolvePaths: resolveCliDataPaths,
  createBackend: createSecretBackend,
  openEnvironment: openProductionEnvironment,
  controlPlaneFactory: (options) => new ControlPlaneClient(options),
  syncEngineFactory: (options) => new SyncEngine(options),
};

/**
 * Connects an empty local data home to an already-enrolled server identity.
 * Only the canonical profile and opaque sync cache are persisted; no vault
 * plaintext is needed to bootstrap the local store.
 */
export async function connectExistingVault(
  options: ExistingVaultConnectOptions,
  dependencies: Pick<
    ProductionConnectDependencies,
    'controlPlaneFactory' | 'syncEngineFactory'
  > = DEFAULT_DEPENDENCIES,
): Promise<CliConnectResult> {
  const identity = validateConnectIdentity(
    options.request,
    options.allowInsecureLoopbackDevelopment === true,
  );
  const existingProfiles = await options.environment.profiles.listProfiles();
  if (existingProfiles.length > 0) {
    throw new CliUsageError('A vault profile already exists on this device.');
  }

  const sessionLocator = {
    version: 1 as const,
    vaultId: identity.vaultId,
    deviceId: identity.deviceId,
    purpose: 'api-session' as const,
  };
  let sessionSecret: Uint8Array | null = null;
  let deviceSecret: Uint8Array | null = null;
  let rootKey: VaultRootKey | undefined;
  let bearer: ApiBearerToken | undefined;
  let profile: VaultProfile | undefined;

  try {
    sessionSecret = await options.backend.sessions.load(sessionLocator);
    if (sessionSecret === null) throw new VaultLifecycleError('profile');
    const parsedSessionSecret = sessionCredentialSecretSchema.safeParse(sessionSecret);
    if (!parsedSessionSecret.success) throw new VaultLifecycleError('profile');
    bearer = apiBearerTokenSchema.parse(encodeBase64Url(parsedSessionSecret.data));

    const remoteOptions: ControlPlaneClientOptions = {
      baseUrl: identity.serverUrl,
      ...(options.allowInsecureLoopbackDevelopment === true
        ? { allowInsecureLoopbackDevelopment: true }
        : {}),
    };
    const controlPlane = dependencies.controlPlaneFactory(remoteOptions);
    const remoteSession = await controlPlane.getSession(
      bearer,
      identity.vaultId,
      identity.deviceId,
    );
    if (
      remoteSession.vaultId !== identity.vaultId ||
      remoteSession.deviceId !== identity.deviceId ||
      !remoteSession.scopes.includes('sync:read') ||
      !remoteSession.scopes.includes('sync:write')
    ) {
      throw new VaultLifecycleError('protocol');
    }

    const vault = vaultRecordSchema.parse(
      await controlPlane.fetchVault(bearer, identity.vaultId),
    );
    const deviceSlots = vault.keySlots.filter(
      (
        slot,
      ): slot is Extract<VaultRecord['keySlots'][number], { type: 'device-key' }> =>
        slot.type === 'device-key' &&
        slot.deviceId === identity.deviceId &&
        slot.state === 'active' &&
        slot.keyVersion === vault.currentKeyVersion,
    );
    if (deviceSlots.length !== 1) throw new VaultLifecycleError('protocol');
    const [deviceSlot] = deviceSlots;
    if (deviceSlot === undefined) throw new VaultLifecycleError('protocol');

    deviceSecret = await options.backend.keychain.load({
      version: 1,
      vaultId: identity.vaultId,
      deviceId: identity.deviceId,
      keySlotId: deviceSlot.id,
    });
    if (deviceSecret === null) throw new VaultLifecycleError('profile');
    const parsedDeviceSecret = deviceUnlockSecretSchema.safeParse(deviceSecret);
    if (!parsedDeviceSecret.success) throw new VaultLifecycleError('profile');
    rootKey = await unlockDeviceKeySlot(
      deviceSlot,
      parsedDeviceSecret.data,
      slotBinding(vault, deviceSlot),
    );

    profile = vaultProfileSchema.parse({
      version: 1,
      serverUrl: identity.serverUrl,
      vaultId: identity.vaultId,
      deviceId: identity.deviceId,
      deviceLocator: {
        version: 1,
        vaultId: identity.vaultId,
        deviceId: identity.deviceId,
        keySlotId: deviceSlot.id,
      },
      sessionLocator,
    });
  } catch (error) {
    if (error instanceof ControlPlaneFailure || error instanceof VaultLifecycleError) {
      throw error;
    }
    throw new VaultLifecycleError('protocol');
  } finally {
    zeroize(rootKey);
    zeroize(deviceSecret ?? undefined);
    zeroize(sessionSecret ?? undefined);
  }

  await options.environment.profiles.store(profile);

  const local = await options.environment.openSyncStore(profile);
  const transportOptions: ControlPlaneClientOptions = {
    baseUrl: profile.serverUrl,
    ...(options.allowInsecureLoopbackDevelopment === true
      ? { allowInsecureLoopbackDevelopment: true }
      : {}),
  };
  const sync = dependencies.syncEngineFactory({
    transport: new FetchSyncTransport({ ...transportOptions, bearerToken: bearer }),
    local,
    protectedState: options.backend.protectedSyncState,
    status: { set: () => Promise.resolve() },
    clock: productionClock(),
    idempotencyKeys: randomIdempotencyKeys(),
  });
  await sync.synchronize({ vaultId: profile.vaultId, deviceId: profile.deviceId });
  return { vaultId: profile.vaultId, deviceId: profile.deviceId };
}

/** Runs connect within the normal protected backend and environment lifecycle. */
export async function executeProductionConnect(
  request: ProductionConnectRequest,
  overrides: Partial<ProductionConnectDependencies> = {},
): Promise<CliConnectResult> {
  const dependencies = { ...DEFAULT_DEPENDENCIES, ...overrides };
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

  let outcome:
    | Readonly<{ succeeded: true; value: CliConnectResult }>
    | Readonly<{ succeeded: false; error: unknown }>;
  try {
    outcome = {
      succeeded: true,
      value: await connectExistingVault(
        {
          environment,
          backend,
          request: request.request,
          ...(request.allowInsecureLoopbackDevelopment === undefined
            ? {}
            : {
                allowInsecureLoopbackDevelopment:
                  request.allowInsecureLoopbackDevelopment,
              }),
        },
        dependencies,
      ),
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
        'The connect operation and cleanup both failed.',
        { cause: outcome.error },
      );
    }
    throw cleanup.error;
  }
  if (!outcome.succeeded) throw outcome.error;
  return outcome.value;
}

function validateConnectIdentity(
  request: CliConnectRequest,
  allowInsecureLoopbackDevelopment: boolean,
): Readonly<{ serverUrl: string; vaultId: VaultId; deviceId: DeviceId }> {
  const validationSlotId = keySlotIdSchema.parse('slot.connect.validation');
  let profile: VaultProfile;
  try {
    profile = vaultProfileSchema.parse({
      version: 1,
      serverUrl: request.serverUrl,
      vaultId: vaultIdSchema.parse(request.vaultId),
      deviceId: deviceIdSchema.parse(request.deviceId),
      deviceLocator: {
        version: 1,
        vaultId: vaultIdSchema.parse(request.vaultId),
        deviceId: deviceIdSchema.parse(request.deviceId),
        keySlotId: validationSlotId,
      },
      sessionLocator: {
        version: 1,
        vaultId: vaultIdSchema.parse(request.vaultId),
        deviceId: deviceIdSchema.parse(request.deviceId),
        purpose: 'api-session',
      },
    });
  } catch {
    throw new CliUsageError('The connect request is invalid.');
  }
  if (isInsecureLoopbackProfile(profile) && !allowInsecureLoopbackDevelopment) {
    throw new CliUsageError('The server URL is invalid.');
  }
  return {
    serverUrl: profile.serverUrl,
    vaultId: profile.vaultId,
    deviceId: profile.deviceId,
  };
}
