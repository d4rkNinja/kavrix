import {
  LastUnlockSlotError,
  type ClockPort,
  type IdGeneratorPort,
} from '@kavrix/core';
import {
  AuthenticationError,
  CryptoInputError,
  LastValidSlotError,
  assertCanRevokeKeySlot,
  constantTimeEqual,
  createDeviceKeySlot,
  createPassphraseKeySlot,
  createPortableKeySlot,
  createRecoveryKeySlot,
  encryptPayload,
  encodeBase64Url,
  generateDeviceKey,
  parsePortableKey,
  parseRecoveryKey,
  unlockDeviceKeySlot,
  unlockPassphraseKeySlot,
  unlockPortableKeySlot,
  unlockRecoveryKeySlot,
  zeroize,
  type DeviceKey,
  type VaultRootKey,
} from '@kavrix/crypto';
import {
  ControlPlaneClient,
  ControlPlaneFailure,
  VaultLifecycleError,
  vaultProfileSchema,
  type VaultProfile,
  type VaultProfileStorePort,
} from '@kavrix/client';
import {
  apiBearerTokenSchema,
  associatedDataSchema,
  auditEventIdSchema,
  canonicalJson,
  deviceUnlockSecretSchema,
  keySlotIdSchema,
  sessionCredentialSecretSchema,
  timestampSchema,
  encryptedAuditRecordSchema,
  keySlotAuditPayloadSchema,
  vaultRecordSchema,
  type ApiBearerToken,
  type ApiSessionResponse,
  type AuditEventId,
  type DeviceId,
  type EncryptedAuditRecord,
  type KeychainLocator,
  type KeySlot,
  type KeySlotId,
  type VaultKeySlotUpdateRequest,
  type VaultRecord,
} from '@kavrix/schemas';
import { z } from 'zod';

import type { CliKeySlot, CliKeySlotResult } from '../contracts.js';
import { CliUsageError } from '../errors.js';
import type { SecretInputPort } from '../secret-input.js';
import {
  openProductionEnvironment,
  resolveActiveProfile,
  type ProductionEnvironment,
} from './environment.js';
import { resolveCliDataPaths } from './paths.js';
import type { SecretBackend, SecretBackendPolicy } from './secret-backend.js';
import { createSecretBackend } from './secret-backend.js';
import {
  productionClock,
  randomIdGenerator,
  randomIdempotencyKeys,
} from './runtime-adapters.js';

const slotTypeSchema = z.enum([
  'portable-key',
  'passphrase',
  'recovery-key',
  'device-key',
]);

export type KeySlotType = z.infer<typeof slotTypeSchema>;

export type SlotReauthentication =
  | Readonly<{ kind: 'device-key'; slotId?: KeySlotId }>
  | Readonly<{ kind: 'portable-key'; formattedKey: string; slotId?: KeySlotId }>
  | Readonly<{ kind: 'recovery-key'; formattedKey: string; slotId?: KeySlotId }>
  | Readonly<{ kind: 'passphrase'; passphrase: string; slotId: KeySlotId }>;

export type NewSlotCredential =
  | Readonly<{ kind: 'portable-key'; formattedKey: string }>
  | Readonly<{ kind: 'recovery-key'; formattedKey: string }>
  | Readonly<{ kind: 'passphrase'; passphrase: string }>;

export type KeySlotOperation =
  | Readonly<{ kind: 'list' }>
  | Readonly<{
      kind: 'create';
      slotType: KeySlotType;
      credential?: NewSlotCredential;
      deviceProvider?: string;
      reauthentication: SlotReauthentication;
    }>
  | Readonly<{
      kind: 'disable';
      slotId: KeySlotId;
      reauthentication: SlotReauthentication;
    }>
  | Readonly<{
      kind: 'revoke';
      slotId: KeySlotId;
      reauthentication: SlotReauthentication;
    }>;

export type SlotLifecycleControlPlane = Readonly<{
  getSession(
    bearerToken: ApiBearerToken,
    expectedVaultId: VaultRecord['id'],
    expectedDeviceId: DeviceId,
  ): Promise<Pick<ApiSessionResponse, 'vaultId' | 'deviceId' | 'scopes'>>;
  fetchVault(
    bearerToken: ApiBearerToken,
    vaultId: VaultRecord['id'],
  ): Promise<VaultRecord>;
  publishKeySlot(
    bearerToken: ApiBearerToken,
    vaultId: VaultRecord['id'],
    slotId: KeySlotId,
    request: VaultKeySlotUpdateRequest,
  ): Promise<void>;
  revokeKeySlot(
    bearerToken: ApiBearerToken,
    vaultId: VaultRecord['id'],
    slotId: KeySlotId,
    request: VaultKeySlotUpdateRequest,
  ): Promise<void>;
}>;

export type SlotLifecycleEnvironment = Readonly<{
  readonly profiles: VaultProfileStorePort;
}>;
export type SlotLifecycleBackend = Pick<SecretBackend, 'sessions' | 'keychain'>;

export interface KeySlotLifecycleOptions {
  readonly environment: SlotLifecycleEnvironment;
  readonly backend: SlotLifecycleBackend;
  readonly profile: VaultProfile;
  readonly controlPlane: SlotLifecycleControlPlane;
  readonly operation: KeySlotOperation;
  readonly clock: ClockPort;
  readonly slotIds: IdGeneratorPort<KeySlotId>;
  readonly idempotencyKeys: { next(): string };
  readonly auditIds: IdGeneratorPort<AuditEventId>;
}

export interface ProductionKeySlotLifecycleRequest {
  readonly environment: Readonly<Record<string, string | undefined>>;
  readonly secrets: SecretInputPort;
  readonly backendPolicy: SecretBackendPolicy;
  readonly operation: KeySlotOperation;
  readonly allowInsecureLoopbackDevelopment?: boolean;
}

export interface ProductionKeySlotLifecycleDependencies {
  readonly resolvePaths: typeof resolveCliDataPaths;
  readonly createBackend: typeof createSecretBackend;
  readonly openEnvironment: typeof openProductionEnvironment;
  readonly resolveProfile: typeof resolveActiveProfile;
  readonly controlPlaneFactory: (options: {
    readonly baseUrl: string;
    readonly allowInsecureLoopbackDevelopment?: boolean;
  }) => SlotLifecycleControlPlane;
  readonly clock: () => ClockPort;
  readonly slotIds: () => IdGeneratorPort<KeySlotId>;
  readonly idempotencyKeys: () => { next(): string };
  readonly auditIds: () => IdGeneratorPort<AuditEventId>;
}

const DEFAULT_DEPENDENCIES: ProductionKeySlotLifecycleDependencies = {
  resolvePaths: resolveCliDataPaths,
  createBackend: createSecretBackend,
  openEnvironment: openProductionEnvironment,
  resolveProfile: resolveActiveProfile,
  controlPlaneFactory: (options) => {
    return new ControlPlaneClient(options);
  },
  clock: productionClock,
  slotIds: randomIdGenerator,
  idempotencyKeys: randomIdempotencyKeys,
  auditIds: randomIdGenerator,
};

/**
 * Runs a slot operation against the real protected session/environment. The
 * operation object may contain transient secret strings from masked input, but
 * this function never persists or returns them.
 */
export async function executeProductionKeySlotLifecycle(
  request: ProductionKeySlotLifecycleRequest,
  overrides: Partial<ProductionKeySlotLifecycleDependencies> = {},
): Promise<readonly CliKeySlot[] | CliKeySlotResult> {
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
    | Readonly<{ succeeded: true; value: readonly CliKeySlot[] | CliKeySlotResult }>
    | Readonly<{ succeeded: false; error: unknown }>;
  try {
    const profile = await dependencies.resolveProfile(environment.profiles);
    const controlPlane = dependencies.controlPlaneFactory({
      baseUrl: profile.serverUrl,
      ...(request.allowInsecureLoopbackDevelopment === true
        ? { allowInsecureLoopbackDevelopment: true }
        : {}),
    });
    outcome = {
      succeeded: true,
      value: await manageKeySlotOperation({
        environment,
        backend,
        profile,
        controlPlane,
        operation: request.operation,
        clock: dependencies.clock(),
        slotIds: dependencies.slotIds(),
        idempotencyKeys: dependencies.idempotencyKeys(),
        auditIds: dependencies.auditIds(),
      }),
    };
  } catch (error) {
    outcome = { succeeded: false, error: mapSlotLifecycleError(error) };
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
        'The slot operation and cleanup both failed.',
        { cause: outcome.error },
      );
    }
    throw cleanup.error;
  }
  if (!outcome.succeeded) throw outcome.error;
  return outcome.value;
}

/** Executes one operation with already-open resources; useful for focused tests. */
export async function manageKeySlotOperation(
  options: KeySlotLifecycleOptions,
): Promise<readonly CliKeySlot[] | CliKeySlotResult> {
  let sessionSecret: Uint8Array | null = null;
  let rootKey: VaultRootKey | undefined;
  try {
    sessionSecret = await options.backend.sessions.load(options.profile.sessionLocator);
    if (sessionSecret === null) throw new VaultLifecycleError('protected-storage');
    const parsedSession = sessionCredentialSecretSchema.safeParse(sessionSecret);
    if (!parsedSession.success) throw new VaultLifecycleError('protected-storage');
    const bearer = apiBearerTokenSchema.parse(encodeBase64Url(parsedSession.data));
    const session = await options.controlPlane.getSession(
      bearer,
      options.profile.vaultId,
      options.profile.deviceId,
    );
    assertSessionBinding(session, options.profile);
    const vault = vaultRecordSchema.parse(
      await options.controlPlane.fetchVault(bearer, options.profile.vaultId),
    );

    if (options.operation.kind === 'list') {
      return vault.keySlots.map(projectSlot);
    }
    requireManageScope(session);
    rootKey = await unwrapForReauthentication(
      vault,
      options.profile,
      options.backend,
      options.operation.reauthentication,
    );

    switch (options.operation.kind) {
      case 'create':
        return await createSlot(options, bearer, vault, rootKey);
      case 'disable':
        return await disableSlot(options, vault, rootKey);
      case 'revoke':
        return await revokeSlot(options, bearer, vault, rootKey);
    }
    throw new VaultLifecycleError('protocol');
  } catch (error) {
    throw mapSlotLifecycleError(error);
  } finally {
    zeroize(rootKey);
    zeroize(sessionSecret ?? undefined);
  }
}

async function createSlot(
  options: KeySlotLifecycleOptions,
  bearer: ApiBearerToken,
  vault: VaultRecord,
  rootKey: VaultRootKey,
): Promise<CliKeySlotResult> {
  const operation = options.operation;
  if (operation.kind !== 'create') throw new VaultLifecycleError('protocol');
  const slotId = allocateSlotId(options.slotIds, vault);
  const createdAt = timestampSchema.parse(options.clock.now().toISOString());
  const slotType = slotTypeSchema.parse(operation.slotType);
  let deviceSecret: DeviceKey | undefined;
  let generatedDeviceLocator: KeychainLocator | undefined;
  let generatedDeviceSecretStored = false;
  let remotePublished = false;
  let slot: KeySlot;
  try {
    switch (slotType) {
      case 'portable-key':
        if (operation.credential?.kind !== 'portable-key') {
          throw new CliUsageError('A portable-key credential is required.');
        }
        {
          const portableKey = parsePortableKey(operation.credential.formattedKey);
          try {
            slot = await createPortableKeySlot(
              {
                vaultId: vault.id,
                slotId,
                schemaVersion: vault.schemaVersion,
                keyVersion: vault.currentKeyVersion,
                createdAt,
              },
              portableKey,
              rootKey,
            );
          } finally {
            zeroize(portableKey);
          }
        }
        break;
      case 'recovery-key':
        if (operation.credential?.kind !== 'recovery-key') {
          throw new CliUsageError('A recovery-key credential is required.');
        }
        {
          const recoveryKey = parseRecoveryKey(operation.credential.formattedKey);
          try {
            slot = await createRecoveryKeySlot(
              {
                vaultId: vault.id,
                slotId,
                schemaVersion: vault.schemaVersion,
                keyVersion: vault.currentKeyVersion,
                createdAt,
              },
              recoveryKey,
              rootKey,
            );
          } finally {
            zeroize(recoveryKey);
          }
        }
        break;
      case 'passphrase':
        if (operation.credential?.kind !== 'passphrase') {
          throw new CliUsageError('A passphrase credential is required.');
        }
        {
          const passphrase = new TextEncoder().encode(operation.credential.passphrase);
          try {
            slot = await createPassphraseKeySlot(
              {
                vaultId: vault.id,
                slotId,
                schemaVersion: vault.schemaVersion,
                keyVersion: vault.currentKeyVersion,
                createdAt,
              },
              passphrase,
              rootKey,
            );
          } finally {
            zeroize(passphrase);
          }
        }
        break;
      case 'device-key':
        deviceSecret = generateDeviceKey();
        slot = await createDeviceKeySlot(
          {
            vaultId: vault.id,
            slotId,
            schemaVersion: vault.schemaVersion,
            keyVersion: vault.currentKeyVersion,
            createdAt,
            deviceId: options.profile.deviceId,
            provider: operation.deviceProvider ?? 'native',
          },
          deviceSecret,
          rootKey,
        );
        break;
    }

    if (deviceSecret !== undefined) {
      const locator = {
        version: 1 as const,
        vaultId: vault.id,
        deviceId: options.profile.deviceId,
        keySlotId: slotId,
      };
      generatedDeviceLocator = locator;
      const secret = deviceUnlockSecretSchema.parse(deviceSecret);
      await options.backend.keychain.store(locator, secret);
      generatedDeviceSecretStored = true;
      const stored = await options.backend.keychain.load(locator);
      try {
        if (stored === null || !constantTimeEqual(stored, secret)) {
          throw new VaultLifecycleError('protected-storage');
        }
      } finally {
        zeroize(stored ?? undefined);
      }
    }

    const next = vaultRecordSchema.parse({
      ...vault,
      keySlots: [...vault.keySlots, slot],
      revision: vault.revision + 1,
      updatedAt: createdAt,
    });
    const idempotencyKey = options.idempotencyKeys.next();
    const audit = await createSlotAudit(
      options,
      rootKey,
      vault,
      slot,
      'create',
      next.revision,
      createdAt,
    );
    await publishAndConfirm(
      options,
      bearer,
      vault,
      next,
      slotId,
      idempotencyKey,
      audit,
    );
    remotePublished = true;
    const published = await fetchPublishedSlot(options, bearer, vault.id, slotId);
    const verifiedRoot = await unwrapCreatedSlot(
      published,
      operation.credential,
      deviceSecret,
      options.profile,
      options.backend,
    );
    try {
      if (!constantTimeEqual(rootKey, verifiedRoot)) {
        throw new VaultLifecycleError('confirmation-failed');
      }
    } finally {
      zeroize(verifiedRoot);
    }

    if (published.type === 'device-key') {
      await persistProfile(
        options.environment,
        vaultProfileSchema.parse({
          ...options.profile,
          deviceLocator: {
            ...options.profile.deviceLocator,
            keySlotId: published.id,
          },
        }),
      );
    }
    return { action: 'created', slot: projectSlot(published) };
  } catch (error) {
    if (
      generatedDeviceSecretStored &&
      !remotePublished &&
      generatedDeviceLocator !== undefined
    ) {
      try {
        await options.backend.keychain.delete(generatedDeviceLocator);
      } catch (cleanupError) {
        throw new AggregateError(
          [error, cleanupError],
          'Slot creation and protected-secret cleanup both failed.',
          { cause: cleanupError },
        );
      }
    }
    throw error;
  } finally {
    zeroize(deviceSecret);
  }
}

async function disableSlot(
  options: KeySlotLifecycleOptions,
  vault: VaultRecord,
  rootKey: VaultRootKey,
): Promise<CliKeySlotResult> {
  const operation = options.operation;
  if (operation.kind !== 'disable') throw new VaultLifecycleError('protocol');
  const target = findSlot(vault, operation.slotId);
  if (target.type !== 'device-key' || target.deviceId !== options.profile.deviceId) {
    throw new CliUsageError(
      'Only a device unlock slot on this device can be disabled locally; revoke other slot types.',
    );
  }
  const replacement =
    target.id === options.profile.deviceLocator.keySlotId
      ? await findVerifiedReplacement(options, vault, rootKey, target.id)
      : undefined;
  if (
    target.id === options.profile.deviceLocator.keySlotId &&
    replacement === undefined
  ) {
    throw new LastUnlockSlotError();
  }
  await options.backend.keychain.delete({
    ...options.profile.deviceLocator,
    keySlotId: target.id,
  });
  if (replacement !== undefined) {
    await persistProfile(
      options.environment,
      vaultProfileSchema.parse({
        ...options.profile,
        deviceLocator: {
          ...options.profile.deviceLocator,
          keySlotId: replacement.id,
        },
      }),
    );
  }
  return { action: 'disabled', slot: projectSlot(target) };
}

async function revokeSlot(
  options: KeySlotLifecycleOptions,
  bearer: ApiBearerToken,
  vault: VaultRecord,
  rootKey: VaultRootKey,
): Promise<CliKeySlotResult> {
  const operation = options.operation;
  if (operation.kind !== 'revoke') throw new VaultLifecycleError('protocol');
  const target = findSlot(vault, operation.slotId);
  if (target.state === 'active') assertCanRevokeKeySlot(vault, target.id);
  const replacement =
    target.id === options.profile.deviceLocator.keySlotId &&
    target.type === 'device-key'
      ? await findVerifiedReplacement(options, vault, rootKey, target.id)
      : undefined;
  if (
    target.id === options.profile.deviceLocator.keySlotId &&
    replacement === undefined
  ) {
    throw new LastUnlockSlotError();
  }
  if (target.state !== 'revoked') {
    const revokedAt = timestampSchema.parse(options.clock.now().toISOString());
    const { revokeKeySlot } = await import('@kavrix/core');
    const next = vaultRecordSchema.parse({
      ...vault,
      keySlots: revokeKeySlot(vault.keySlots, target.id, revokedAt),
      revision: vault.revision + 1,
      updatedAt: revokedAt,
    });
    const audit = await createSlotAudit(
      options,
      rootKey,
      vault,
      target,
      'revoke',
      next.revision,
      revokedAt,
    );
    await revokeAndConfirm(
      options,
      bearer,
      vault,
      next,
      target.id,
      options.idempotencyKeys.next(),
      audit,
    );
  }
  const current = await fetchPublishedSlot(options, bearer, vault.id, target.id);
  if (current.state !== 'revoked') throw new VaultLifecycleError('protocol');
  if (replacement !== undefined) {
    await options.backend.keychain.delete({
      ...options.profile.deviceLocator,
      keySlotId: target.id,
    });
    await persistProfile(
      options.environment,
      vaultProfileSchema.parse({
        ...options.profile,
        deviceLocator: {
          ...options.profile.deviceLocator,
          keySlotId: replacement.id,
        },
      }),
    );
  }
  return { action: 'revoked', slot: projectSlot(current) };
}

async function unwrapForReauthentication(
  vault: VaultRecord,
  profile: VaultProfile,
  backend: SlotLifecycleBackend,
  authentication: SlotReauthentication,
): Promise<VaultRootKey> {
  const expectedType = authentication.kind;
  const slot = selectSlot(vault, expectedType, authentication.slotId);
  try {
    switch (authentication.kind) {
      case 'device-key': {
        if (slot.type !== 'device-key' || slot.deviceId !== profile.deviceId) {
          throw new AuthenticationError();
        }
        const locator = {
          ...profile.deviceLocator,
          keySlotId: slot.id,
        };
        const secret = await backend.keychain.load(locator);
        if (secret === null) throw new AuthenticationError();
        try {
          const parsed = deviceUnlockSecretSchema.parse(secret);
          return await unlockDeviceKeySlot(slot, parsed, binding(vault, slot));
        } finally {
          zeroize(secret);
        }
      }
      case 'portable-key':
        if (slot.type !== 'portable-key') throw new AuthenticationError();
        return await unlockPortableKeySlot(
          slot,
          authentication.formattedKey,
          binding(vault, slot),
        );
      case 'recovery-key':
        if (slot.type !== 'recovery-key') throw new AuthenticationError();
        return await unlockRecoveryKeySlot(
          slot,
          authentication.formattedKey,
          binding(vault, slot),
        );
      case 'passphrase': {
        if (slot.type !== 'passphrase') throw new AuthenticationError();
        const passphrase = new TextEncoder().encode(authentication.passphrase);
        try {
          return await unlockPassphraseKeySlot(slot, passphrase, binding(vault, slot));
        } finally {
          zeroize(passphrase);
        }
      }
    }
  } catch (error) {
    if (error instanceof AuthenticationError || error instanceof CryptoInputError) {
      throw new VaultLifecycleError('confirmation-failed');
    }
    throw error;
  }
}

async function unwrapCreatedSlot(
  slot: KeySlot,
  credential: NewSlotCredential | undefined,
  deviceSecret: DeviceKey | undefined,
  profile: VaultProfile,
  backend: SlotLifecycleBackend,
): Promise<VaultRootKey> {
  switch (slot.type) {
    case 'portable-key':
      if (credential?.kind !== 'portable-key')
        throw new VaultLifecycleError('protocol');
      return unlockPortableKeySlot(
        slot,
        credential.formattedKey,
        bindingForProfile(slot, profile),
      );
    case 'recovery-key':
      if (credential?.kind !== 'recovery-key')
        throw new VaultLifecycleError('protocol');
      return unlockRecoveryKeySlot(
        slot,
        credential.formattedKey,
        bindingForProfile(slot, profile),
      );
    case 'passphrase': {
      if (credential?.kind !== 'passphrase') throw new VaultLifecycleError('protocol');
      const passphrase = new TextEncoder().encode(credential.passphrase);
      try {
        return await unlockPassphraseKeySlot(
          slot,
          passphrase,
          bindingForProfile(slot, profile),
        );
      } finally {
        zeroize(passphrase);
      }
    }
    case 'device-key': {
      const locator = {
        ...profile.deviceLocator,
        keySlotId: slot.id,
      };
      const secret = deviceSecret ?? (await backend.keychain.load(locator));
      if (secret === null) {
        throw new VaultLifecycleError('protected-storage');
      }
      try {
        return await unlockDeviceKeySlot(
          slot,
          secret,
          bindingForProfile(slot, profile),
        );
      } finally {
        if (secret !== deviceSecret) zeroize(secret);
      }
    }
  }
}

async function findVerifiedReplacement(
  options: KeySlotLifecycleOptions,
  vault: VaultRecord,
  rootKey: VaultRootKey,
  excluded: KeySlotId,
): Promise<Extract<KeySlot, { type: 'device-key' }> | undefined> {
  const candidates = vault.keySlots.filter(
    (slot): slot is Extract<KeySlot, { type: 'device-key' }> =>
      slot.id !== excluded &&
      slot.type === 'device-key' &&
      slot.deviceId === options.profile.deviceId &&
      slot.state === 'active' &&
      slot.keyVersion === vault.currentKeyVersion,
  );
  for (const candidate of candidates) {
    const secret = await options.backend.keychain.load({
      ...options.profile.deviceLocator,
      keySlotId: candidate.id,
    });
    if (secret === null) continue;
    try {
      const verified = await unlockDeviceKeySlot(
        candidate,
        secret,
        binding(vault, candidate),
      );
      try {
        if (constantTimeEqual(rootKey, verified)) return candidate;
      } finally {
        zeroize(verified);
      }
    } catch {
      // An unavailable or mismatched replacement is not a usable current slot.
    } finally {
      zeroize(secret);
    }
  }
  return undefined;
}

async function publishAndConfirm(
  options: KeySlotLifecycleOptions,
  bearer: ApiBearerToken,
  previous: VaultRecord,
  next: VaultRecord,
  slotId: KeySlotId,
  idempotencyKey: string,
  audit: EncryptedAuditRecord,
): Promise<void> {
  let failure: unknown;
  try {
    await options.controlPlane.publishKeySlot(bearer, previous.id, slotId, {
      expectedVaultRevision: previous.revision,
      idempotencyKey,
      record: next,
      audit,
    });
  } catch (error) {
    failure = error;
  }
  const fetched = await options.controlPlane.fetchVault(bearer, previous.id);
  const parsed = vaultRecordSchema.parse(fetched);
  const published = parsed.keySlots.find((slot) => slot.id === slotId);
  const expected = next.keySlots.find((slot) => slot.id === slotId);
  if (
    published !== undefined &&
    expected !== undefined &&
    canonicalJson(published) === canonicalJson(expected) &&
    parsed.revision === next.revision
  ) {
    return;
  }
  if (failure !== undefined) throw asLifecycleError(failure);
  throw new VaultLifecycleError('protocol');
}

async function revokeAndConfirm(
  options: KeySlotLifecycleOptions,
  bearer: ApiBearerToken,
  previous: VaultRecord,
  next: VaultRecord,
  slotId: KeySlotId,
  idempotencyKey: string,
  audit: EncryptedAuditRecord,
): Promise<void> {
  let failure: unknown;
  try {
    await options.controlPlane.revokeKeySlot(bearer, previous.id, slotId, {
      expectedVaultRevision: previous.revision,
      idempotencyKey,
      record: next,
      audit,
    });
  } catch (error) {
    failure = error;
  }
  const fetched = vaultRecordSchema.parse(
    await options.controlPlane.fetchVault(bearer, previous.id),
  );
  const revoked = fetched.keySlots.find((slot) => slot.id === slotId);
  if (revoked?.state === 'revoked' && fetched.revision >= next.revision) return;
  if (failure !== undefined) throw asLifecycleError(failure);
  throw new VaultLifecycleError('protocol');
}

export async function createSlotAudit(
  options: Pick<KeySlotLifecycleOptions, 'auditIds' | 'profile'>,
  rootKey: VaultRootKey,
  vault: VaultRecord,
  slot: KeySlot,
  action: 'create' | 'revoke',
  recordRevision: VaultRecord['revision'],
  occurredAt: VaultRecord['updatedAt'],
): Promise<EncryptedAuditRecord> {
  const auditId = auditEventIdSchema.parse(options.auditIds.next());
  const payload = keySlotAuditPayloadSchema.parse({
    version: 1,
    action,
    slotId: slot.id,
    slotType: slot.type,
    resultingState: action === 'create' ? 'active' : 'revoked',
    keyVersion: slot.keyVersion,
    actorDeviceId: options.profile.deviceId,
    occurredAt,
  });
  const plaintext = new TextEncoder().encode(canonicalJson(payload));
  try {
    const encryptedPayload = await encryptPayload(
      plaintext,
      rootKey,
      associatedDataSchema.parse({
        version: 1,
        schemaVersion: vault.schemaVersion,
        keyVersion: vault.currentKeyVersion,
        vaultId: vault.id,
        entityType: 'audit-event',
        entityId: auditId,
        purpose: 'audit-event',
      }),
    );
    return encryptedAuditRecordSchema.parse({
      id: auditId,
      vaultId: vault.id,
      schemaVersion: vault.schemaVersion,
      encryptedPayload,
      recordRevision,
      createdAt: occurredAt,
    });
  } finally {
    zeroize(plaintext);
  }
}

async function fetchPublishedSlot(
  options: KeySlotLifecycleOptions,
  bearer: ApiBearerToken,
  vaultId: VaultRecord['id'],
  slotId: KeySlotId,
): Promise<KeySlot> {
  const vault = vaultRecordSchema.parse(
    await options.controlPlane.fetchVault(bearer, vaultId),
  );
  const matches = vault.keySlots.filter((slot) => slot.id === slotId);
  if (matches.length !== 1) throw new VaultLifecycleError('protocol');
  const [slot] = matches;
  if (slot === undefined) throw new VaultLifecycleError('protocol');
  return slot;
}

function selectSlot(
  vault: VaultRecord,
  authenticationKind: SlotReauthentication['kind'],
  requestedSlotId?: KeySlotId,
): KeySlot {
  const expectedType = authenticationKind;
  const candidates = vault.keySlots.filter(
    (slot) =>
      slot.type === expectedType &&
      slot.state === 'active' &&
      slot.keyVersion === vault.currentKeyVersion,
  );
  if (requestedSlotId !== undefined) {
    const slot = candidates.find((candidate) => candidate.id === requestedSlotId);
    if (slot === undefined) throw new VaultLifecycleError('confirmation-failed');
    return slot;
  }
  if (candidates.length !== 1)
    throw new CliUsageError('Reauthentication slot selection is ambiguous.');
  const [only] = candidates;
  if (only === undefined) throw new VaultLifecycleError('confirmation-failed');
  return only;
}

function findSlot(vault: VaultRecord, slotId: KeySlotId): KeySlot {
  const parsedId = keySlotIdSchema.safeParse(slotId);
  if (!parsedId.success) throw new CliUsageError('The unlock slot ID is invalid.');
  const matches = vault.keySlots.filter((slot) => slot.id === parsedId.data);
  if (matches.length !== 1) throw new CliUsageError('The unlock slot was not found.');
  const [slot] = matches;
  if (slot === undefined) throw new CliUsageError('The unlock slot was not found.');
  return slot;
}

function allocateSlotId(
  ids: IdGeneratorPort<KeySlotId>,
  vault: VaultRecord,
): KeySlotId {
  const existing = new Set(vault.keySlots.map((slot) => slot.id));
  for (let attempt = 0; attempt < 8; attempt += 1) {
    const candidate = keySlotIdSchema.parse(ids.next());
    if (!existing.has(candidate)) return candidate;
  }
  throw new VaultLifecycleError('invalid-input');
}

function assertSessionBinding(
  session: Pick<ApiSessionResponse, 'vaultId' | 'deviceId' | 'scopes'>,
  profile: VaultProfile,
): void {
  if (session.vaultId !== profile.vaultId || session.deviceId !== profile.deviceId) {
    throw new VaultLifecycleError('protocol');
  }
}

function requireManageScope(
  session: Pick<ApiSessionResponse, 'vaultId' | 'deviceId' | 'scopes'>,
): void {
  if (!session.scopes.includes('device:manage')) {
    throw new VaultLifecycleError('protocol');
  }
}

function binding(
  vault: VaultRecord,
  slot: KeySlot,
): {
  vaultId: VaultRecord['id'];
  slotId: KeySlotId;
  schemaVersion: number;
  keyVersion: number;
} {
  return {
    vaultId: vault.id,
    slotId: slot.id,
    schemaVersion: vault.schemaVersion,
    keyVersion: slot.keyVersion,
  };
}

function bindingForProfile(
  slot: KeySlot,
  profile: VaultProfile,
): {
  vaultId: VaultRecord['id'];
  slotId: KeySlotId;
  schemaVersion: number;
  keyVersion: number;
} {
  return {
    vaultId: profile.vaultId,
    slotId: slot.id,
    schemaVersion: slot.wrappedRootKey.aad.schemaVersion,
    keyVersion: slot.keyVersion,
  };
}

function projectSlot(slot: KeySlot): CliKeySlot {
  const projection = {
    id: slot.id,
    type: slot.type,
    state: slot.state,
    keyVersion: slot.keyVersion,
    createdAt: slot.createdAt,
    ...(slot.revokedAt === undefined ? {} : { revokedAt: slot.revokedAt }),
    ...(slot.type === 'device-key' ? { deviceId: slot.deviceId } : {}),
  };
  return projection;
}

function asLifecycleError(error: unknown): Error {
  return error instanceof Error ? error : new VaultLifecycleError('protocol');
}

async function persistProfile(
  environment: SlotLifecycleEnvironment,
  profile: VaultProfile,
): Promise<void> {
  await environment.profiles.store(structuredClone(profile));
  const loaded = await environment.profiles.load(profile.vaultId, profile.deviceId);
  const parsed = vaultProfileSchema.parse(loaded);
  if (canonicalJson(parsed) !== canonicalJson(profile)) {
    throw new VaultLifecycleError('profile');
  }
}

function mapSlotLifecycleError(error: unknown): Error {
  if (
    error instanceof VaultLifecycleError ||
    error instanceof ControlPlaneFailure ||
    error instanceof CliUsageError ||
    error instanceof LastValidSlotError ||
    error instanceof LastUnlockSlotError
  ) {
    return error;
  }
  return new VaultLifecycleError('protocol');
}
