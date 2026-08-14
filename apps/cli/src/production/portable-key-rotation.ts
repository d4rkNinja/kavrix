import { TextEncoder } from 'node:util';

import { revokeKeySlot, type ClockPort, type IdGeneratorPort } from '@kavrix/core';
import {
  assertCanRevokeKeySlot,
  constantTimeEqual,
  createPortableKeySlot,
  derivePortableKek,
  formatPortableKey,
  generatePortableKey,
  parsePortableKey,
  portableKeyRotationSlotDigest,
  createPortableKeyRotationCheckpoint,
  advancePortableKeyRotationCheckpoint,
  verifyPortableKeyRotationCheckpoint,
  unlockPortableKeySlot,
  unlockDeviceKeySlot,
  unlockPassphraseKeySlot,
  unlockRecoveryKeySlot,
  unwrapRootKey,
  zeroize,
  type PortableKey,
  type VaultRootKey,
  type PortableKeyFileBinding,
  type PortableKeyRotationCheckpointExpectation,
} from '@kavrix/crypto';
import {
  ControlPlaneClient,
  ControlPlaneFailure,
  lifecycleOperationIdSchema,
  parsePortableKeyRotationJournalRecord,
  type LifecycleOperationId,
  type PortableKeyRotationJournalPort,
  type PortableKeyRotationJournalRecord,
  type VaultProfile,
  type VaultProfileStorePort,
  VaultLifecycleError,
} from '@kavrix/client';
import {
  apiBearerTokenSchema,
  type AuditEventId,
  associatedDataSchema,
  canonicalJson,
  deviceUnlockSecretSchema,
  keySlotIdSchema,
  keySlotSchema,
  sessionCredentialSecretSchema,
  timestampSchema,
  vaultRevisionSchema,
  vaultRecordSchema,
  type ApiBearerToken,
  type ApiSessionResponse,
  type KeySlot,
  type KeySlotId,
  type Timestamp,
  type VaultKeySlotUpdateRequest,
  type VaultRecord,
} from '@kavrix/schemas';
import { AuthenticationError, CryptoInputError } from '@kavrix/crypto';

import { CliUsageError } from '../errors.js';
import type { SecretInputPort } from '../secret-input.js';
import { createProductionPortableKeyFileReader } from './portable-key-files.js';
import {
  openProductionEnvironment,
  resolveActiveProfile,
  type ProductionEnvironment,
} from './environment.js';
import { resolveCliDataPaths } from './paths.js';
import type { SecretBackend, SecretBackendPolicy } from './secret-backend.js';
import { createSecretBackend } from './secret-backend.js';
import { createSlotAudit, type SlotReauthentication } from './slot-lifecycle.js';
import {
  productionClock,
  randomIdGenerator,
  randomIdempotencyKeys,
} from './runtime-adapters.js';

const PROTECTED_KEY_FILE_MIN_PASSPHRASE_BYTES = 12;

export type PortableKeyRotationReplacement =
  | Readonly<{
      kind: 'generate-file';
      path: string;
      protectWithPassphrase: boolean;
      passphraseFromStdin: boolean;
    }>
  | Readonly<{
      kind: 'import-file';
      path: string;
      passphraseFromStdin: boolean;
    }>;

export type PortableKeyRotationOperation =
  | Readonly<{
      kind: 'list';
    }>
  | Readonly<{
      kind: 'start';
      sourceSlotId?: KeySlotId;
      replacement: PortableKeyRotationReplacement;
      reauthentication: SlotReauthentication;
    }>
  | Readonly<{
      kind: 'resume';
      operationId: LifecycleOperationId;
      replacementFile: Readonly<{
        path: string;
        passphraseFromStdin: boolean;
      }>;
      reauthentication: SlotReauthentication;
    }>;

export type PortableKeyRotationResult =
  | Readonly<{
      action: 'rotated' | 'resumed';
      operationId: LifecycleOperationId;
      sourceSlotId: KeySlotId;
      replacementSlotId: KeySlotId;
      state: 'completed';
    }>
  | Readonly<{
      action: 'listed';
      operations: readonly PortableKeyRotationListing[];
    }>;

export type PortableKeyRotationListing = Readonly<{
  operationId: LifecycleOperationId;
  state: PortableKeyRotationJournalRecord['state'];
  vaultId: VaultRecord['id'];
  deviceId: VaultProfile['deviceId'];
  sourceSlotId: KeySlotId;
  replacementSlotId: KeySlotId;
  createdAt: Timestamp;
  updatedAt: Timestamp;
}>;

export type PortableKeyRotationControlPlane = Readonly<{
  getSession(
    bearerToken: ApiBearerToken,
    expectedVaultId: VaultRecord['id'],
    expectedDeviceId: VaultProfile['deviceId'],
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

export type PortableKeyRotationEnvironment = Readonly<{
  readonly profiles: VaultProfileStorePort;
  readonly rotationJournal: PortableKeyRotationJournalPort;
}>;

export type PortableKeyRotationBackend = Pick<SecretBackend, 'sessions' | 'keychain'>;

export interface PortableKeyRotationOptions {
  readonly environment: PortableKeyRotationEnvironment;
  readonly backend: PortableKeyRotationBackend;
  readonly profile: VaultProfile;
  readonly controlPlane: PortableKeyRotationControlPlane;
  readonly operation: PortableKeyRotationOperation;
  readonly secrets: SecretInputPort;
  readonly clock: ClockPort;
  readonly operationIds: IdGeneratorPort<LifecycleOperationId>;
  readonly slotIds: IdGeneratorPort<KeySlotId>;
  readonly idempotencyKeys: { next(): string };
  readonly auditIds: IdGeneratorPort<AuditEventId>;
}

export interface ProductionPortableKeyRotationRequest {
  readonly environment: Readonly<Record<string, string | undefined>>;
  readonly secrets: SecretInputPort;
  readonly backendPolicy: SecretBackendPolicy;
  readonly operation: PortableKeyRotationOperation;
  readonly allowInsecureLoopbackDevelopment?: boolean;
}

export interface ProductionPortableKeyRotationDependencies {
  readonly resolvePaths: typeof resolveCliDataPaths;
  readonly createBackend: typeof createSecretBackend;
  readonly openEnvironment: typeof openProductionEnvironment;
  readonly resolveProfile: typeof resolveActiveProfile;
  readonly controlPlaneFactory: (options: {
    readonly baseUrl: string;
    readonly allowInsecureLoopbackDevelopment?: boolean;
  }) => PortableKeyRotationControlPlane;
  readonly clock: () => ClockPort;
  readonly operationIds: () => IdGeneratorPort<LifecycleOperationId>;
  readonly slotIds: () => IdGeneratorPort<KeySlotId>;
  readonly idempotencyKeys: () => { next(): string };
  readonly auditIds: () => IdGeneratorPort<AuditEventId>;
}

const DEFAULT_DEPENDENCIES: ProductionPortableKeyRotationDependencies = {
  resolvePaths: resolveCliDataPaths,
  createBackend: createSecretBackend,
  openEnvironment: openProductionEnvironment,
  resolveProfile: resolveActiveProfile,
  controlPlaneFactory: (options) => new ControlPlaneClient(options),
  clock: productionClock,
  operationIds: randomIdGenerator,
  slotIds: randomIdGenerator,
  idempotencyKeys: randomIdempotencyKeys,
  auditIds: randomIdGenerator,
};

export async function executeProductionPortableKeyRotation(
  request: ProductionPortableKeyRotationRequest,
  overrides: Partial<ProductionPortableKeyRotationDependencies> = {},
): Promise<PortableKeyRotationResult> {
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
    | Readonly<{ succeeded: true; value: PortableKeyRotationResult }>
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
      value: await managePortableKeyRotation({
        environment,
        backend,
        profile,
        controlPlane,
        operation: request.operation,
        secrets: request.secrets,
        clock: dependencies.clock(),
        operationIds: dependencies.operationIds(),
        slotIds: dependencies.slotIds(),
        idempotencyKeys: dependencies.idempotencyKeys(),
        auditIds: dependencies.auditIds(),
      }),
    };
  } catch (error) {
    outcome = { succeeded: false, error: mapPortableKeyRotationError(error) };
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
        'The portable-key rotation and cleanup both failed.',
        { cause: outcome.error },
      );
    }
    throw cleanup.error;
  }
  if (!outcome.succeeded) throw outcome.error;
  return outcome.value;
}

export async function managePortableKeyRotation(
  options: PortableKeyRotationOptions,
): Promise<PortableKeyRotationResult> {
  if (options.operation.kind === 'list') return listRotations(options);

  let sessionSecret: Uint8Array | null = null;
  let rootKey: VaultRootKey | undefined;
  try {
    sessionSecret = await options.backend.sessions.load(options.profile.sessionLocator);
    if (sessionSecret === null) throw new VaultLifecycleError('protected-storage');
    const parsedSession = sessionCredentialSecretSchema.safeParse(sessionSecret);
    if (!parsedSession.success) throw new VaultLifecycleError('protected-storage');
    const bearer = apiBearerTokenSchema.parse(encodeBase64UrlSafe(parsedSession.data));
    const session = await options.controlPlane.getSession(
      bearer,
      options.profile.vaultId,
      options.profile.deviceId,
    );
    assertSessionBinding(session, options.profile);
    requireManageScope(session);
    rootKey = await unwrapForReauthentication(
      await fetchVault(options, bearer),
      options.profile,
      options.backend,
      options.operation.reauthentication,
    );

    if (options.operation.kind === 'start') {
      return await startRotation(options, bearer, rootKey);
    }
    return await resumeRotation(options, bearer, rootKey);
  } catch (error) {
    throw mapPortableKeyRotationError(error);
  } finally {
    zeroize(rootKey);
    zeroize(sessionSecret ?? undefined);
  }
}

async function listRotations(
  options: PortableKeyRotationOptions,
): Promise<PortableKeyRotationResult> {
  const operationIds = await options.environment.rotationJournal.listOperationIds();
  const operations: PortableKeyRotationListing[] = [];
  for (const operationId of operationIds) {
    const record = await options.environment.rotationJournal.load(operationId);
    if (record === null) throw new VaultLifecycleError('journal');
    operations.push({
      operationId: record.operationId,
      state: record.state,
      vaultId: record.vaultId,
      deviceId: record.deviceId,
      sourceSlotId: record.sourceSlot.id,
      replacementSlotId: record.replacementSlot.id,
      createdAt: record.createdAt,
      updatedAt: record.updatedAt,
    });
  }
  return { action: 'listed', operations };
}

async function startRotation(
  options: PortableKeyRotationOptions,
  bearer: ApiBearerToken,
  rootKey: VaultRootKey,
): Promise<PortableKeyRotationResult> {
  const operation = options.operation;
  if (operation.kind !== 'start') throw new VaultLifecycleError('protocol');
  const vault = await fetchVault(options, bearer);
  const sourceSlot = selectSourceSlot(vault, operation.sourceSlotId);
  const operationId = lifecycleOperationIdSchema.parse(options.operationIds.next());
  const replacementSlotId = allocateSlotId(options.slotIds, vault);
  const createdAt = timestampSchema.parse(options.clock.now().toISOString());

  let formattedReplacement: string;
  let replacementKey: PortableKey | undefined;
  try {
    if (operation.replacement.kind === 'generate-file') {
      replacementKey = generatePortableKey();
      formattedReplacement = await writeAndConfirmGeneratedKeyFile(
        options.secrets,
        operation.replacement,
        replacementKey,
        vault.id,
        replacementSlotId,
      );
    } else {
      formattedReplacement = await readReplacementFile(
        options.secrets,
        operation.replacement.path,
        { kind: 'unbound' },
        operation.replacement.passphraseFromStdin,
      );
      replacementKey = parsePortableKey(formattedReplacement);
    }

    const replacementActive = await createPortableKeySlot(
      {
        vaultId: vault.id,
        slotId: replacementSlotId,
        schemaVersion: vault.schemaVersion,
        keyVersion: vault.currentKeyVersion,
        createdAt,
      },
      replacementKey,
      rootKey,
    );
    const replacementSlot = keySlotSchema.parse({
      ...replacementActive,
      state: 'pending',
    });
    await verifyReplacementEnvelope(replacementSlot, formattedReplacement, rootKey);

    const expected = rotationExpectation(
      vault,
      operationId,
      sourceSlot,
      replacementSlot,
    );
    const checkpoint = createPortableKeyRotationCheckpoint(expected, rootKey);
    const record = parsePortableKeyRotationJournalRecord({
      version: 1,
      kind: 'portable-key-rotation',
      operationId,
      vaultId: vault.id,
      deviceId: options.profile.deviceId,
      state: 'prepared',
      sourceKind:
        operation.replacement.kind === 'generate-file'
          ? 'generated-file'
          : 'imported-file',
      sourceSlot,
      replacementSlot,
      sourceRevision: vault.revision,
      createdAt,
      updatedAt: createdAt,
      checkpoint,
    });
    await options.environment.rotationJournal.createPrepared(record);
    const completed = await driveRotation(
      options,
      bearer,
      rootKey,
      record,
      formattedReplacement,
    );
    return {
      ...completed,
      action: 'rotated',
    };
  } finally {
    zeroize(replacementKey);
  }
}

async function resumeRotation(
  options: PortableKeyRotationOptions,
  bearer: ApiBearerToken,
  rootKey: VaultRootKey,
): Promise<PortableKeyRotationResult> {
  const operation = options.operation;
  if (operation.kind !== 'resume') throw new VaultLifecycleError('protocol');
  const record = await options.environment.rotationJournal.load(operation.operationId);
  if (record?.vaultId !== options.profile.vaultId) {
    throw new CliUsageError('The rotation operation was not found.');
  }
  if (record.deviceId !== options.profile.deviceId) {
    throw new VaultLifecycleError('protocol');
  }
  const formattedReplacement = await readReplacementFile(
    options.secrets,
    operation.replacementFile.path,
    record.sourceKind === 'generated-file'
      ? {
          kind: 'bound',
          vaultId: record.vaultId,
          keySlotId: record.replacementSlot.id,
        }
      : { kind: 'unbound' },
    operation.replacementFile.passphraseFromStdin,
  );
  await verifyReplacementEnvelope(
    record.replacementSlot,
    formattedReplacement,
    rootKey,
  );
  return {
    ...(await driveRotation(options, bearer, rootKey, record, formattedReplacement)),
    action: 'resumed',
  };
}

async function driveRotation(
  options: PortableKeyRotationOptions,
  bearer: ApiBearerToken,
  rootKey: VaultRootKey,
  initialRecord: PortableKeyRotationJournalRecord,
  formattedReplacement: string,
): Promise<Exclude<PortableKeyRotationResult, { action: 'listed' }>> {
  let record = initialRecord;
  const expected = rotationExpectationFromRecord(record);
  verifyPortableKeyRotationCheckpoint(record.checkpoint, rootKey, expected);
  let vault = await fetchVault(options, bearer);
  let remoteStage = inspectRemoteStage(vault, record);
  const localStage = rotationStage(record.state);
  if (remoteStage < localStage) throw new VaultLifecycleError('protocol');

  while (remoteStage > localStageFor(record)) {
    record = await advanceJournalToStage(options, record, remoteStage, rootKey);
  }

  if (record.state === 'prepared') {
    if (remoteStage !== 0) throw new VaultLifecycleError('protocol');
    const pending = vaultRecordWithSlot(
      vault,
      record.replacementSlot,
      timestampSchema.parse(options.clock.now().toISOString()),
    );
    await publishAndConfirm(
      options,
      bearer,
      vault,
      pending,
      record.replacementSlot.id,
      options.idempotencyKeys.next(),
    );
    vault = await fetchVault(options, bearer);
    remoteStage = inspectRemoteStage(vault, record);
    if (remoteStage !== 1) throw new VaultLifecycleError('protocol');
    record = await advanceJournalToStage(options, record, 1, rootKey);
  }

  if (record.state === 'pending-published') {
    if (remoteStage !== 1) {
      remoteStage = inspectRemoteStage(vault, record);
      if (remoteStage !== 1) throw new VaultLifecycleError('protocol');
    }
    await verifyReplacementEnvelope(
      findSlot(vault, record.replacementSlot.id),
      formattedReplacement,
      rootKey,
    );
    const activeAt = timestampSchema.parse(options.clock.now().toISOString());
    const activeSlot = keySlotSchema.parse({
      ...record.replacementSlot,
      state: 'active',
    });
    const active = vaultRecordWithSlot(vault, activeSlot, activeAt);
    const audit = await createSlotAudit(
      options,
      rootKey,
      vault,
      activeSlot,
      'create',
      active.revision,
      activeAt,
    );
    await publishAndConfirm(
      options,
      bearer,
      vault,
      active,
      activeSlot.id,
      options.idempotencyKeys.next(),
      audit,
    );
    vault = await fetchVault(options, bearer);
    remoteStage = inspectRemoteStage(vault, record);
    if (remoteStage !== 2) throw new VaultLifecycleError('protocol');
    record = await advanceJournalToStage(options, record, 2, rootKey);
  }

  if (record.state === 'active-published') {
    if (remoteStage !== 2) {
      remoteStage = inspectRemoteStage(vault, record);
      if (remoteStage !== 2) throw new VaultLifecycleError('protocol');
    }
    await verifyReplacementEnvelope(
      findSlot(vault, record.replacementSlot.id),
      formattedReplacement,
      rootKey,
    );
    const source = findSlot(vault, record.sourceSlot.id);
    assertCanRevokeKeySlot(vault, source.id);
    const revokedAt = timestampSchema.parse(options.clock.now().toISOString());
    const revoked = vaultRecordSchema.parse({
      ...vault,
      keySlots: revokeKeySlot(vault.keySlots, source.id, revokedAt),
      revision: vault.revision + 1,
      updatedAt: revokedAt,
    });
    const audit = await createSlotAudit(
      options,
      rootKey,
      vault,
      source,
      'revoke',
      revoked.revision,
      revokedAt,
    );
    await revokeAndConfirm(
      options,
      bearer,
      vault,
      revoked,
      source.id,
      options.idempotencyKeys.next(),
      audit,
    );
    vault = await fetchVault(options, bearer);
    remoteStage = inspectRemoteStage(vault, record);
    if (remoteStage !== 3) throw new VaultLifecycleError('protocol');
    record = await advanceJournalToStage(options, record, 3, rootKey);
  }

  if (record.state !== 'completed' || remoteStage !== 3) {
    throw new VaultLifecycleError('protocol');
  }
  await verifyReplacementEnvelope(
    findSlot(vault, record.replacementSlot.id),
    formattedReplacement,
    rootKey,
  );
  return {
    action: 'resumed',
    operationId: record.operationId,
    sourceSlotId: record.sourceSlot.id,
    replacementSlotId: record.replacementSlot.id,
    state: 'completed',
  };
}

async function advanceJournalToStage(
  options: PortableKeyRotationOptions,
  record: PortableKeyRotationJournalRecord,
  targetStage: number,
  rootKey: VaultRootKey,
): Promise<PortableKeyRotationJournalRecord> {
  let current = record;
  const expected = rotationExpectationFromRecord(current);
  const currentStage = localStageFor(current);
  if (targetStage <= currentStage) return current;
  const nextState = stageState(currentStage + 1);
  const nextCheckpoint = advancePortableKeyRotationCheckpoint(
    current.checkpoint,
    rootKey,
    expected,
    nextState,
    vaultRevisionSchema.parse(current.sourceRevision + currentStage + 1),
  );
  const updatedAt = timestampSchema.parse(options.clock.now().toISOString());
  if (nextState === 'pending-published') {
    await options.environment.rotationJournal.markPendingPublished(
      current.operationId,
      updatedAt,
      nextCheckpoint,
    );
  } else if (nextState === 'active-published') {
    await options.environment.rotationJournal.markActivePublished(
      current.operationId,
      updatedAt,
      nextCheckpoint,
    );
  } else {
    await options.environment.rotationJournal.complete(
      current.operationId,
      updatedAt,
      nextCheckpoint,
    );
  }
  current = requiredRecord(
    await options.environment.rotationJournal.load(current.operationId),
  );
  return current;
}

function inspectRemoteStage(
  vault: VaultRecord,
  record: PortableKeyRotationJournalRecord,
): number {
  const source = vault.keySlots.find((slot) => slot.id === record.sourceSlot.id);
  const replacement = vault.keySlots.find(
    (slot) => slot.id === record.replacementSlot.id,
  );
  if (
    source === undefined ||
    portableKeyRotationSlotDigest(source) !== record.checkpoint.payload.sourceSlotDigest
  ) {
    throw new VaultLifecycleError('protocol');
  }
  if (
    replacement === undefined &&
    vault.revision === record.sourceRevision &&
    source.state === 'active'
  ) {
    return 0;
  }
  if (
    replacement !== undefined &&
    vault.revision === record.sourceRevision + 1 &&
    replacement.state === 'pending' &&
    portableKeyRotationSlotDigest(replacement) ===
      record.checkpoint.payload.replacementSlotDigest &&
    source.state === 'active'
  ) {
    return 1;
  }
  if (
    replacement !== undefined &&
    vault.revision === record.sourceRevision + 2 &&
    replacement.state === 'active' &&
    portableKeyRotationSlotDigest(replacement) ===
      record.checkpoint.payload.replacementSlotDigest &&
    source.state === 'active'
  ) {
    return 2;
  }
  if (
    replacement !== undefined &&
    vault.revision === record.sourceRevision + 3 &&
    replacement.state === 'active' &&
    portableKeyRotationSlotDigest(replacement) ===
      record.checkpoint.payload.replacementSlotDigest &&
    source.state === 'revoked'
  ) {
    return 3;
  }
  throw new VaultLifecycleError('protocol');
}

function rotationStage(state: PortableKeyRotationJournalRecord['state']): number {
  return {
    prepared: 0,
    'pending-published': 1,
    'active-published': 2,
    completed: 3,
  }[state];
}

function localStageFor(record: PortableKeyRotationJournalRecord): number {
  return rotationStage(record.state);
}

function stageState(
  stage: number,
): Exclude<PortableKeyRotationJournalRecord['state'], 'prepared'> {
  if (stage === 1) return 'pending-published';
  if (stage === 2) return 'active-published';
  if (stage === 3) return 'completed';
  throw new VaultLifecycleError('protocol');
}

function rotationExpectation(
  vault: VaultRecord,
  operationId: LifecycleOperationId,
  sourceSlot: KeySlot,
  replacementSlot: KeySlot,
): PortableKeyRotationCheckpointExpectation {
  return {
    vaultId: vault.id,
    operationId,
    sourceSlotId: sourceSlot.id,
    replacementSlotId: replacementSlot.id,
    sourceRevision: vault.revision,
    sourceSlotDigest: portableKeyRotationSlotDigest(sourceSlot),
    replacementSlotDigest: portableKeyRotationSlotDigest(replacementSlot),
  } as const;
}

function rotationExpectationFromRecord(
  record: PortableKeyRotationJournalRecord,
): PortableKeyRotationCheckpointExpectation {
  return {
    vaultId: record.vaultId,
    operationId: record.operationId,
    sourceSlotId: record.sourceSlot.id,
    replacementSlotId: record.replacementSlot.id,
    sourceRevision: record.sourceRevision,
    sourceSlotDigest: portableKeyRotationSlotDigest(record.sourceSlot),
    replacementSlotDigest: portableKeyRotationSlotDigest(record.replacementSlot),
  } as const;
}

function vaultRecordWithSlot(
  vault: VaultRecord,
  slot: KeySlot,
  updatedAt: Timestamp,
): VaultRecord {
  const existing = vault.keySlots.some((candidate) => candidate.id === slot.id);
  return vaultRecordSchema.parse({
    ...vault,
    keySlots: existing
      ? vault.keySlots.map((candidate) => (candidate.id === slot.id ? slot : candidate))
      : [...vault.keySlots, slot],
    revision: vault.revision + 1,
    updatedAt,
  });
}

async function publishAndConfirm(
  options: PortableKeyRotationOptions,
  bearer: ApiBearerToken,
  previous: VaultRecord,
  next: VaultRecord,
  slotId: KeySlotId,
  idempotencyKey: string,
  audit?: Awaited<ReturnType<typeof createSlotAudit>>,
): Promise<void> {
  let failure: unknown;
  try {
    await options.controlPlane.publishKeySlot(bearer, previous.id, slotId, {
      expectedVaultRevision: previous.revision,
      idempotencyKey,
      record: next,
      ...(audit === undefined ? {} : { audit }),
    });
  } catch (error) {
    failure = error;
  }
  const fetched = vaultRecordSchema.parse(
    await options.controlPlane.fetchVault(bearer, previous.id),
  );
  if (
    fetched.revision === next.revision &&
    canonicalJson(fetched) === canonicalJson(next)
  ) {
    return;
  }
  if (failure !== undefined) {
    throw failure instanceof Error ? failure : new VaultLifecycleError('protocol');
  }
  throw new VaultLifecycleError('protocol');
}

async function revokeAndConfirm(
  options: PortableKeyRotationOptions,
  bearer: ApiBearerToken,
  previous: VaultRecord,
  next: VaultRecord,
  slotId: KeySlotId,
  idempotencyKey: string,
  audit: Awaited<ReturnType<typeof createSlotAudit>>,
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
  if (
    fetched.revision === next.revision &&
    canonicalJson(fetched) === canonicalJson(next)
  ) {
    return;
  }
  if (failure !== undefined) {
    throw failure instanceof Error ? failure : new VaultLifecycleError('protocol');
  }
  throw new VaultLifecycleError('protocol');
}

async function verifyReplacementEnvelope(
  slot: KeySlot,
  formattedReplacement: string,
  rootKey: VaultRootKey,
): Promise<void> {
  if (slot.type !== 'portable-key') throw new VaultLifecycleError('protocol');
  let key: PortableKey | undefined;
  let kek: Uint8Array | undefined;
  let candidate: VaultRootKey | undefined;
  try {
    key = parsePortableKey(formattedReplacement);
    kek = derivePortableKek(key, slot.derivation);
    candidate = await unwrapRootKey(
      slot.wrappedRootKey,
      kek,
      associatedDataSchema.parse({
        version: 1,
        schemaVersion: slot.wrappedRootKey.aad.schemaVersion,
        keyVersion: slot.keyVersion,
        vaultId: slot.wrappedRootKey.aad.vaultId,
        entityType: 'wrapped-root-key',
        entityId: slot.id,
        purpose: 'vrk-slot',
      }),
    );
    if (!constantTimeEqual(rootKey, candidate)) {
      throw new VaultLifecycleError('confirmation-failed');
    }
  } catch (error) {
    if (error instanceof VaultLifecycleError) throw error;
    throw new VaultLifecycleError('confirmation-failed');
  } finally {
    zeroize(key);
    zeroize(kek);
    zeroize(candidate);
  }
}

async function unwrapForReauthentication(
  vault: VaultRecord,
  profile: VaultProfile,
  backend: PortableKeyRotationBackend,
  authentication: SlotReauthentication,
): Promise<VaultRootKey> {
  const slot = selectAuthenticationSlot(
    vault,
    authentication.kind,
    authentication.slotId,
  );
  try {
    switch (authentication.kind) {
      case 'device-key': {
        if (slot.type !== 'device-key' || slot.deviceId !== profile.deviceId) {
          throw new AuthenticationError();
        }
        const secret = await backend.keychain.load({
          ...profile.deviceLocator,
          keySlotId: slot.id,
        });
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
        const bytes = new TextEncoder().encode(authentication.passphrase);
        try {
          return await unlockPassphraseKeySlot(slot, bytes, binding(vault, slot));
        } finally {
          zeroize(bytes);
        }
      }
    }
  } catch (error) {
    if (error instanceof CliUsageError) throw error;
    if (error instanceof AuthenticationError || error instanceof CryptoInputError) {
      throw new VaultLifecycleError('confirmation-failed');
    }
    throw error;
  }
}

function selectAuthenticationSlot(
  vault: VaultRecord,
  kind: SlotReauthentication['kind'],
  requestedSlotId?: KeySlotId,
): KeySlot {
  const candidates = vault.keySlots.filter(
    (slot) =>
      slot.type === kind &&
      slot.state === 'active' &&
      slot.keyVersion === vault.currentKeyVersion,
  );
  if (requestedSlotId !== undefined) {
    const selected = candidates.find((candidate) => candidate.id === requestedSlotId);
    if (selected === undefined) throw new VaultLifecycleError('confirmation-failed');
    return selected;
  }
  if (candidates.length !== 1) {
    throw new CliUsageError('Reauthentication slot selection is ambiguous.');
  }
  const [selected] = candidates;
  if (selected === undefined) throw new VaultLifecycleError('confirmation-failed');
  return selected;
}

async function writeAndConfirmGeneratedKeyFile(
  secrets: SecretInputPort,
  replacement: Extract<PortableKeyRotationReplacement, { kind: 'generate-file' }>,
  key: PortableKey,
  vaultId: VaultRecord['id'],
  slotId: KeySlotId,
): Promise<string> {
  let passphrase: Uint8Array | undefined;
  try {
    if (replacement.protectWithPassphrase) {
      passphrase = await readConfirmedPassphrase(
        secrets,
        replacement.passphraseFromStdin,
      );
    } else if (replacement.passphraseFromStdin) {
      throw new CliUsageError(
        '--replacement-passphrase-stdin requires protected generated output.',
      );
    }
    const keyFiles = await import('@kavrix/key-files');
    await keyFiles.writePortableKeyFile(
      replacement.path,
      key,
      { kind: 'bound', vaultId, keySlotId: slotId },
      {
        mode: 'create',
        protection:
          passphrase === undefined
            ? { kind: 'unprotected' }
            : { kind: 'passphrase', passphrase },
      },
    );
    const parsed = await keyFiles.readPortableKeyFile(
      replacement.path,
      passphrase === undefined
        ? { kind: 'unprotected' }
        : { kind: 'passphrase', passphrase },
      { kind: 'bound', vaultId, keySlotId: slotId },
    );
    try {
      if (!constantTimeEqual(key, parsed.key)) {
        throw new VaultLifecycleError('confirmation-failed');
      }
    } finally {
      zeroize(parsed.key);
    }
    return formatPortableKey(key);
  } catch (error) {
    if (error instanceof CliUsageError || error instanceof VaultLifecycleError)
      throw error;
    throw new VaultLifecycleError('protected-storage');
  } finally {
    zeroize(passphrase);
  }
}

async function readReplacementFile(
  secrets: SecretInputPort,
  path: string,
  expectedBinding: PortableKeyFileBinding,
  passphraseFromStdin: boolean,
): Promise<string> {
  const reader = createProductionPortableKeyFileReader({
    secrets,
    passphraseFromStdin,
  });
  return String(await reader.readFormattedPortableKey(path, expectedBinding));
}

async function readConfirmedPassphrase(
  secrets: SecretInputPort,
  fromStdin: boolean,
): Promise<Uint8Array> {
  const values = await secrets.readBatch({
    kinds: ['passphrase', 'passphrase'],
    fromStdin,
    requireEnd: fromStdin,
  });
  const first = values[0];
  const second = values[1];
  if (first === undefined || second === undefined) {
    throw new CliUsageError(
      'Generated key-file passphrase confirmation is incomplete.',
    );
  }
  const firstBytes = new TextEncoder().encode(first);
  const secondBytes = new TextEncoder().encode(second);
  try {
    if (
      firstBytes.byteLength < PROTECTED_KEY_FILE_MIN_PASSPHRASE_BYTES ||
      !constantTimeEqual(firstBytes, secondBytes)
    ) {
      throw new CliUsageError(
        'Generated key-file passphrase confirmation did not match.',
      );
    }
    return firstBytes;
  } catch (error) {
    zeroize(firstBytes);
    throw error;
  } finally {
    zeroize(secondBytes);
  }
}

async function fetchVault(
  options: PortableKeyRotationOptions,
  bearer: ApiBearerToken,
): Promise<VaultRecord> {
  return vaultRecordSchema.parse(
    await options.controlPlane.fetchVault(bearer, options.profile.vaultId),
  );
}

function selectSourceSlot(
  vault: VaultRecord,
  requestedSlotId?: KeySlotId,
): Extract<KeySlot, { type: 'portable-key' }> {
  const candidates = vault.keySlots.filter(
    (slot): slot is Extract<KeySlot, { type: 'portable-key' }> =>
      slot.type === 'portable-key' &&
      slot.state === 'active' &&
      slot.keyVersion === vault.currentKeyVersion,
  );
  if (requestedSlotId !== undefined) {
    const selected = candidates.find((candidate) => candidate.id === requestedSlotId);
    if (selected === undefined)
      throw new CliUsageError('The source portable-key slot was not found.');
    return selected;
  }
  if (candidates.length !== 1) {
    throw new CliUsageError(
      'Source portable-key selection is ambiguous; specify --slot.',
    );
  }
  const [selected] = candidates;
  if (selected === undefined) throw new VaultLifecycleError('confirmation-failed');
  return selected;
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

function findSlot(vault: VaultRecord, slotId: KeySlotId): KeySlot {
  const matches = vault.keySlots.filter((slot) => slot.id === slotId);
  if (matches.length !== 1 || matches[0] === undefined) {
    throw new VaultLifecycleError('protocol');
  }
  return matches[0];
}

function requiredRecord(
  record: PortableKeyRotationJournalRecord | null,
): PortableKeyRotationJournalRecord {
  if (record === null) throw new VaultLifecycleError('journal');
  return record;
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

function encodeBase64UrlSafe(value: Uint8Array): string {
  return Buffer.from(value).toString('base64url');
}

function mapPortableKeyRotationError(error: unknown): Error {
  if (
    error instanceof VaultLifecycleError ||
    error instanceof ControlPlaneFailure ||
    error instanceof CliUsageError
  ) {
    return error;
  }
  return new VaultLifecycleError('protocol');
}
