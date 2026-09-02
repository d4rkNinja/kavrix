import { createHash } from 'node:crypto';
import { lstat, realpath } from 'node:fs/promises';
import { homedir } from 'node:os';
import { basename, dirname, isAbsolute, join, resolve } from 'node:path';

import { zeroize } from '@kavrix/crypto';
import {
  databaseRevisionAnchorPath,
  readDatabaseRecoveryKitFileBinding,
} from '@kavrix/key-files';
import {
  profileIdSchema,
  type DatabaseId,
  type ProfileId,
  type VaultId,
} from '@kavrix/schemas';
import { FileEncryptedDatabaseStore } from '@kavrix/storage';

import { LocalCliError } from './cli-error.js';
import { DatabaseSession, DatabaseSessionError } from './database-session.js';
import {
  DatastoreProfileError,
  DatastoreProfileRegistry,
  resolveProfilePath,
  type DatastoreProfileRegistryOptions,
} from './datastore-profiles.js';

export type GuidedLocalOnboardingDestinations = Readonly<{
  profileId: string;
  dataFile: string;
  keyFile: string;
  recoveryFile: string;
  registryOptions?: DatastoreProfileRegistryOptions;
  reservedPaths?: readonly string[];
}>;

export type GuidedLocalOnboardingRequest = GuidedLocalOnboardingDestinations &
  Readonly<{
    databaseLabel: string;
    ownerPassphrase: Uint8Array;
    vaultLabel: string;
    recoveryPassphrase: Uint8Array;
  }>;

export type GuidedLocalOnboardingReceipt = Readonly<{
  profileId: ProfileId;
  databaseId: DatabaseId;
  vaultId: VaultId;
  dataFile: string;
  keyFile: string;
  recoveryFile: string;
  recoveryReady: true;
}>;

export type GuidedLocalOnboardingPhase =
  | 'profile-added'
  | 'database-initialized'
  | 'vault-created'
  | 'default-vault-selected'
  | 'recovery-created'
  | 'recovery-verified'
  | 'profile-selected';

export class GuidedLocalOnboardingError extends LocalCliError {
  public constructor(
    public readonly phase: GuidedLocalOnboardingPhase,
    public readonly profileId: ProfileId,
    cause?: unknown,
  ) {
    super(partialSetupMessage(phase, profileId));
    this.name = 'GuidedLocalOnboardingError';
    if (cause !== undefined) {
      Object.defineProperty(this, 'cause', {
        configurable: true,
        enumerable: false,
        value: cause instanceof Error ? cause : new Error('Onboarding failed.'),
        writable: false,
      });
    }
  }
}

/**
 * Validates every visible destination before the CLI asks for protected input.
 * Execution repeats the checks immediately before mutation to close the
 * interactive time-of-check gap.
 */
export async function preflightGuidedLocalOnboarding(
  destinations: GuidedLocalOnboardingDestinations,
): Promise<void> {
  const parsed = parseDestinations(destinations);
  const registry = await DatastoreProfileRegistry.open(parsed.registryOptions ?? {});
  await validatePreflight(parsed, registry);
}

/**
 * Creates one local encrypted database, one default vault, and one verified
 * recovery kit. The profile is selected only after every authenticated step
 * succeeds.
 */
export async function executeGuidedLocalOnboarding(
  request: GuidedLocalOnboardingRequest,
): Promise<GuidedLocalOnboardingReceipt> {
  const parsed = parseDestinations(request);
  const registry = await DatastoreProfileRegistry.open(parsed.registryOptions ?? {});
  let ownerPassphrase: Uint8Array | undefined;
  let recoveryPassphrase: Uint8Array | undefined;
  let store: FileEncryptedDatabaseStore | undefined;
  let session: DatabaseSession | undefined;
  let profileAdded = false;
  let phase: GuidedLocalOnboardingPhase = 'profile-added';
  let receipt: GuidedLocalOnboardingReceipt | undefined;
  let failure: Error | undefined;

  try {
    ownerPassphrase = Uint8Array.from(request.ownerPassphrase);
    recoveryPassphrase = Uint8Array.from(request.recoveryPassphrase);
    await validatePreflight(parsed, registry);
    const unboundProfile = {
      id: parsed.profileId,
      datastore: 'file' as const,
      dataFile: parsed.dataFile,
      keyFile: parsed.keyFile,
    };
    const profilePublication = await registry.addForInitialization(unboundProfile);
    if (profilePublication.status !== 'published') {
      throw new GuidedLocalOnboardingError(
        phase,
        parsed.profileId,
        profilePublication.error,
      );
    }
    profileAdded = true;
    await validateArtifactDestinations(parsed);

    store = await FileEncryptedDatabaseStore.open(parsed.dataFile);
    const initialized = await DatabaseSession.initialize({
      store,
      keyFile: parsed.keyFile,
      passphrase: ownerPassphrase,
      label: request.databaseLabel,
      rollbackDatabase: (databaseId) =>
        store?.rollbackOwnedInitialization(databaseId) ??
        Promise.reject(new DatabaseSessionError('operation')),
      publishBinding: (databaseId) =>
        registry.bindDatabaseIdForInitialization(
          parsed.profileId,
          databaseId,
          unboundProfile,
        ),
    });
    phase = 'database-initialized';

    session = await DatabaseSession.open({
      store,
      keyFile: parsed.keyFile,
      passphrase: ownerPassphrase,
      expectedDatabaseId: initialized.databaseId,
    });
    const vault = await session.createVault(request.vaultLabel);
    phase = 'vault-created';

    await registry.setDefaultVaultId(
      parsed.profileId,
      vault.id,
      initialized.databaseId,
      { ...unboundProfile, databaseId: initialized.databaseId },
    );
    phase = 'default-vault-selected';

    const recovery = await session.createRecovery({
      recoveryFile: parsed.recoveryFile,
      passphrase: recoveryPassphrase,
    });
    phase = 'recovery-created';
    const expectedBinding = await readDatabaseRecoveryKitFileBinding(
      parsed.recoveryFile,
    );
    const verifiedSlotId = await session.verifyRecovery({
      recoveryFile: parsed.recoveryFile,
      passphrase: recoveryPassphrase,
      expectedBinding,
    });
    if (verifiedSlotId !== recovery.slotId || session.recoveryStatus().active < 1) {
      throw new DatabaseSessionError('authentication');
    }
    phase = 'recovery-verified';

    await registry.useExpected({
      id: parsed.profileId,
      datastore: 'file',
      dataFile: parsed.dataFile,
      keyFile: parsed.keyFile,
      databaseId: initialized.databaseId,
      defaultVaultId: vault.id,
    });
    phase = 'profile-selected';
    receipt = {
      profileId: parsed.profileId,
      databaseId: initialized.databaseId,
      vaultId: vault.id,
      dataFile: parsed.dataFile,
      keyFile: parsed.keyFile,
      recoveryFile: parsed.recoveryFile,
      recoveryReady: true,
    };
  } catch (error) {
    failure = profileAdded
      ? new GuidedLocalOnboardingError(phase, parsed.profileId, error)
      : error instanceof Error
        ? error
        : new DatabaseSessionError('operation');
  } finally {
    const closeErrors: unknown[] = [];
    if (session !== undefined) {
      await session.close().catch((error: unknown) => closeErrors.push(error));
    }
    if (store !== undefined) {
      await store.close().catch((error: unknown) => closeErrors.push(error));
    }
    zeroize(ownerPassphrase);
    zeroize(recoveryPassphrase);
    if (closeErrors.length > 0) {
      failure = new GuidedLocalOnboardingError(
        phase,
        parsed.profileId,
        new AggregateError(closeErrors, 'Protected onboarding cleanup failed.'),
      );
    }
  }

  if (failure !== undefined) throw failure;
  if (receipt === undefined) {
    throw new GuidedLocalOnboardingError(phase, parsed.profileId);
  }
  return receipt;
}

async function validatePreflight(
  destinations: ParsedDestinations,
  registry: DatastoreProfileRegistry,
): Promise<void> {
  await assertDistinctDestinations(destinations);
  if (
    (await registry.list()).some((profile) => profile.id === destinations.profileId)
  ) {
    throw new DatastoreProfileError('PROFILE_DUPLICATE');
  }
  await validateArtifactDestinations(destinations);
}

type ParsedDestinations = Readonly<{
  profileId: ProfileId;
  dataFile: string;
  keyFile: string;
  recoveryFile: string;
  registryOptions?: DatastoreProfileRegistryOptions;
  reservedPaths: readonly string[];
}>;

function parseDestinations(
  input: GuidedLocalOnboardingDestinations,
): ParsedDestinations {
  let profileId: ProfileId;
  try {
    profileId = profileIdSchema.parse(input.profileId);
  } catch {
    throw new DatastoreProfileError('PROFILE_INVALID');
  }
  if (
    typeof input.dataFile !== 'string' ||
    input.dataFile.length === 0 ||
    typeof input.keyFile !== 'string' ||
    input.keyFile.length === 0 ||
    typeof input.recoveryFile !== 'string' ||
    input.recoveryFile.length === 0
  ) {
    throw new DatabaseSessionError('invalid');
  }
  return {
    profileId,
    dataFile: input.dataFile,
    keyFile: input.keyFile,
    recoveryFile: input.recoveryFile,
    reservedPaths: input.reservedPaths ?? [],
    ...(input.registryOptions === undefined
      ? {}
      : { registryOptions: input.registryOptions }),
  };
}

async function validateArtifactDestinations(
  destinations: ParsedDestinations,
): Promise<void> {
  await DatabaseSession.validateInitializationDestinations(destinations.keyFile);
  await DatabaseSession.validateRecoveryDestinations(destinations.recoveryFile);
  await FileEncryptedDatabaseStore.validatePath(destinations.dataFile);
  await requireVacantDataFile(destinations.dataFile);
}

async function assertDistinctDestinations(
  destinations: ParsedDestinations,
): Promise<void> {
  const registryDirectory =
    destinations.registryOptions?.configDirectory ??
    join(homedir(), '.config', 'kavrix');
  const registryPath = resolveProfilePath(
    registryDirectory,
    destinations.registryOptions?.fileName,
  );
  const dataTarget = await canonicalCollisionTarget(destinations.dataFile);
  const protectedTargets = await Promise.all(
    [
      destinations.keyFile,
      databaseRevisionAnchorPath(destinations.keyFile),
      destinations.recoveryFile,
      databaseRevisionAnchorPath(destinations.recoveryFile),
      registryPath,
      ...destinations.reservedPaths,
    ].map(canonicalCollisionTarget),
  );
  const candidates = [
    dataTarget,
    dataTarget + '.lock',
    ...protectedTargets.flatMap((target) => [target, secureFileLockPath(target)]),
  ];
  const unique = new Set(candidates.map(canonicalCollisionPath));
  if (unique.size !== candidates.length) {
    throw new DatabaseSessionError('invalid');
  }
}

async function canonicalCollisionTarget(path: string): Promise<string> {
  const absolute = isAbsolute(path) ? path : resolve(path);
  return join(await realpath(dirname(absolute)), basename(absolute));
}

function secureFileLockPath(targetPath: string): string {
  const digest = createHash('sha256').update(targetPath, 'utf8').digest('hex');
  return join(dirname(targetPath), '.kavrix-' + digest + '.lock');
}

function canonicalCollisionPath(path: string): string {
  // Reject case-only destination aliases on every platform. This is
  // intentionally conservative on case-sensitive volumes so a setup prepared
  // on one filesystem cannot become colliding when moved to another.
  return path.toLocaleLowerCase('en-US');
}

function partialSetupMessage(
  phase: GuidedLocalOnboardingPhase,
  profileId: ProfileId,
): string {
  const prefix =
    'Guided setup did not reach a verified completion report. Protected state for profile ' +
    profileId +
    ' was retained or its publication may be uncertain. ';
  if (phase === 'profile-added') {
    return (
      prefix +
      'Inspect `kavrix db profile list` before resuming initialization for this profile.'
    );
  }
  if (phase === 'recovery-created') {
    return (
      prefix +
      'Verify the recovery kit with `kavrix db recovery verify --profile ' +
      profileId +
      ' --recovery-file <path>` before selecting the profile.'
    );
  }
  if (phase === 'recovery-verified') {
    return (
      prefix +
      'Final selection may have completed; check `kavrix db profile status` and authenticated database health before changing profile selection.'
    );
  }
  if (phase === 'profile-selected') {
    return (
      prefix +
      'Selection may have completed; authenticate with `kavrix db status --profile ' +
      profileId +
      '` and recheck recovery status.'
    );
  }
  return (
    prefix +
    'Inspect authenticated health with `kavrix db doctor health --profile ' +
    profileId +
    '`, then resume vault or recovery setup explicitly.'
  );
}

async function requireVacantDataFile(path: string): Promise<void> {
  try {
    await lstat(resolve(path));
  } catch (error) {
    if (errorCode(error) === 'ENOENT') return;
    throw new DatabaseSessionError('invalid');
  }
  throw new DatabaseSessionError('invalid');
}

function errorCode(error: unknown): string | undefined {
  return typeof error === 'object' &&
    error !== null &&
    'code' in error &&
    typeof (error as { code?: unknown }).code === 'string'
    ? (error as { code: string }).code
    : undefined;
}
