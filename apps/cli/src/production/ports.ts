import {
  VaultClientSession,
  type ControlPlaneClient,
  type CredentialCopyReceipt,
  type VaultProfile,
} from '@kavrix/client';
import type {
  ProtectedSyncStatePort,
  ResolveSyncConflictResult,
  SyncConflictMetadata,
  SyncStatus,
} from '@kavrix/sync';
import type {
  ApiBearerToken,
  ControlListPageOptions,
  InviteId,
  InviteIssueRequest,
  InviteIssueResponse,
  InviteListPageResponse,
  VaultId,
} from '@kavrix/schemas';

import type { KeySlotId } from '@kavrix/schemas';

import type {
  CliInviteJoinRequest,
  CliInviteJoinResult,
  CliShowResult,
  CliStatus,
  CliUseCasePorts,
} from '../contracts.js';
import { CliUnavailableError, CliUsageError } from '../errors.js';
import type { SecretInputPort } from '../secret-input.js';
import type { ProductionEnvironment } from './environment.js';
import type { SecretBackend } from './secret-backend.js';
import { productionClock, randomIdempotencyKeys } from './runtime-adapters.js';
import type { UnlockMethod } from './unlock.js';

/** Seconds a copied secret stays on the clipboard before it is cleared. */
const CLIPBOARD_CLEAR_MS = 30_000;

export interface ProductionPortsOptions {
  readonly profile: VaultProfile;
  readonly environment: ProductionEnvironment;
  readonly secrets: SecretBackend;
  readonly secretsInput?: SecretInputPort;
  readonly unlockMethod?: UnlockMethod;
  /** Completes an invite redemption; see `join.ts`. */
  readonly join: (
    request: CliInviteJoinRequest,
    portableKey: string,
    serverUrl?: string,
  ) => Promise<CliInviteJoinResult>;
  readonly allowInsecureLoopbackDevelopment?: boolean;
  readonly sessionFactory?: (
    options: ConstructorParameters<typeof VaultClientSession>[0],
  ) => ProductionVaultSession;
}

export interface ProductionVaultSession {
  unlockRememberedDevice(): Promise<void>;
  unlockPassphrase?(passphrase: Uint8Array, slotId: KeySlotId): Promise<void>;
  unlockPortable?(formattedPortableKey: string, slotId?: KeySlotId): Promise<void>;
  unlockRecovery?(formattedRecoveryKey: string, slotId?: KeySlotId): Promise<void>;
  synchronize(): Promise<unknown>;
  listConflicts?(): Promise<readonly SyncConflictMetadata[]>;
  resolveConflict?(
    input: Readonly<{
      conflictId: string;
      currentRevision: number;
      strategy: 'keep-local' | 'accept-remote';
    }>,
  ): Promise<ResolveSyncConflictResult>;
  show(groupQuery: string, credentialQuery: string): Promise<CliShowResult>;
  lock(): Promise<void>;
}

export interface ProductionStatusOptions {
  readonly profile: VaultProfile;
  readonly environment: Pick<ProductionEnvironment, 'openSyncStore'>;
  readonly protectedSyncState: ProtectedSyncStatePort;
  readonly syncState?: SyncStatus['state'];
}

/** Reads only the canonical, redacted local status projection. */
export async function readProductionStatus(
  options: ProductionStatusOptions,
): Promise<CliStatus> {
  const { vaultId, deviceId } = options.profile;
  const store = await options.environment.openSyncStore(options.profile);
  const pending = await store.listPendingMutations(vaultId);
  const conflictStore = store as unknown as {
    listConflicts?: (vaultId: VaultId) => Promise<readonly SyncConflictMetadata[]>;
  };
  const conflicts =
    conflictStore.listConflicts === undefined
      ? []
      : await conflictStore.listConflicts(vaultId);
  const protectedState = await options.protectedSyncState.load(vaultId, deviceId);
  return {
    // No daemon holds keys between invocations, so a fresh process is locked.
    vaultState: 'locked',
    vaultId,
    deviceId,
    syncState: mapSyncState(
      conflicts.length > 0 ? 'conflict' : (options.syncState ?? 'offline'),
    ),
    pendingChanges: pending.length,
    ...(protectedState === null ? {} : { lastSyncAt: protectedState.updatedAt }),
  };
}

/**
 * Production `CliUseCasePorts`.
 *
 * Each `creds` invocation is a fresh process with no daemon, so the vault is
 * always locked at start. `show` therefore unlocks, synchronizes, reads, and
 * locks again within the single command. `copy` fails closed because this
 * process cannot outlive its clipboard-clear timer.
 */
export function createProductionPorts(
  options: ProductionPortsOptions,
): CliUseCasePorts {
  const lastSyncStatus = { value: 'offline' as SyncStatus['state'] };

  const openSession = async (): Promise<ProductionVaultSession> => {
    const store = await options.environment.openSyncStore(options.profile);
    const configuration: ConstructorParameters<typeof VaultClientSession>[0] = {
      profile: options.profile,
      sessions: options.secrets.sessions,
      keychain: options.secrets.keychain,
      store,
      clipboard: options.environment.clipboard,
      interaction: { clearAfterMs: CLIPBOARD_CLEAR_MS },
      sync: {
        protectedState: options.secrets.protectedSyncState,
        status: {
          set: (status) => {
            lastSyncStatus.value = status.state;
            return Promise.resolve();
          },
        },
        clock: productionClock(),
        idempotencyKeys: randomIdempotencyKeys(),
      },
      ...(options.allowInsecureLoopbackDevelopment === true
        ? { allowInsecureLoopbackDevelopment: true }
        : {}),
    };
    return options.sessionFactory === undefined
      ? new VaultClientSession(configuration)
      : options.sessionFactory(configuration);
  };

  const unlockSession = async (
    session: ProductionVaultSession,
    method: UnlockMethod,
  ): Promise<void> => {
    switch (method.kind) {
      case 'remembered-device':
        await session.unlockRememberedDevice();
        break;
      case 'portable':
        if (session.unlockPortable === undefined) {
          throw new CliUsageError('Portable unlock is unsupported by this session.');
        }
        await session.unlockPortable(method.formattedKey, method.slotId);
        break;
      case 'passphrase': {
        if (options.secretsInput === undefined) {
          throw new CliUsageError(
            'Secret input port is required for passphrase unlock.',
          );
        }
        const acquired = await options.secretsInput.read({
          kind: 'passphrase',
          fromStdin: false,
        });
        if (method.passphraseSlotId === undefined) {
          throw new CliUsageError(
            'A passphrase slot ID is required for passphrase unlock.',
          );
        }
        if (session.unlockPassphrase === undefined) {
          throw new CliUsageError('Passphrase unlock is unsupported by this session.');
        }
        const encoded = new TextEncoder().encode(acquired);
        try {
          await session.unlockPassphrase(encoded, method.passphraseSlotId);
        } finally {
          encoded.fill(0);
        }
        break;
      }
      case 'key-file': {
        const { readPortableKeyFile } = await import('@kavrix/key-files');
        const { formatPortableKey } = await import('@kavrix/crypto');
        const file = await readPortableKeyFile(method.path, { kind: 'unprotected' });
        const formattedKey = formatPortableKey(file.key);
        if (session.unlockPortable === undefined) {
          throw new CliUsageError('Portable unlock is unsupported by this session.');
        }
        await session.unlockPortable(formattedKey, method.slotId);
        break;
      }
    }
  };

  /** Unlocks with the specified unlock method, runs, then always relocks. */
  const withUnlocked = async <Output>(
    operation: (session: ProductionVaultSession) => Promise<Output>,
    synchronize = false,
  ): Promise<Output> => {
    const session = await openSession();
    let outcome:
      | Readonly<{ succeeded: true; value: Output }>
      | Readonly<{ succeeded: false; error: unknown }>;
    try {
      await unlockSession(
        session,
        options.unlockMethod ?? { kind: 'remembered-device' },
      );
      if (synchronize) await session.synchronize();
      outcome = { succeeded: true, value: await operation(session) };
    } catch (error) {
      outcome = { succeeded: false, error };
    }
    let cleanupOutcome:
      Readonly<{ succeeded: true }> | Readonly<{ succeeded: false; error: unknown }>;
    try {
      await session.lock();
      cleanupOutcome = { succeeded: true };
    } catch (error) {
      cleanupOutcome = { succeeded: false, error };
    }
    if (!cleanupOutcome.succeeded) {
      if (!outcome.succeeded) {
        throw new AggregateError(
          [outcome.error, cleanupOutcome.error],
          'The vault operation and cleanup both failed.',
          { cause: outcome.error },
        );
      }
      throw cleanupOutcome.error;
    }
    if (!outcome.succeeded) throw outcome.error;
    return outcome.value;
  };

  return {
    status: () =>
      readProductionStatus({
        profile: options.profile,
        environment: options.environment,
        protectedSyncState: options.secrets.protectedSyncState,
        syncState: lastSyncStatus.value,
      }),

    sync: async () => {
      await withUnlocked((session) => session.synchronize());
      return readProductionStatus({
        profile: options.profile,
        environment: options.environment,
        protectedSyncState: options.secrets.protectedSyncState,
        syncState: lastSyncStatus.value,
      });
    },

    listConflicts: async () =>
      withUnlocked((session) => {
        if (session.listConflicts === undefined) {
          throw new CliUnavailableError('sync conflicts list');
        }
        return session.listConflicts();
      }),

    resolveConflict: async (input) =>
      withUnlocked((session) => {
        if (session.resolveConflict === undefined) {
          throw new CliUnavailableError('sync conflicts resolve');
        }
        return session.resolveConflict(input);
      }),

    lock: async () => {
      // Keys never outlive the process; clearing the clipboard is the only
      // cross-process state a lock can still reach.
      await options.environment.clipboard.lock();
    },

    show: (groupQuery, credentialQuery): Promise<CliShowResult> =>
      withUnlocked((session) => session.show(groupQuery, credentialQuery), true),

    copy: (): Promise<CredentialCopyReceipt> =>
      Promise.reject(new CliUnavailableError('copy')),

    listInvitePage: (
      vaultId: VaultId,
      pageOptions: ControlListPageOptions,
    ): Promise<InviteListPageResponse> =>
      withRemoteVault(options, vaultId, (client, bearer) =>
        client.listInvitePage(bearer, vaultId, pageOptions),
      ),

    issueInvite: (
      vaultId: VaultId,
      request: InviteIssueRequest,
    ): Promise<InviteIssueResponse> =>
      withRemoteVault(options, vaultId, (client, bearer) =>
        client.issueInvite(bearer, vaultId, request),
      ),

    revokeInvite: (vaultId: VaultId, inviteId: InviteId): Promise<void> =>
      withRemoteVault(options, vaultId, (client, bearer) =>
        client.revokeInvite(bearer, vaultId, inviteId),
      ),

    // The catalog reads the invite token and the portable key as one masked
    // batch, so the key arrives as an argument. Reading it again here would
    // double-prompt interactively and could never succeed under
    // `--invite-stdin`, where the stream is already exhausted.
    joinInvite: (request, portableKey, serverUrl) =>
      serverUrl === undefined
        ? options.join(request, portableKey)
        : options.join(request, portableKey, serverUrl),
  };
}

/**
 * `SyncStatus` carries states the CLI contract does not model. The mapping is
 * lossy in two places and is written out rather than inferred: a completed sync
 * reads as idle, and an unresolved conflict reads as an error because it needs
 * the user's attention.
 */
function mapSyncState(state: SyncStatus['state']): CliStatus['syncState'] {
  switch (state) {
    case 'synced':
      return 'idle';
    case 'syncing':
      return 'syncing';
    case 'offline':
      return 'offline';
    case 'conflict':
    case 'error':
      return 'error';
    default:
      return 'error';
  }
}

async function withRemoteVault<Output>(
  options: ProductionPortsOptions,
  vaultId: VaultId,
  operation: (client: ControlPlaneClient, bearer: ApiBearerToken) => Promise<Output>,
): Promise<Output> {
  if (vaultId !== options.profile.vaultId) {
    throw new CliUsageError('The requested vault is not enrolled on this device.');
  }
  const { ControlPlaneClient } = await import('@kavrix/client');
  const { apiBearerTokenSchema } = await import('@kavrix/schemas');
  const secret = await options.secrets.sessions.load(options.profile.sessionLocator);
  if (secret === null) {
    throw new CliUsageError('This device has no stored session. Re-enroll the device.');
  }
  try {
    const bearer = apiBearerTokenSchema.parse(encodeBase64Url(secret));
    const client = new ControlPlaneClient({
      baseUrl: options.profile.serverUrl,
      ...(options.allowInsecureLoopbackDevelopment === true
        ? { allowInsecureLoopbackDevelopment: true }
        : {}),
    });
    return await operation(client, bearer);
  } finally {
    secret.fill(0);
  }
}

function encodeBase64Url(bytes: Uint8Array): string {
  return Buffer.from(bytes).toString('base64url');
}
