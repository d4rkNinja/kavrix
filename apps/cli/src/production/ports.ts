import {
  VaultClientSession,
  type ControlPlaneClient,
  type CredentialCopyOptions,
  type CredentialCopyReceipt,
  type VaultProfile,
} from '@kavrix/client';
import type { SyncStatus } from '@kavrix/sync';
import type {
  ApiBearerToken,
  InviteId,
  PublicInviteRecord,
  VaultId,
} from '@kavrix/schemas';

import type {
  CliInviteJoinRequest,
  CliInviteJoinResult,
  CliShowResult,
  CliStatus,
  CliUseCasePorts,
} from '../contracts.js';
import { CliUsageError } from '../errors.js';
import type { ProductionEnvironment } from './environment.js';
import type { SecretBackend } from './secret-backend.js';
import { productionClock, randomIdempotencyKeys } from './runtime-adapters.js';

/** Seconds a copied secret stays on the clipboard before it is cleared. */
const CLIPBOARD_CLEAR_MS = 30_000;

export interface ProductionPortsOptions {
  readonly profile: VaultProfile;
  readonly environment: ProductionEnvironment;
  readonly secrets: SecretBackend;
  /** Completes an invite redemption; see `join.ts`. */
  readonly join: (
    request: CliInviteJoinRequest,
    portableKey: string,
    serverUrl?: string,
  ) => Promise<CliInviteJoinResult>;
  readonly allowInsecureLoopbackDevelopment?: boolean;
}

/**
 * Production `CliUseCasePorts`.
 *
 * Each `creds` invocation is a fresh process with no daemon, so the vault is
 * always locked at start. `show` and `copy` therefore unlock, act, and lock
 * again within the single command; `status` reports the honest per-process
 * state rather than pretending a background session exists.
 */
export function createProductionPorts(
  options: ProductionPortsOptions,
): CliUseCasePorts {
  const lastSyncStatus = { value: 'offline' as SyncStatus['state'] };

  const openSession = async (): Promise<VaultClientSession> => {
    const store = await options.environment.openSyncStore(options.profile);
    return new VaultClientSession({
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
    });
  };

  /** Unlocks with the remembered device key, runs, then always relocks. */
  const withUnlocked = async <Output>(
    operation: (session: VaultClientSession) => Promise<Output>,
  ): Promise<Output> => {
    const session = await openSession();
    try {
      await session.unlockRememberedDevice();
      return await operation(session);
    } finally {
      await session.lock().catch(() => undefined);
    }
  };

  return {
    status: async () => {
      const { vaultId, deviceId } = options.profile;
      const store = await options.environment.openSyncStore(options.profile);
      const pending = await store.listPendingMutations(vaultId);
      const protectedState = await options.secrets.protectedSyncState
        .load(vaultId, deviceId)
        .catch(() => null);
      const status: CliStatus = {
        // No daemon holds keys between invocations, so a fresh process is locked.
        vaultState: 'locked',
        vaultId,
        deviceId,
        syncState: mapSyncState(lastSyncStatus.value),
        pendingChanges: pending.length,
        ...(protectedState === null ? {} : { lastSyncAt: protectedState.updatedAt }),
      };
      return status;
    },

    lock: async () => {
      // Keys never outlive the process; clearing the clipboard is the only
      // cross-process state a lock can still reach.
      await options.environment.clipboard.lock();
    },

    show: (groupQuery, credentialQuery): Promise<CliShowResult> =>
      withUnlocked((session) => session.show(groupQuery, credentialQuery)),

    copy: (
      groupQuery,
      credentialQuery,
      fieldQuery,
      copyOptions?: CredentialCopyOptions,
    ): Promise<CredentialCopyReceipt> =>
      withUnlocked((session) =>
        session.copy(groupQuery, credentialQuery, fieldQuery, copyOptions ?? {}),
      ),

    listInvites: (vaultId: VaultId): Promise<readonly PublicInviteRecord[]> =>
      withRemoteVault(options, vaultId, (client, bearer) =>
        client.listInvites(bearer, vaultId),
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
