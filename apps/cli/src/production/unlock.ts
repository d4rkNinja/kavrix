import { slotBinding, type VaultProfile } from '@kavrix/client';
import { unlockDeviceKeySlot, zeroize, type VaultRootKey } from '@kavrix/crypto';
import { deviceUnlockSecretSchema } from '@kavrix/schemas';
import { keySlotIdSchema, type SessionLifetimePolicy } from '@kavrix/schemas';
import { z } from 'zod';

import type { CliUseCasePorts } from '../contracts.js';
import type { SecretInputPort } from '../secret-input.js';
import {
  runWithInvocationSession,
  type InvocationSession,
  type SessionRuntimePorts,
} from '../session.js';
import {
  openProductionCommandEnvironment,
  resolveActiveProfile,
  type ProductionCommandEnvironment,
} from './environment.js';
import { resolveCliDataPaths } from './paths.js';
import { createProductionPorts } from './ports.js';
import {
  createSecretBackend,
  type SecretBackend,
  type SecretBackendPolicy,
} from './secret-backend.js';
import { resolveSessionLifetimePolicy } from './session-policy.js';

export const unlockMethodSchema = z.discriminatedUnion('kind', [
  z.object({ kind: z.literal('remembered-device') }).strict(),
  z
    .object({
      kind: z.literal('passphrase'),
      passphraseSlotId: keySlotIdSchema.optional(),
    })
    .strict(),
  z
    .object({
      kind: z.literal('key-file'),
      path: z.string().min(1),
      slotId: keySlotIdSchema.optional(),
    })
    .strict(),
  z
    .object({
      kind: z.literal('portable'),
      formattedKey: z.string().min(1),
      slotId: keySlotIdSchema.optional(),
    })
    .strict(),
]);

export type UnlockMethod = z.infer<typeof unlockMethodSchema>;

export interface ProductionUnlockedRequest {
  readonly environment: Readonly<Record<string, string | undefined>>;
  readonly secrets: SecretInputPort;
  readonly backendPolicy: SecretBackendPolicy;
  readonly unlockMethod?: UnlockMethod;
  readonly allowInsecureLoopbackDevelopment?: boolean;
  /**
   * Deadlines for this invocation. Omitted in production so the operator's
   * environment resolves them; supplied by tests to drive expiry deterministically.
   */
  readonly sessionPolicy?: SessionLifetimePolicy;
  /** Injectable monotonic clock, timer, and signal source for the session. */
  readonly sessionPorts?: Partial<SessionRuntimePorts>;
}

export interface ProductionUnlockedContext {
  readonly profile: VaultProfile;
  readonly ports: CliUseCasePorts;
  readonly environment: ProductionCommandEnvironment;
  /**
   * The protected secret backend backing this invocation. It is owned by the
   * environment and closed with it; callers must never close it themselves.
   */
  readonly backend: SecretBackend;
  /**
   * The lifetime that bounds this invocation. Cancellable work is threaded onto
   * `session.signal`, release steps are registered on it, and a command asserts
   * `session.assertLive()` before reporting an unlocked result.
   */
  readonly session: InvocationSession;
}

/**
 * Reopens the remembered device slot inside an already unlocked invocation.
 * The returned root key is caller-owned and must be zeroized immediately after
 * the bounded operation that needs it completes.
 */
export async function unwrapRememberedDeviceRootKey(
  unlocked: ProductionUnlockedContext,
): Promise<VaultRootKey> {
  const store = await unlocked.environment.openSyncStore(unlocked.profile);
  const vault = await store.getVault(unlocked.profile.vaultId);
  if (vault === null) throw new Error('Vault record not found');
  const slot = vault.keySlots.find(
    (candidate) => candidate.id === unlocked.profile.deviceLocator.keySlotId,
  );
  if (slot?.type !== 'device-key' || slot.deviceId !== unlocked.profile.deviceId) {
    throw new Error('Device key slot not found');
  }
  const secret = await unlocked.backend.keychain.load(unlocked.profile.deviceLocator);
  if (secret === null) throw new Error('Device secret not found');
  try {
    return await unlockDeviceKeySlot(
      slot,
      deviceUnlockSecretSchema.parse(secret),
      slotBinding(vault, slot),
    );
  } finally {
    zeroize(secret);
  }
}

/**
 * Runs an operation within an unlocked invocation-scoped lifecycle.
 *
 * Resolves the active profile, opens environment/backend, executes the callback,
 * and always locks and closes resources on exit. The environment is handed to the
 * session's cleanup stack rather than released in a local `finally`, so it is
 * closed on the deadline, the inactivity limit, and SIGINT/SIGTERM/SIGHUP as
 * reliably as on a normal return — including when the operation itself has stopped
 * making progress and never observes the abort.
 */
export async function runProductionUnlocked<Output>(
  request: ProductionUnlockedRequest,
  operation: (context: ProductionUnlockedContext) => Promise<Output>,
): Promise<Output> {
  const unlockMethod =
    request.unlockMethod === undefined
      ? { kind: 'remembered-device' as const }
      : unlockMethodSchema.parse(request.unlockMethod);
  const policy =
    request.sessionPolicy ?? resolveSessionLifetimePolicy(request.environment);

  return await runWithInvocationSession(
    {
      policy,
      ...(request.sessionPorts === undefined ? {} : { ports: request.sessionPorts }),
    },
    async (session) => {
      const paths = resolveCliDataPaths(request.environment);
      const backend = await createSecretBackend(
        paths,
        request.secrets,
        request.backendPolicy,
      );

      let environment: ProductionCommandEnvironment;
      try {
        environment = await openProductionCommandEnvironment(paths, backend);
      } catch (openFailure) {
        await backend.close();
        throw openFailure;
      }
      // The environment owns the backend, so one release step covers both. From
      // here the session, not this scope, decides when they close.
      session.register('command environment', () => environment.close());
      // Opening a protected environment can involve a masked prompt, so the
      // inactivity limit restarts once the resource is actually available.
      session.touch();

      const profile = await resolveActiveProfile(environment.profiles);
      const ports = createProductionPorts({
        profile,
        environment,
        secrets: backend,
        secretsInput: request.secrets,
        unlockMethod,
        join: () =>
          Promise.reject(new Error('Join unavailable during unlocked runner')),
        ...(request.allowInsecureLoopbackDevelopment !== undefined
          ? {
              allowInsecureLoopbackDevelopment:
                request.allowInsecureLoopbackDevelopment,
            }
          : {}),
      });

      const value = await operation({ profile, ports, environment, backend, session });
      // The work is done, but it may have finished after a deadline passed. An
      // expired session never reports a successful unlocked result.
      session.assertLive();
      return value;
    },
  );
}

/** Locks the vault and clears managed clipboard state in production. */
export async function runProductionLock(
  request: Pick<ProductionUnlockedRequest, 'environment' | 'secrets' | 'backendPolicy'>,
): Promise<void> {
  const paths = resolveCliDataPaths(request.environment);
  const backend = await createSecretBackend(
    paths,
    request.secrets,
    request.backendPolicy,
  );

  let environment: ProductionCommandEnvironment | undefined;
  try {
    environment = await openProductionCommandEnvironment(paths, backend);
    await environment.clipboard.lock();
  } finally {
    if (environment !== undefined) {
      await environment.close();
    } else {
      await backend.close();
    }
  }
}
