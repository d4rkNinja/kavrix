import { slotBinding, type VaultProfile } from '@kavrix/client';
import { unlockDeviceKeySlot, zeroize, type VaultRootKey } from '@kavrix/crypto';
import { deviceUnlockSecretSchema } from '@kavrix/schemas';
import { keySlotIdSchema } from '@kavrix/schemas';
import { z } from 'zod';

import type { CliUseCasePorts } from '../contracts.js';
import type { SecretInputPort } from '../secret-input.js';
import {
  openProductionEnvironment,
  resolveActiveProfile,
  type ProductionEnvironment,
} from './environment.js';
import { resolveCliDataPaths } from './paths.js';
import { createProductionPorts } from './ports.js';
import {
  createSecretBackend,
  type SecretBackend,
  type SecretBackendPolicy,
} from './secret-backend.js';

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
}

export interface ProductionUnlockedContext {
  readonly profile: VaultProfile;
  readonly ports: CliUseCasePorts;
  readonly environment: ProductionEnvironment;
  /**
   * The protected secret backend backing this invocation. It is owned by the
   * environment and closed with it; callers must never close it themselves.
   */
  readonly backend: SecretBackend;
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
 * Resolves the active profile, opens environment/backend, executes the callback,
 * and always locks and closes resources on exit.
 */
export async function runProductionUnlocked<Output>(
  request: ProductionUnlockedRequest,
  operation: (context: ProductionUnlockedContext) => Promise<Output>,
): Promise<Output> {
  const unlockMethod =
    request.unlockMethod === undefined
      ? { kind: 'remembered-device' as const }
      : unlockMethodSchema.parse(request.unlockMethod);

  const paths = resolveCliDataPaths(request.environment);
  const backend = await createSecretBackend(
    paths,
    request.secrets,
    request.backendPolicy,
  );

  let environment: ProductionEnvironment | undefined;
  try {
    environment = await openProductionEnvironment(paths, backend);
  } catch (openFailure) {
    await backend.close();
    throw openFailure;
  }

  let outcome:
    | Readonly<{ succeeded: true; value: Output }>
    | Readonly<{ succeeded: false; error: unknown }>;
  try {
    const profile = await resolveActiveProfile(environment.profiles);
    const ports = createProductionPorts({
      profile,
      environment,
      secrets: backend,
      secretsInput: request.secrets,
      unlockMethod,
      join: () => Promise.reject(new Error('Join unavailable during unlocked runner')),
      ...(request.allowInsecureLoopbackDevelopment !== undefined
        ? { allowInsecureLoopbackDevelopment: request.allowInsecureLoopbackDevelopment }
        : {}),
    });
    outcome = {
      succeeded: true,
      value: await operation({ profile, ports, environment, backend }),
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
        'The unlocked operation and cleanup both failed.',
        { cause: outcome.error },
      );
    }
    throw cleanup.error;
  }

  if (!outcome.succeeded) throw outcome.error;
  return outcome.value;
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

  let environment: ProductionEnvironment | undefined;
  try {
    environment = await openProductionEnvironment(paths, backend);
    await environment.clipboard.lock();
  } finally {
    if (environment !== undefined) {
      await environment.close();
    } else {
      await backend.close();
    }
  }
}
