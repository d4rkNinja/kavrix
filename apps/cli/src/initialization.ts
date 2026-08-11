import {
  lifecycleOperationIdSchema,
  type LifecycleOperationId,
  type VaultImportedPortableDisplayMaterial,
  type VaultImportedPortableInitializationCreation,
  type VaultInitializationConfirmation,
  type VaultInitializationCreation,
  type VaultInitializationDisplayMaterial,
  type VaultInitializationInput,
  type VaultLifecycleReceipt,
} from '@kavrix/client';
import { deviceIdSchema, vaultIdSchema, vaultPreferencesSchema } from '@kavrix/schemas';
import { z } from 'zod';

import { CliUnavailableError, CliUsageError } from './errors.js';
import {
  acquiredSecretSchema,
  type AcquiredSecret,
  type SecretInputPort,
} from './secret-input.js';

const keyFilePathSchema = z
  .string()
  .min(1)
  .max(32_768)
  .refine((value) => !/[\0\r\n]/u.test(value));
const sensitiveDisplayAcknowledgementSchema = z
  .object({ acknowledged: z.literal(true), interactiveTty: z.literal(true) })
  .strict();

export const DEFAULT_VAULT_INITIALIZATION_INPUT: VaultInitializationInput =
  Object.freeze({
    preferences: Object.freeze(
      vaultPreferencesSchema.parse({
        productLabel: 'CredVault',
        executableName: 'creds',
        clipboardClearSeconds: 30,
        revealHideSeconds: 15,
        historyRetentionDays: 365,
        telemetryEnabled: false,
      }),
    ),
    deviceKeyProvider: 'native',
  });

/**
 * The initialization surface the CLI depends on.
 *
 * `VaultInitializationCoordinator` satisfies this structurally. The two `begin`
 * members are declared as awaitable rather than borrowed verbatim so the
 * production adapter can construct the coordinator behind a dynamic `import()`
 * on first use: the packed binary must not evaluate the crypto graph for
 * `--version` or `completion`.
 */
export interface CliVaultInitializationPort {
  begin(
    input: VaultInitializationInput,
    serverUrl?: string,
  ): VaultInitializationCreation | Promise<VaultInitializationCreation>;
  beginImportedPortable(
    input: VaultInitializationInput,
    formattedPortableKey: string,
    serverUrl?: string,
  ):
    | VaultImportedPortableInitializationCreation
    | Promise<VaultImportedPortableInitializationCreation>;
  resume(
    operationId: LifecycleOperationId,
    serverUrl?: string,
  ): Promise<VaultLifecycleReceipt>;
  cancel(operationId: LifecycleOperationId, serverUrl?: string): Promise<void>;
}

export type SensitiveInitializationMaterial =
  VaultInitializationDisplayMaterial | VaultImportedPortableDisplayMaterial;

export type SensitiveInitializationDisplayRequest = Readonly<{
  operationId: LifecycleOperationId;
  material: SensitiveInitializationMaterial;
  requiresInteractiveTty: true;
  requiresExplicitAcknowledgement: true;
}>;

export interface SensitiveInitializationDisplayPort {
  /**
   * The implementation must use a dedicated sensitive surface, refuse a
   * non-interactive terminal, show the material once, and require explicit
   * acknowledgement before resolving.
   */
  display(request: SensitiveInitializationDisplayRequest): Promise<unknown>;
}

export interface ProtectedPortableKeyFileReaderPort {
  /** Returns one formatted portable key without echoing or logging the path/key. */
  readFormattedPortableKey(path: string): Promise<unknown>;
}

export type CliInitializationDependencies = Readonly<{
  coordinator: CliVaultInitializationPort;
  sensitiveDisplay: SensitiveInitializationDisplayPort;
  keyFiles?: ProtectedPortableKeyFileReaderPort;
  input?: VaultInitializationInput;
}>;

export type CliInitializationStartOptions =
  | Readonly<{
      source: 'generated';
      confirmationFromStdin: boolean;
    }>
  | Readonly<{
      source: 'masked-portable';
      confirmationFromStdin: false;
    }>
  | Readonly<{
      source: 'key-file';
      path: string;
      confirmationFromStdin: boolean;
    }>
  | Readonly<{
      source: 'stdin-protocol';
      confirmationFromStdin: true;
    }>;

/**
 * `serverUrl` is the sync server the new vault will belong to. It is forwarded
 * rather than resolved here: only the adapter knows whether an omitted `--server`
 * can fall back to an environment default.
 */
export async function startVaultInitialization(
  dependencies: CliInitializationDependencies,
  secrets: SecretInputPort,
  options: CliInitializationStartOptions,
  serverUrl?: string,
): Promise<VaultLifecycleReceipt> {
  const input = dependencies.input ?? DEFAULT_VAULT_INITIALIZATION_INPUT;
  if (options.source === 'generated') {
    const creation =
      serverUrl === undefined
        ? await dependencies.coordinator.begin(input)
        : await dependencies.coordinator.begin(input, serverUrl);
    try {
      await displayAndAcknowledge(
        dependencies.sensitiveDisplay,
        creation.operationId,
        creation.takeDisplayMaterial(),
      );
      const confirmation = await readConfirmation(
        secrets,
        options.confirmationFromStdin,
      );
      return await creation.confirm(confirmation);
    } catch (error) {
      creation.cancel();
      throw error;
    }
  }

  let importedPortable: AcquiredSecret;
  if (options.source === 'masked-portable') {
    importedPortable = await secrets.read({
      kind: 'portable-key',
      fromStdin: false,
    });
  } else if (options.source === 'key-file') {
    const keyFiles = dependencies.keyFiles;
    if (keyFiles === undefined) throw new CliUnavailableError('init');
    const path = parseKeyFilePath(options.path);
    try {
      importedPortable = acquiredSecretSchema.parse(
        await keyFiles.readFormattedPortableKey(path),
      );
    } catch {
      throw new CliUsageError('The protected portable key file is invalid.');
    }
  } else {
    const frames = await readExactSecretFrames(secrets, ['portable-key'], true, false);
    importedPortable = requiredFrame(frames, 0);
  }

  const creation =
    serverUrl === undefined
      ? await dependencies.coordinator.beginImportedPortable(input, importedPortable)
      : await dependencies.coordinator.beginImportedPortable(
          input,
          importedPortable,
          serverUrl,
        );
  try {
    await displayAndAcknowledge(
      dependencies.sensitiveDisplay,
      creation.operationId,
      creation.takeDisplayMaterial(),
    );
    const confirmation = await readConfirmation(secrets, options.confirmationFromStdin);
    return await creation.confirm(confirmation);
  } catch (error) {
    creation.cancel();
    throw error;
  }
}

export function parseLifecycleOperationId(value: string): LifecycleOperationId {
  try {
    return lifecycleOperationIdSchema.parse(value);
  } catch {
    throw new CliUsageError('The initialization operation ID is invalid.');
  }
}

export function renderInitializationReceipt(receipt: VaultLifecycleReceipt): string {
  const vaultId = vaultIdSchema.parse(receipt.vaultId);
  const deviceId = deviceIdSchema.parse(receipt.deviceId);
  lifecycleOperationIdSchema.parse(receipt.operationId);
  void vaultId;
  void deviceId;
  return 'Vault initialized.\n';
}

async function displayAndAcknowledge(
  display: SensitiveInitializationDisplayPort,
  operationId: LifecycleOperationId,
  material: SensitiveInitializationMaterial,
): Promise<void> {
  let result: unknown;
  try {
    result = await display.display({
      operationId,
      material,
      requiresInteractiveTty: true,
      requiresExplicitAcknowledgement: true,
    });
  } catch {
    throw new CliUsageError(
      'Sensitive initialization material requires an interactive acknowledged display.',
    );
  }
  if (!sensitiveDisplayAcknowledgementSchema.safeParse(result).success) {
    throw new CliUsageError(
      'Sensitive initialization material requires an interactive acknowledged display.',
    );
  }
}

async function readConfirmation(
  secrets: SecretInputPort,
  fromStdin: boolean,
): Promise<VaultInitializationConfirmation> {
  const frames = await readExactSecretFrames(
    secrets,
    ['portable-key', 'recovery-key'],
    fromStdin,
    fromStdin,
  );
  return {
    portableKey: requiredFrame(frames, 0),
    recoveryKey: requiredFrame(frames, 1),
  };
}

async function readExactSecretFrames(
  secrets: SecretInputPort,
  kinds: Parameters<SecretInputPort['readBatch']>[0]['kinds'],
  fromStdin = true,
  requireEnd = fromStdin,
): Promise<readonly AcquiredSecret[]> {
  let values: readonly AcquiredSecret[];
  try {
    values = await secrets.readBatch({ kinds, fromStdin, requireEnd });
  } catch (error) {
    if (error instanceof CliUsageError) throw error;
    throw new CliUsageError('Secret confirmation could not be read.');
  }
  if (values.length !== kinds.length) {
    throw new CliUsageError('Secret confirmation used invalid framing.');
  }
  try {
    return values.map((value) => acquiredSecretSchema.parse(value));
  } catch {
    throw new CliUsageError('Secret confirmation used invalid framing.');
  }
}

function requiredFrame(
  values: readonly AcquiredSecret[],
  index: number,
): AcquiredSecret {
  const value = values[index];
  if (value === undefined) {
    throw new CliUsageError('Secret confirmation used invalid framing.');
  }
  return value;
}

function parseKeyFilePath(path: string): string {
  const result = keyFilePathSchema.safeParse(path);
  if (!result.success)
    throw new CliUsageError('The portable key file path is invalid.');
  return result.data;
}
