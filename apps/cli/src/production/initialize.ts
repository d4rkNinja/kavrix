import type {
  VaultInitializationCoordinator,
  LifecycleOperationId,
  VaultInitializationInput,
} from '@kavrix/client';

import { CliUsageError } from '../errors.js';
import type {
  CliInitializationDependencies,
  CliVaultInitializationPort,
} from '../initialization.js';
import type { SecretInputPort } from '../secret-input.js';
import {
  openProductionEnvironment,
  type ProductionEnvironment,
} from './environment.js';
import { resolveCliDataPaths } from './paths.js';
import { productionClock, randomIdGenerator } from './runtime-adapters.js';
import {
  createSecretBackend,
  type SecretBackend,
  type SecretBackendPolicy,
} from './secret-backend.js';
import { NodeSensitiveInitializationDisplay } from './sensitive-display.js';

export interface ProductionInitializationPortOptions {
  readonly environment: ProductionEnvironment;
  readonly secrets: SecretBackend;
  readonly defaultServerUrl?: string;
  readonly allowInsecureLoopbackDevelopment?: boolean;
  readonly coordinatorFactory?: (
    options: ConstructorParameters<typeof VaultInitializationCoordinator>[0],
  ) => CliVaultInitializationPort;
}

export interface ProductionInitializationRequest {
  readonly environment: Readonly<Record<string, string | undefined>>;
  readonly secrets: SecretInputPort;
  readonly backendPolicy: SecretBackendPolicy;
  readonly serverUrl?: string;
  readonly allowInsecureLoopbackDevelopment?: boolean;
}

/**
 * Creates the production `CliVaultInitializationPort` backed by real SQLite stores,
 * native/sealed keychains, and the zero-knowledge control plane HTTP client.
 */
export function createProductionInitializationPort(
  options: ProductionInitializationPortOptions,
): CliVaultInitializationPort {
  const getCoordinator = async (
    explicitServerUrl?: string,
  ): Promise<CliVaultInitializationPort> => {
    const serverUrl = explicitServerUrl ?? options.defaultServerUrl ?? '';
    const { ControlPlaneClient, VaultInitializationCoordinator } =
      await import('@kavrix/client');
    const controlPlane = new ControlPlaneClient({
      baseUrl: serverUrl,
      ...(options.allowInsecureLoopbackDevelopment === true
        ? { allowInsecureLoopbackDevelopment: true }
        : {}),
    });

    const coordinatorOptions: ConstructorParameters<
      typeof VaultInitializationCoordinator
    >[0] = {
      controlPlane,
      journal: options.environment.initializationJournal,
      profiles: options.environment.profiles,
      keychain: options.secrets.keychain,
      sessions: options.secrets.sessions,
      clock: productionClock(),
      ids: {
        operation: randomIdGenerator(),
        vault: randomIdGenerator(),
        device: randomIdGenerator(),
        keySlot: randomIdGenerator(),
      },
    };

    return options.coordinatorFactory === undefined
      ? new VaultInitializationCoordinator(coordinatorOptions)
      : options.coordinatorFactory(coordinatorOptions);
  };

  const ensureNoExistingProfile = async (): Promise<void> => {
    const profiles = await options.environment.profiles.listProfiles();
    if (profiles.length > 0) {
      throw new CliUsageError('A vault profile already exists on this device.');
    }
  };

  return {
    begin: async (input: VaultInitializationInput, serverUrl?: string) => {
      await ensureNoExistingProfile();
      const coordinator = await getCoordinator(serverUrl);
      return coordinator.begin(input, serverUrl);
    },

    beginImportedPortable: async (
      input: VaultInitializationInput,
      formattedPortableKey: string,
      serverUrl?: string,
    ) => {
      await ensureNoExistingProfile();
      const coordinator = await getCoordinator(serverUrl);
      return coordinator.beginImportedPortable(input, formattedPortableKey, serverUrl);
    },

    resume: async (operationId: LifecycleOperationId, serverUrl?: string) => {
      const coordinator = await getCoordinator(serverUrl);
      return coordinator.resume(operationId, serverUrl);
    },

    cancel: async (operationId: LifecycleOperationId, serverUrl?: string) => {
      const coordinator = await getCoordinator(serverUrl);
      return coordinator.cancel(operationId, serverUrl);
    },
  };
}

/** Runs the production initialization lifecycle slice and closes environment on exit. */
export async function runProductionInitialization<Output>(
  request: ProductionInitializationRequest,
  operation: (dependencies: CliInitializationDependencies) => Promise<Output>,
): Promise<Output> {
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

  const coordinatorPort = createProductionInitializationPort({
    environment,
    secrets: backend,
    ...(request.serverUrl !== undefined ? { defaultServerUrl: request.serverUrl } : {}),
    ...(request.allowInsecureLoopbackDevelopment !== undefined
      ? { allowInsecureLoopbackDevelopment: request.allowInsecureLoopbackDevelopment }
      : {}),
  });

  const sensitiveDisplay = new NodeSensitiveInitializationDisplay(
    process.stdin,
    process.stderr,
  );

  const dependencies: CliInitializationDependencies = {
    coordinator: coordinatorPort,
    sensitiveDisplay,
  };

  let outcome:
    | Readonly<{ succeeded: true; value: Output }>
    | Readonly<{ succeeded: false; error: unknown }>;
  try {
    outcome = { succeeded: true, value: await operation(dependencies) };
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
        'The initialization operation and cleanup both failed.',
        { cause: outcome.error },
      );
    }
    throw cleanup.error;
  }
  if (!outcome.succeeded) throw outcome.error;
  return outcome.value;
}
