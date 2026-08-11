import type { CliStatus } from '../contracts.js';
import type { SecretInputPort } from '../secret-input.js';
import {
  openProductionStatusEnvironment,
  resolveActiveProfile,
} from './environment.js';
import { resolveCliDataPaths } from './paths.js';
import { readProductionStatus } from './ports.js';
import { createSecretBackend, type SecretBackendPolicy } from './secret-backend.js';

export interface ProductionStatusRequest {
  readonly environment: Readonly<Record<string, string | undefined>>;
  readonly secrets: SecretInputPort;
  readonly backendPolicy: SecretBackendPolicy;
}

export interface ProductionStatusDependencies {
  readonly resolvePaths: typeof resolveCliDataPaths;
  readonly createBackend: typeof createSecretBackend;
  readonly openEnvironment: typeof openProductionStatusEnvironment;
  readonly resolveProfile: typeof resolveActiveProfile;
  readonly readStatus: typeof readProductionStatus;
}

const DEFAULT_DEPENDENCIES: ProductionStatusDependencies = {
  resolvePaths: resolveCliDataPaths,
  createBackend: createSecretBackend,
  openEnvironment: openProductionStatusEnvironment,
  resolveProfile: resolveActiveProfile,
  readStatus: readProductionStatus,
};

/** Runs the locked, network-free status slice and closes it before rendering. */
export async function runProductionStatus(
  request: ProductionStatusRequest,
  overrides: Partial<ProductionStatusDependencies> = {},
): Promise<CliStatus> {
  const dependencies = { ...DEFAULT_DEPENDENCIES, ...overrides };
  const paths = dependencies.resolvePaths(request.environment);
  const backend = await dependencies.createBackend(
    paths,
    request.secrets,
    request.backendPolicy,
  );

  // Ownership transfers at the call boundary. The opener closes the backend if
  // acquisition fails; after it resolves, this scope owns the environment.
  const environment = await dependencies.openEnvironment(paths, backend);
  let outcome:
    | Readonly<{ succeeded: true; value: CliStatus }>
    | Readonly<{ succeeded: false; error: unknown }>;
  try {
    const profile = await dependencies.resolveProfile(environment.profiles);
    outcome = {
      succeeded: true,
      value: await dependencies.readStatus({
        profile,
        environment,
        protectedSyncState: backend.protectedSyncState,
      }),
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
        'The status operation and cleanup both failed.',
        { cause: outcome.error },
      );
    }
    throw cleanup.error;
  }
  if (!outcome.succeeded) throw outcome.error;
  return outcome.value;
}
