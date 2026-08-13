import type { VaultProfile } from '@kavrix/client';

import type { CliUseCasePorts } from '../contracts.js';
import type { SecretInputPort } from '../secret-input.js';
import {
  openProductionEnvironment,
  resolveActiveProfile,
  type ProductionEnvironment,
} from './environment.js';
import { resolveCliDataPaths } from './paths.js';
import { createProductionPorts } from './ports.js';
import { createSecretBackend, type SecretBackendPolicy } from './secret-backend.js';

export interface ProductionUnlockedRequest {
  readonly environment: Readonly<Record<string, string | undefined>>;
  readonly secrets: SecretInputPort;
  readonly backendPolicy: SecretBackendPolicy;
  readonly allowInsecureLoopbackDevelopment?: boolean;
}

export interface ProductionUnlockedContext {
  readonly profile: VaultProfile;
  readonly ports: CliUseCasePorts;
  readonly environment: ProductionEnvironment;
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
      join: () => Promise.reject(new Error('Join unavailable during unlocked runner')),
      ...(request.allowInsecureLoopbackDevelopment !== undefined
        ? { allowInsecureLoopbackDevelopment: request.allowInsecureLoopbackDevelopment }
        : {}),
    });
    outcome = {
      succeeded: true,
      value: await operation({ profile, ports, environment }),
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
