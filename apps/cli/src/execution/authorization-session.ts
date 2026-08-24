import { AuthorizationState } from './authorization-state.js';
import {
  closeDatabaseFlatVault,
  openDatabaseFlatVault,
  readDatabaseFlatSecrets,
  usesDatabaseContainer,
  type DatabaseFlatCommandOptions,
} from '../database-flat-commands.js';
import { zeroize } from '@kavrix/crypto';

import { invalidConfiguration } from './exit-codes.js';

/**
 * Opens the sealed authorization state for the selected database vault and
 * hands it to the operation. The database session closes before the operation
 * runs: policy, grant, audit, and agent commands never need the DRK after the
 * derived state key exists.
 */
export async function withAuthorizationState<T>(
  options: DatabaseFlatCommandOptions,
  operation: (state: AuthorizationState) => Promise<T>,
): Promise<T> {
  if (!(await usesDatabaseContainer(options))) {
    throw invalidConfiguration(
      'Authorization commands require a database profile; create one with `kavrix db profile add`.',
    );
  }
  const secrets = await readDatabaseFlatSecrets(options, []);
  const handle = await openDatabaseFlatVault(options, secrets);
  let authzKey: Uint8Array;
  let keyFile: string;
  try {
    authzKey = handle.session.authorizationStateKey();
    keyFile = handle.profile.keyFile;
  } finally {
    await closeDatabaseFlatVault(handle).catch(() => undefined);
  }
  const scopeId = handle.session.databaseId;
  let state: AuthorizationState;
  try {
    state = await AuthorizationState.open(keyFile, authzKey, {
      scopeKind: 'database',
      scopeId,
    });
  } catch (error) {
    zeroize(authzKey);
    throw error;
  }
  try {
    return await operation(state);
  } finally {
    state.close();
  }
}
