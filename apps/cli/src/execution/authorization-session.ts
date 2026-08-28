import { zeroize } from '@kavrix/crypto';

import {
  openDatabaseAuthorizationStateAccess,
  readDatabaseFlatSecrets,
  usesDatabaseContainer,
  type DatabaseFlatCommandOptions,
} from '../database-flat-commands.js';
import {
  AuthorizationState,
  type AuthorizationStateSnapshot,
} from './authorization-state.js';
import { invalidConfiguration } from './exit-codes.js';

/**
 * Opens the sealed authorization state for the selected database. Database
 * metadata is authenticated to derive the state key, but credential vault
 * payloads are never decrypted by policy/grant metadata commands.
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
  const secrets = await readDatabaseFlatSecrets(options, [], {
    requireVaultSelection: false,
  });
  const access = await openDatabaseAuthorizationStateAccess(options, secrets);
  let state: AuthorizationState;
  try {
    state = await AuthorizationState.open(
      access.keyFile,
      access.authorizationStateKey,
      { scopeKind: 'database', scopeId: access.databaseId },
    );
  } finally {
    zeroize(access.authorizationStateKey);
  }
  try {
    return await operation(state);
  } finally {
    state.close();
  }
}

/**
 * Reads sealed authorization metadata without creating or rewriting its
 * sidecar. The missing-sidecar view is an empty in-memory snapshot.
 */
export async function withAuthorizationSnapshot<T>(
  options: DatabaseFlatCommandOptions,
  operation: (snapshot: AuthorizationStateSnapshot) => Promise<T> | T,
): Promise<T> {
  if (!(await usesDatabaseContainer(options))) {
    throw invalidConfiguration(
      'Authorization commands require a database profile; create one with `kavrix db profile add`.',
    );
  }
  const secrets = await readDatabaseFlatSecrets(options, [], {
    requireVaultSelection: false,
  });
  const access = await openDatabaseAuthorizationStateAccess(options, secrets);
  const snapshot = await (async (): Promise<AuthorizationStateSnapshot> => {
    try {
      return await AuthorizationState.readSnapshot(
        access.keyFile,
        access.authorizationStateKey,
        { scopeKind: 'database', scopeId: access.databaseId },
      );
    } finally {
      // The derived key is only needed to authenticate/decrypt this one read;
      // policy analysis and its callback must never run while it remains live.
      zeroize(access.authorizationStateKey);
    }
  })();
  return await operation(snapshot);
}
