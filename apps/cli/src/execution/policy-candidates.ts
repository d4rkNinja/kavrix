import {
  readDatabaseFlatSecrets,
  withDatabaseFlatVault,
  type DatabaseFlatCommandOptions,
} from '../database-flat-commands.js';
import { AuthorizationState } from './authorization-state.js';
import { zeroize } from '@kavrix/crypto';
import { credentialMissing } from './exit-codes.js';
import type { PolicyCandidateMap } from '@kavrix/schemas';

/** Candidate definitions are inert until this explicit, owner-authenticated action. */
export async function executePolicyCandidates(
  options: DatabaseFlatCommandOptions,
  id?: string,
): Promise<unknown> {
  const secrets = await readDatabaseFlatSecrets(options, []);
  let result: unknown;
  await withDatabaseFlatVault(options, secrets, async (session, vaultId, profile) => {
    let candidates: PolicyCandidateMap = {};
    await session.inspectStructuredVault(vaultId, (payload) => {
      candidates = payload.policyCandidates ?? {};
    });
    if (id === undefined) {
      result = { candidates };
      return;
    }
    if (!Object.hasOwn(candidates, id)) throw credentialMissing();
    const entry = candidates[id];
    if (entry === undefined) throw credentialMissing();
    const key = session.authorizationStateKey();
    let state;
    try {
      state = await AuthorizationState.open(profile.keyFile, key, {
        scopeKind: 'database',
        scopeId: session.databaseId,
      });
    } finally {
      zeroize(key);
    }
    try {
      await state.putPolicy(id, entry, { createOnly: true });
      result = { imported: true, id };
    } finally {
      state.close();
    }
  });
  return result;
}
