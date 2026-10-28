import { structuredVaultPayloadSchema } from '@kavrix/schemas';
import {
  readDatabaseFlatSecrets,
  withDatabaseFlatVault,
  type DatabaseFlatCommandOptions,
} from '../database-flat-commands.js';
import { invalidConfiguration } from './exit-codes.js';

export async function executePolicyMode(
  options: DatabaseFlatCommandOptions,
  mode?: string,
): Promise<unknown> {
  if (mode !== undefined && mode !== 'optional' && mode !== 'required')
    throw invalidConfiguration('Policy mode must be optional or required.');
  const secrets = await readDatabaseFlatSecrets(options, []);
  let observed = 'optional';
  await withDatabaseFlatVault(options, secrets, async (session, vaultId) => {
    if (mode === undefined) {
      await session.inspectStructuredVault(vaultId, (payload) => {
        observed = payload.executionPolicy ?? 'optional';
      });
    } else {
      await session.updateStructuredVault(vaultId, (payload) =>
        structuredVaultPayloadSchema.parse({
          ...payload,
          version: 2,
          executionPolicy: mode,
        }),
      );
      observed = mode;
    }
  });
  return { mode: observed, changed: mode !== undefined };
}
