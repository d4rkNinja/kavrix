import {
  localVaultPayloadSchema,
  timestampSchema,
  type LocalVaultPayload,
} from '@kavrix/schemas';
import { LocalCliError } from './cli-error.js';
import { validateCredentialName } from './credential-name.js';
import { credentialMissing } from './execution/exit-codes.js';

export function putCredential(
  payload: LocalVaultPayload,
  name: string,
  value: string,
  overwrite: boolean,
): LocalVaultPayload {
  validateCredentialName(name);
  if (Object.hasOwn(payload.records, name) && !overwrite)
    throw new LocalCliError(
      'Credential already exists. Re-run with --overwrite to replace it.',
    );
  return localVaultPayloadSchema.parse({
    records: {
      ...payload.records,
      [name]: { value, updatedAt: timestampSchema.parse(new Date().toISOString()) },
    },
  });
}

export function renameCredential(
  payload: LocalVaultPayload,
  from: string,
  to: string,
): LocalVaultPayload {
  validateCredentialName(from);
  validateCredentialName(to);
  if (from === to) throw new LocalCliError('Credential names must be different.');
  if (!Object.hasOwn(payload.records, from)) throw credentialMissing();
  if (Object.hasOwn(payload.records, to))
    throw new LocalCliError('The destination credential already exists.');
  return localVaultPayloadSchema.parse({
    records: Object.fromEntries(
      Object.entries(payload.records).map(([key, record]) => [
        key === from ? to : key,
        record,
      ]),
    ),
  });
}

export function removeCredential(
  payload: LocalVaultPayload,
  name: string,
): LocalVaultPayload {
  validateCredentialName(name);
  if (!Object.hasOwn(payload.records, name)) throw credentialMissing();
  return localVaultPayloadSchema.parse({
    records: Object.fromEntries(
      Object.entries(payload.records).filter(([key]) => key !== name),
    ),
  });
}
