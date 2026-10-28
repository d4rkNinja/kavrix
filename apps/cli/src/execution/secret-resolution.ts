import {
  parseExecutionReference,
  type StructuredVaultPayload,
  type VaultId,
} from '@kavrix/schemas';
import type { DatabaseSession } from '../database-session.js';
import { projectFlatVaultPayload } from '../structured-vault-projection.js';
import {
  encodeStructuredFieldValueBase64,
  projectStructuredField,
  resolveItem,
  resolveProjectContext,
  resolveService,
} from '../structured-vault-impl.js';
import { executionReferenceIdentities } from './reference-identity.js';
import { credentialMissing, invalidConfiguration } from './exit-codes.js';

/** Values never cross the storage interface; both execution paths use this resolver. */
export function resolveExecutionValue(
  payload: StructuredVaultPayload,
  reference: string,
): string {
  const flat = projectFlatVaultPayload(payload);
  const parsed = parseExecutionReference(reference);
  if (parsed.kind === 'flat') {
    const record = flat.records[parsed.name];
    if (record === undefined) throw credentialMissing(reference);
    return record.value;
  }
  if (Object.hasOwn(flat.records, reference))
    throw invalidConfiguration(
      'Execution reference is ambiguous with a flat credential name.',
    );
  const context = resolveProjectContext(payload, parsed.context);
  const group = resolveService(payload, context.id, parsed.service);
  const item = resolveItem(payload, group.id, parsed.item);
  if (
    context.name !== parsed.context ||
    group.name !== parsed.service ||
    item.title !== parsed.item
  )
    throw invalidConfiguration(
      'Structured execution references must use exact canonical names.',
    );
  const field = projectStructuredField(item, parsed.field, group.template);
  if (field.definition.stableKey !== parsed.field || field.value?.state !== 'present')
    throw credentialMissing(reference);
  return Buffer.from(encodeStructuredFieldValueBase64(field.value), 'base64').toString(
    'utf8',
  );
}

export async function loadExecutionSecrets(
  session: DatabaseSession,
  vaultId: VaultId,
  references: ReadonlySet<string>,
  identityOnlyReferences: readonly string[] = [],
): Promise<{
  values: Map<string, string>;
  policyRequired: boolean;
  identities: Map<string, readonly string[]>;
}> {
  const values = new Map<string, string>();
  const identities = new Map<string, readonly string[]>();
  let policyRequired = false;
  await session.inspectStructuredVault(vaultId, (payload) => {
    policyRequired = payload.executionPolicy === 'required';
    for (const reference of [...references, ...identityOnlyReferences])
      identities.set(reference, executionReferenceIdentities(payload, reference));
    for (const reference of references)
      values.set(reference, resolveExecutionValue(payload, reference));
  });
  return { values, policyRequired, identities };
}
