import { randomUUID } from 'node:crypto';
import {
  structuredVaultPayloadSchema,
  type StructuredVaultPayload,
  type VaultId,
} from '@kavrix/schemas';
import {
  DEFAULT_PROJECT_CONTEXT_ID,
  DEFAULT_SERVICE_ID,
  DEFAULT_TEMPLATE_ID,
  DEFAULT_VALUE_FIELD_ID,
} from './structured-vault-projection.js';

/** Remap only schema-owned identities. Secret strings are never rewritten. */
export function rebindStructuredExport(
  source: StructuredVaultPayload,
  target: VaultId,
): StructuredVaultPayload {
  const stable = new Set<string>([
    DEFAULT_PROJECT_CONTEXT_ID,
    DEFAULT_SERVICE_ID,
    DEFAULT_TEMPLATE_ID,
    DEFAULT_VALUE_FIELD_ID,
  ]);
  const ids = new Map<string, string>();
  const identity = (id: string): string => {
    if (stable.has(id)) return id;
    let mapped = ids.get(id);
    if (mapped === undefined) {
      mapped = `entity_${randomUUID()}`;
      ids.set(id, mapped);
    }
    return mapped;
  };
  const identityKeys = new Set([
    'id',
    'groupId',
    'projectContextId',
    'itemId',
    'templateId',
    'fieldId',
  ]);
  const identityArrays = new Set(['relatedItemIds', 'attachmentIds']);
  function visit(value: unknown, key = ''): unknown {
    if (typeof value === 'string') {
      if (key === 'vaultId') return target;
      return identityKeys.has(key) || identityArrays.has(key) ? identity(value) : value;
    }
    if (Array.isArray(value)) return value.map((entry: unknown) => visit(entry, key));
    if (value !== null && typeof value === 'object')
      return Object.fromEntries(
        Object.entries(value).map(([name, entry]) => [name, visit(entry, name)]),
      );
    return value;
  }
  return structuredVaultPayloadSchema.parse(visit(source));
}
