import { VaultReadSession, type VaultReadSourcePort } from '@kavrix/client';
import { resolveNamedEntity } from '@kavrix/core';
import type { VaultRootKey } from '@kavrix/crypto';
import type { ActiveFieldValue, FieldScalarValue, VaultId } from '@kavrix/schemas';

import { CliUsageError } from '../errors.js';

const REDACTED = '[REDACTED]';

export type ProductionGetOptions = Readonly<{
  source: VaultReadSourcePort;
  vaultId: VaultId;
  rootKey: VaultRootKey;
}>;

export type CredentialGetResult = Readonly<{
  groupName: string;
  credentialTitle: string;
  fieldLabel: string;
  fieldKey: string;
  fieldType: string;
  sensitive: boolean;
  /** True when the value was withheld, so `value` is a placeholder. */
  redacted: boolean;
  /** Record revision the value was read at, for an optimistic write. */
  revision: number;
  value: string;
}>;

export async function executeProductionGet(
  options: ProductionGetOptions,
  groupQuery: string,
  credentialQuery: string,
  fieldQuery: string,
  getOptions: Readonly<{ index?: number; reveal?: boolean }> = {},
): Promise<CredentialGetResult> {
  const readSession = new VaultReadSession(options.source, options.vaultId);
  await readSession.unlock(options.rootKey);
  try {
    const aggregate = await readSession.show(groupQuery, credentialQuery);
    const { item, template } = aggregate;

    const templateValues = new Map(
      item.templateValues.map((stored) => [stored.fieldId, stored]),
    );
    const itemValues = new Map(
      item.itemValues.map((stored) => [stored.fieldId, stored]),
    );
    const candidates = [
      ...template.fields.map((definition) => ({
        id: definition.id,
        name: definition.label,
        slug: definition.stableKey,
        aliases: [] as const,
        definition,
        value: templateValues.get(definition.id)?.value,
        archived: false,
      })),
      ...item.itemFields.map((definition) => ({
        id: definition.id,
        name: definition.label,
        slug: definition.stableKey,
        aliases: [] as const,
        definition,
        value: itemValues.get(definition.id)?.value,
        archived: false,
      })),
    ];

    const resolved = resolveNamedEntity(fieldQuery, candidates);
    if (resolved.value === undefined || resolved.value.state === 'missing') {
      throw new CliUsageError(`Field "${fieldQuery}" value is missing.`);
    }
    if (resolved.value.state === 'empty') {
      throw new CliUsageError(`Field "${fieldQuery}" value is empty.`);
    }
    if (resolved.value.state !== 'present') {
      throw new CliUsageError(`Field "${fieldQuery}" value is not present.`);
    }

    const scalar = selectScalarValue(resolved.value, getOptions.index);
    const isSensitive = resolved.definition.sensitive || scalar.kind === 'secret';
    // A caller reading JSON cannot tell a withheld secret from a stored value
    // that happens to spell the placeholder, so report the decision itself.
    const redacted = isSensitive && getOptions.reveal !== true;
    const valueStr = redacted ? REDACTED : scalarText(scalar);

    return {
      groupName: aggregate.group.name,
      credentialTitle: item.title,
      fieldLabel: resolved.definition.label,
      fieldKey: resolved.definition.stableKey,
      fieldType: resolved.definition.type,
      sensitive: isSensitive,
      redacted,
      revision: item.revision,
      value: valueStr,
    };
  } finally {
    readSession.lock();
  }
}

function selectScalarValue(
  value: Extract<ActiveFieldValue, { state: 'present' }>,
  index: number | undefined,
): FieldScalarValue {
  if (value.content.cardinality === 'single') {
    if (index !== undefined) {
      throw new CliUsageError('Index is not applicable for single field value.');
    }
    return value.content.value;
  }
  if (index === undefined) {
    throw new CliUsageError('Index is required for multi-value field.');
  }
  if (!Number.isSafeInteger(index) || index < 1) {
    throw new CliUsageError('Index out of range.');
  }
  const element = value.content.elements[index - 1];
  if (element === undefined) {
    throw new CliUsageError('Index out of range.');
  }
  return element.value;
}

function scalarText(value: FieldScalarValue): string {
  switch (value.kind) {
    case 'text':
    case 'secret':
      return value.value;
    case 'number':
    case 'boolean':
      return String(value.value);
    case 'item-reference':
      return value.itemId;
    case 'attachment-reference':
      return value.attachmentId;
    default: {
      const raw = (value as { value?: unknown }).value;
      return typeof raw === 'string' ||
        typeof raw === 'number' ||
        typeof raw === 'boolean'
        ? String(raw)
        : '';
    }
  }
}
