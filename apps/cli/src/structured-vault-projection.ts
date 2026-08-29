import { randomUUID } from 'node:crypto';

import {
  databaseVaultPayloadSchema,
  fieldIdSchema,
  fieldValueSchema,
  groupIdSchema,
  itemIdSchema,
  localVaultPayloadSchema,
  projectContextIdSchema,
  structuredVaultPayloadSchema,
  templateIdSchema,
  timestampSchema,
  vaultIdSchema,
  type DatabaseVaultPayload,
  type FieldValue,
  type ItemPayload,
  type LocalVaultPayload,
  type StructuredServicePayload,
  type StructuredVaultPayload,
  type Timestamp,
  type VaultId,
} from '@kavrix/schemas';

/** The stable identity used for the hierarchy behind legacy root commands. */
export const DEFAULT_PROJECT_CONTEXT_ID =
  projectContextIdSchema.parse('project.default');
export const DEFAULT_PROJECT_CONTEXT_NAME = 'Default project';
export const DEFAULT_PROJECT_NAME = DEFAULT_PROJECT_CONTEXT_NAME;
export const DEFAULT_PROJECT_CONTEXT_ENVIRONMENT = 'default';

/** The service/group that owns the compatibility projection. */
export const DEFAULT_SERVICE_ID = groupIdSchema.parse('service.default');
export const DEFAULT_SERVICE_NAME = 'Default service';
export const DEFAULT_GROUP_ID = DEFAULT_SERVICE_ID;
export const DEFAULT_GROUP_NAME = DEFAULT_SERVICE_NAME;

/** The one item-only field exposed by legacy flat commands. */
export const DEFAULT_TEMPLATE_ID = templateIdSchema.parse('template.default');
export const DEFAULT_TEMPLATE_NAME = 'Default';
export const DEFAULT_VALUE_FIELD_ID = fieldIdSchema.parse('field.value');
export const DEFAULT_VALUE_FIELD_KEY = 'value';
export const DEFAULT_VALUE_FIELD_STABLE_KEY = DEFAULT_VALUE_FIELD_KEY;
export const DEFAULT_VALUE_FIELD_LABEL = 'Value';
export const DEFAULT_FIELD_ID = DEFAULT_VALUE_FIELD_ID;
export const DEFAULT_FIELD_KEY = DEFAULT_VALUE_FIELD_KEY;
export const DEFAULT_FIELD_LABEL = DEFAULT_VALUE_FIELD_LABEL;

export type StructuredVaultProjectionErrorCode = 'invalid' | 'ambiguous' | 'collision';

/** Errors deliberately do not include record names or values. */
export class StructuredVaultProjectionError extends Error {
  public constructor(public readonly code: StructuredVaultProjectionErrorCode) {
    super(messageFor(code));
    this.name = 'StructuredVaultProjectionError';
  }
}

/** Return true only for a complete, currently supported structured payload. */
export function isStructuredVaultPayload(
  value: unknown,
): value is StructuredVaultPayload {
  return structuredVaultPayloadSchema.safeParse(value).success;
}

/** Return true only for a complete legacy flat payload. */
export function isLocalVaultPayload(value: unknown): value is LocalVaultPayload {
  return localVaultPayloadSchema.safeParse(value).success;
}

/**
 * Create the empty structured representation used by new database vaults.
 *
 * The parser adapter accepts both the draft `groups` spelling and the final
 * `services` spelling while the schemas are being migrated. The returned
 * value is always the canonical schema's parsed value.
 */
export function createEmptyStructuredVaultPayload(
  vaultIdInput: VaultId,
  atInput: Timestamp,
): StructuredVaultPayload {
  const vaultId = parseVaultId(vaultIdInput);
  const at = parseTimestamp(atInput);
  const context = {
    id: DEFAULT_PROJECT_CONTEXT_ID,
    name: DEFAULT_PROJECT_CONTEXT_NAME,
    environment: DEFAULT_PROJECT_CONTEXT_ENVIRONMENT,
    revision: 0,
    createdAt: at,
    updatedAt: at,
  };
  const service = defaultService(vaultId, at);
  return parseStructuredCandidate({
    vaultId,
    projectContexts: [context],
    services: [service],
    groups: [service],
    items: [],
    attachments: [],
    history: [],
  });
}

/**
 * Explicitly upgrade a legacy flat payload into the structured hierarchy.
 * Calling this function is the only compatibility operation that creates
 * structured records from a legacy payload.
 */
export function upgradeLegacyVaultPayload(
  flatInput: LocalVaultPayload,
  vaultIdInput: VaultId,
  atInput: Timestamp,
): StructuredVaultPayload {
  const flat = parseLocalPayload(flatInput);
  const vaultId = parseVaultId(vaultIdInput);
  const at = parseTimestamp(atInput);
  const empty = createEmptyStructuredVaultPayload(vaultId, at);
  const services = structuredServices(empty);
  const service = services.find((candidate) => candidate.id === DEFAULT_SERVICE_ID);
  if (service === undefined) projectionError('invalid');

  const items: Record<string, unknown>[] = [];
  for (const [name, record] of Object.entries(flat.records)) {
    assertExactName(name);
    const itemId = freshItemId();
    items.push(
      defaultItem(itemId, vaultId, service, name, record.value, record.updatedAt, at),
    );
  }

  return parseStructuredCandidate({
    ...asRecord(empty),
    items,
  });
}

/**
 * Project only active items in the default project/service into the legacy
 * record map. Non-default contexts, services, and items are intentionally
 * invisible to this compatibility view.
 */
export function projectFlatVaultPayload(
  databasePayloadInput: DatabaseVaultPayload,
): LocalVaultPayload {
  const databasePayload = parseDatabasePayload(databasePayloadInput);
  if (!isStructuredVaultPayload(databasePayload)) return cloneLocal(databasePayload);

  const defaultService = defaultServiceFor(databasePayload);
  if (defaultService === undefined) return { records: {} };

  const records: Record<string, { value: string; updatedAt: Timestamp }> = {};
  for (const item of structuredItems(databasePayload)) {
    if (item.groupId !== defaultService.id || item.deletedAt !== undefined) continue;
    const canonical = canonicalValue(item);
    if (canonical === undefined) projectionError('invalid');
    if (records[item.title] !== undefined) projectionError('collision');
    records[item.title] = canonical;
  }
  return parseLocalPayload({ records });
}

/**
 * Apply one legacy flat snapshot transition to the default structured
 * hierarchy. The current snapshot must equal the compatibility projection;
 * otherwise a caller would be asking us to infer an identity that the flat
 * format does not carry.
 */
export function applyFlatVaultPayload(
  structuredInput: StructuredVaultPayload,
  currentFlatInput: LocalVaultPayload,
  nextFlatInput: LocalVaultPayload,
  atInput: Timestamp,
): StructuredVaultPayload {
  const structured = parseStructuredPayload(structuredInput);
  const currentFlat = parseLocalPayload(currentFlatInput);
  const nextFlat = parseLocalPayload(nextFlatInput);
  const at = parseTimestamp(atInput);
  assertFlatEqual(projectFlatVaultPayload(structured), currentFlat);

  let working = cloneStructured(structured);
  let service = defaultServiceFor(working);
  const currentNames = Object.keys(currentFlat.records);
  const nextNames = Object.keys(nextFlat.records);
  const removed = currentNames.filter((name) => nextFlat.records[name] === undefined);
  const added = nextNames.filter((name) => currentFlat.records[name] === undefined);

  if (removed.length > 0 && added.length > 0) {
    if (removed.length !== 1 || added.length !== 1) projectionError('ambiguous');
    const oldName = removed[0];
    const newName = added[0];
    if (oldName === undefined || newName === undefined) {
      projectionError('ambiguous');
    }
    const oldRecord = currentFlat.records[oldName];
    const newRecord = nextFlat.records[newName];
    if (
      oldRecord === undefined ||
      newRecord === undefined ||
      !sameFlatRecord(oldRecord, newRecord)
    ) {
      projectionError('ambiguous');
    }
    assertExactName(newName);
    working = renameDefaultItem(working, service, oldName, newName, at);
    service = defaultServiceFor(working);
  }

  if (added.length > 0 && removed.length === 0) {
    if (service === undefined) {
      working = ensureDefaultHierarchy(working, at);
      service = defaultServiceFor(working);
    }
    if (service === undefined) projectionError('invalid');
    const activeService = service;
    for (const name of added) {
      assertExactName(name);
      const record = nextFlat.records[name];
      if (record === undefined) projectionError('invalid');
      const item = defaultItem(
        freshItemId(),
        structuredVaultId(working),
        activeService,
        name,
        record.value,
        record.updatedAt,
        at,
      );
      const candidate = asRecord(working);
      const items = [...structuredItems(working), item];
      candidate['items'] = items;
      working = parseStructuredCandidate(candidate);
      service = defaultServiceFor(working);
    }
  }

  for (const name of Object.keys(nextFlat.records)) {
    if (currentFlat.records[name] === undefined) continue;
    const current = currentFlat.records[name];
    const next = nextFlat.records[name];
    if (sameFlatRecord(current, next)) continue;
    if (next === undefined) projectionError('invalid');
    working = overwriteDefaultItem(
      working,
      service,
      name,
      next.value,
      next.updatedAt,
      at,
    );
    service = defaultServiceFor(working);
  }

  if (removed.length > 0 && added.length === 0) {
    for (const name of removed) {
      working = removeDefaultItem(working, service, name);
      service = defaultServiceFor(working);
    }
  }

  return parseStructuredPayload(working);
}

function messageFor(code: StructuredVaultProjectionErrorCode): string {
  switch (code) {
    case 'ambiguous':
      return 'Flat payload transition is ambiguous.';
    case 'collision':
      return 'Flat payload collides with structured identities.';
    case 'invalid':
      return 'Structured vault projection is invalid.';
  }
}

function projectionError(code: StructuredVaultProjectionErrorCode): never {
  throw new StructuredVaultProjectionError(code);
}

function parseVaultId(input: VaultId): VaultId {
  const parsed = vaultIdSchema.safeParse(input);
  if (!parsed.success) return projectionError('invalid');
  return parsed.data;
}

function parseTimestamp(input: Timestamp): Timestamp {
  const parsed = timestampSchema.safeParse(input);
  if (!parsed.success) return projectionError('invalid');
  return parsed.data;
}

function parseDatabasePayload(input: DatabaseVaultPayload): DatabaseVaultPayload {
  const parsed = databaseVaultPayloadSchema.safeParse(input);
  if (!parsed.success) return projectionError('invalid');
  return parsed.data;
}

function parseLocalPayload(input: LocalVaultPayload): LocalVaultPayload {
  const parsed = localVaultPayloadSchema.safeParse(input);
  if (!parsed.success) return projectionError('invalid');
  return parsed.data;
}

function parseStructuredPayload(input: unknown): StructuredVaultPayload {
  const parsed = structuredVaultPayloadSchema.safeParse(input);
  if (!parsed.success) return projectionError('invalid');
  return parsed.data;
}

/** Try final and draft collection spellings without maintaining another schema. */
function parseStructuredCandidate(input: unknown): StructuredVaultPayload {
  const record = asRecord(input);
  const projectContexts = record['projectContexts'];
  const items = record['items'];
  const attachments = record['attachments'];
  const history = record['history'];
  if (
    !Array.isArray(projectContexts) ||
    !Array.isArray(items) ||
    !Array.isArray(attachments) ||
    !Array.isArray(history)
  ) {
    return projectionError('invalid');
  }
  const vaultId = record['vaultId'];
  const services = record['services'];
  const groups = record['groups'];
  const base = {
    version: 1,
    projectContexts,
    items,
    attachments,
    history,
  };
  const candidates: unknown[] = [];
  if (Array.isArray(services)) {
    candidates.push({
      ...base,
      ...(vaultId === undefined ? {} : { vaultId }),
      services,
    });
  }
  if (Array.isArray(groups)) {
    candidates.push({ ...base, ...(vaultId === undefined ? {} : { vaultId }), groups });
  }
  if (Array.isArray(services)) candidates.push({ ...base, services });
  if (Array.isArray(groups)) candidates.push({ ...base, groups });
  for (const candidate of candidates) {
    const parsed = structuredVaultPayloadSchema.safeParse(candidate);
    if (parsed.success) return parsed.data;
  }
  return projectionError('invalid');
}

function asRecord(value: unknown): Record<string, unknown> {
  if (typeof value !== 'object' || value === null || Array.isArray(value)) {
    return projectionError('invalid');
  }
  return value as Record<string, unknown>;
}

function structuredServices(
  value: StructuredVaultPayload,
): readonly StructuredServicePayload[] {
  const record = asRecord(value);
  const services = record['services'];
  if (Array.isArray(services)) return services as StructuredServicePayload[];
  const groups = record['groups'];
  if (Array.isArray(groups)) return groups as StructuredServicePayload[];
  return projectionError('invalid');
}

function structuredItems(value: StructuredVaultPayload): readonly ItemPayload[] {
  const items = asRecord(value)['items'];
  if (!Array.isArray(items)) return projectionError('invalid');
  return items as ItemPayload[];
}

function structuredVaultId(value: StructuredVaultPayload): VaultId {
  const candidate = asRecord(value)['vaultId'];
  if (candidate !== undefined) return parseVaultId(candidate as VaultId);
  for (const service of structuredServices(value)) {
    const parsed = vaultIdSchema.safeParse(service.vaultId);
    if (parsed.success) return parsed.data;
  }
  for (const item of structuredItems(value)) {
    const parsed = vaultIdSchema.safeParse(item.vaultId);
    if (parsed.success) return parsed.data;
  }
  return projectionError('invalid');
}

function structuredAttachments(
  value: StructuredVaultPayload,
): readonly Record<string, unknown>[] {
  const attachments = asRecord(value)['attachments'];
  if (!Array.isArray(attachments)) return projectionError('invalid');
  return attachments as Record<string, unknown>[];
}

function structuredHistory(
  value: StructuredVaultPayload,
): readonly Record<string, unknown>[] {
  const history = asRecord(value)['history'];
  if (!Array.isArray(history)) return projectionError('invalid');
  return history as Record<string, unknown>[];
}

function structuredServicesKey(value: StructuredVaultPayload): 'services' | 'groups' {
  const record = asRecord(value);
  if (Array.isArray(record['services'])) return 'services';
  if (Array.isArray(record['groups'])) return 'groups';
  return projectionError('invalid');
}

function defaultServiceFor(
  value: StructuredVaultPayload,
): StructuredServicePayload | undefined {
  const contextsValue = asRecord(value)['projectContexts'];
  if (!Array.isArray(contextsValue)) projectionError('invalid');
  const contexts = contextsValue as readonly unknown[];
  const defaultContext = contexts.find(
    (context) => asRecord(context)['id'] === DEFAULT_PROJECT_CONTEXT_ID,
  );
  if (defaultContext !== undefined) {
    const contextRecord = asRecord(defaultContext);
    if (
      contextRecord['name'] !== DEFAULT_PROJECT_CONTEXT_NAME ||
      contextRecord['environment'] !== DEFAULT_PROJECT_CONTEXT_ENVIRONMENT
    ) {
      projectionError('collision');
    }
  }

  const defaultServices = structuredServices(value).filter(
    (service) => service.id === DEFAULT_SERVICE_ID,
  );
  if (defaultServices.length > 1) projectionError('collision');
  const service = defaultServices[0];
  if (service === undefined) return undefined;
  if (defaultContext === undefined) projectionError('invalid');
  if (
    service.projectContextId !== DEFAULT_PROJECT_CONTEXT_ID ||
    service.name !== DEFAULT_SERVICE_NAME ||
    service.template.id !== DEFAULT_TEMPLATE_ID ||
    service.template.name !== DEFAULT_TEMPLATE_NAME
  ) {
    projectionError('collision');
  }
  return service;
}

function defaultService(vaultId: VaultId, at: Timestamp): Record<string, unknown> {
  return {
    id: DEFAULT_SERVICE_ID,
    vaultId,
    projectContextId: DEFAULT_PROJECT_CONTEXT_ID,
    name: DEFAULT_SERVICE_NAME,
    aliases: [],
    tags: [],
    notes: [],
    template: {
      id: DEFAULT_TEMPLATE_ID,
      name: DEFAULT_TEMPLATE_NAME,
      version: 1,
      fields: [],
      createdAt: at,
      updatedAt: at,
    },
    sortOrder: 0,
    revision: 0,
    createdAt: at,
    updatedAt: at,
  };
}

function defaultItem(
  itemId: ReturnType<typeof itemIdSchema.parse>,
  vaultId: VaultId,
  service: StructuredServicePayload,
  title: string,
  value: string,
  valueUpdatedAt: Timestamp,
  at: Timestamp,
): Record<string, unknown> {
  const field = defaultValueField(at);
  const parsedValue = canonicalFieldValue(value);
  return {
    version: 1,
    id: itemId,
    vaultId,
    groupId: service.id,
    templateId: service.template.id,
    title,
    aliases: [],
    templateVersion: service.template.version,
    templateValues: [],
    itemFields: [field],
    itemValues: [
      {
        fieldId: field['id'],
        stableKey: DEFAULT_VALUE_FIELD_KEY,
        value: parsedValue,
        updatedAt: valueUpdatedAt,
      },
    ],
    archivedFieldValues: [],
    notes: [],
    tags: [],
    favorite: false,
    productionSensitive: true,
    relatedItemIds: [],
    attachmentIds: [],
    copySequences: [],
    revision: 0,
    createdAt: at,
    updatedAt: valueUpdatedAt,
  };
}

function defaultValueField(at: Timestamp): Record<string, unknown> {
  return {
    id: DEFAULT_VALUE_FIELD_ID,
    stableKey: DEFAULT_VALUE_FIELD_KEY,
    label: DEFAULT_VALUE_FIELD_LABEL,
    type: 'password',
    required: false,
    sensitive: true,
    repeatable: false,
    copyable: true,
    searchableLocally: false,
    showInPreview: false,
    copyPolicy: 'allowed',
    revealPolicy: 'timed',
    reauthenticationPolicy: 'after-lock',
    exportPolicy: 'guarded',
    sortOrder: 0,
    createdAt: at,
    updatedAt: at,
  };
}

function canonicalFieldValue(value: string): FieldValue {
  if (value.length === 0) {
    return fieldValueSchema.parse({ version: 1, state: 'empty' });
  }
  return fieldValueSchema.parse({
    version: 1,
    state: 'present',
    content: {
      cardinality: 'single',
      value: { kind: 'secret', value },
    },
  });
}

function canonicalValue(
  item: ItemPayload,
): { value: string; updatedAt: Timestamp } | undefined {
  const fields = item.itemFields.filter(
    (field) => field.stableKey === DEFAULT_VALUE_FIELD_KEY,
  );
  if (fields.length !== 1) return undefined;
  const field = fields[0];
  if (field === undefined) return undefined;
  if (
    field.id !== DEFAULT_VALUE_FIELD_ID ||
    field.type !== 'password' ||
    !field.sensitive ||
    field.repeatable ||
    !field.copyable ||
    field.copyPolicy === 'never' ||
    field.revealPolicy === 'never' ||
    field.reauthenticationPolicy === 'never' ||
    field.exportPolicy === 'never'
  ) {
    return undefined;
  }
  const values = item.itemValues.filter(
    (value) =>
      value.fieldId === field.id && value.stableKey === DEFAULT_VALUE_FIELD_KEY,
  );
  if (values.length !== 1) return undefined;
  const stored = values[0];
  if (stored === undefined) return undefined;
  if (stored.value.state === 'empty') {
    return { value: '', updatedAt: stored.updatedAt };
  }
  if (
    stored.value.state !== 'present' ||
    stored.value.content.cardinality !== 'single' ||
    stored.value.content.value.kind !== 'secret'
  )
    return undefined;
  return {
    value: stored.value.content.value.value,
    updatedAt: stored.updatedAt,
  };
}

function renameDefaultItem(
  value: StructuredVaultPayload,
  service: StructuredServicePayload | undefined,
  oldName: string,
  newName: string,
  at: Timestamp,
): StructuredVaultPayload {
  if (service === undefined) projectionError('invalid');
  const item = defaultItemByName(value, service, oldName);
  if (item === undefined) projectionError('invalid');
  if (defaultItemByName(value, service, newName) !== undefined) {
    projectionError('collision');
  }
  const updated = {
    ...item,
    title: newName,
    revision: item.revision + 1,
    updatedAt: at,
  };
  return replaceItem(value, item.id, updated);
}

function overwriteDefaultItem(
  value: StructuredVaultPayload,
  service: StructuredServicePayload | undefined,
  name: string,
  nextValue: string,
  nextUpdatedAt: Timestamp,
  at: Timestamp,
): StructuredVaultPayload {
  if (service === undefined) projectionError('invalid');
  const item = defaultItemByName(value, service, name);
  if (item === undefined) projectionError('invalid');
  if (canonicalValue(item) === undefined) projectionError('invalid');
  const itemValues = item.itemValues.map((stored) =>
    stored.stableKey === DEFAULT_VALUE_FIELD_KEY
      ? {
          ...stored,
          value: canonicalFieldValue(nextValue),
          updatedAt: nextUpdatedAt,
        }
      : stored,
  );
  const updated = {
    ...item,
    itemValues,
    revision: item.revision + 1,
    updatedAt: at,
  };
  return replaceItem(value, item.id, updated);
}

function removeDefaultItem(
  value: StructuredVaultPayload,
  service: StructuredServicePayload | undefined,
  name: string,
): StructuredVaultPayload {
  if (service === undefined) projectionError('invalid');
  const item = defaultItemByName(value, service, name);
  if (item === undefined) projectionError('invalid');
  const candidate = asRecord(cloneStructured(value));
  candidate['items'] = structuredItems(value).filter((entry) => entry.id !== item.id);
  candidate['attachments'] = structuredAttachments(value).filter(
    (attachment) => attachment['itemId'] !== item.id,
  );
  candidate['history'] = structuredHistory(value).filter(
    (record) => record['itemId'] !== item.id,
  );
  return parseStructuredPayload(candidate);
}

function defaultItemByName(
  value: StructuredVaultPayload,
  service: StructuredServicePayload,
  name: string,
): ItemPayload | undefined {
  const matches = structuredItems(value).filter(
    (item) =>
      item.groupId === service.id &&
      item.deletedAt === undefined &&
      item.title === name,
  );
  if (matches.length > 1) projectionError('collision');
  const item = matches[0];
  if (item !== undefined && canonicalValue(item) === undefined) {
    projectionError('invalid');
  }
  return item;
}

function replaceItem(
  value: StructuredVaultPayload,
  itemId: string,
  updated: Record<string, unknown>,
): StructuredVaultPayload {
  const candidate = asRecord(cloneStructured(value));
  candidate['items'] = structuredItems(value).map((item) =>
    item.id === itemId ? updated : item,
  );
  return parseStructuredPayload(candidate);
}

function ensureDefaultHierarchy(
  value: StructuredVaultPayload,
  at: Timestamp,
): StructuredVaultPayload {
  const candidate = asRecord(cloneStructured(value));
  const projectContexts = candidate['projectContexts'];
  const contexts = Array.isArray(projectContexts)
    ? (projectContexts as readonly unknown[]).slice()
    : [];
  if (
    !contexts.some((context) => asRecord(context)['id'] === DEFAULT_PROJECT_CONTEXT_ID)
  ) {
    contexts.push({
      id: DEFAULT_PROJECT_CONTEXT_ID,
      name: DEFAULT_PROJECT_CONTEXT_NAME,
      environment: DEFAULT_PROJECT_CONTEXT_ENVIRONMENT,
      revision: 0,
      createdAt: at,
      updatedAt: at,
    });
  }
  candidate['projectContexts'] = contexts;
  const key = structuredServicesKey(value);
  const services = [...structuredServices(value)];
  if (!services.some((service) => service.id === DEFAULT_SERVICE_ID)) {
    services.push(
      defaultService(structuredVaultId(value), at) as StructuredServicePayload,
    );
  } else if (
    services.some(
      (service) =>
        service.id === DEFAULT_SERVICE_ID &&
        service.projectContextId !== DEFAULT_PROJECT_CONTEXT_ID,
    )
  ) {
    projectionError('collision');
  }
  candidate[key] = services;
  return parseStructuredPayload(candidate);
}

function freshItemId(): ReturnType<typeof itemIdSchema.parse> {
  const parsed = itemIdSchema.safeParse(`item_${randomUUID()}`);
  if (!parsed.success) return projectionError('invalid');
  return parsed.data;
}

function cloneStructured(value: StructuredVaultPayload): StructuredVaultPayload {
  return structuredClone(value);
}

function cloneLocal(value: LocalVaultPayload): LocalVaultPayload {
  return structuredClone(value);
}

function assertExactName(name: string): void {
  if (name.length === 0 || name.trim() !== name) projectionError('invalid');
}

function sameFlatRecord(
  left: LocalVaultPayload['records'][string] | undefined,
  right: LocalVaultPayload['records'][string] | undefined,
): boolean {
  const leftValue = left?.value;
  const rightValue = right?.value;
  const leftUpdatedAt = left?.updatedAt;
  const rightUpdatedAt = right?.updatedAt;
  return (
    left !== undefined &&
    right !== undefined &&
    leftValue === rightValue &&
    leftUpdatedAt === rightUpdatedAt
  );
}

function assertFlatEqual(expected: LocalVaultPayload, actual: LocalVaultPayload): void {
  const expectedNames = Object.keys(expected.records);
  const actualNames = Object.keys(actual.records);
  if (expectedNames.length !== actualNames.length) projectionError('invalid');
  for (const name of expectedNames) {
    const left = expected.records[name];
    const right = actual.records[name];
    if (!sameFlatRecord(left, right)) projectionError('invalid');
  }
}
