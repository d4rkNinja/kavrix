import { randomUUID } from 'node:crypto';
import {
  canonicalJson,
  historyIdSchema,
  itemPayloadSchema,
  structuredVaultPayloadSchema,
  type DatabaseVaultPayload,
  type StructuredVaultPayload,
  type Timestamp,
} from '@kavrix/schemas';
import { isStructuredVaultPayload } from './structured-vault-projection.js';
import { credentialMissing, securityIntegrityFailure } from './execution/exit-codes.js';

export function recordItemSnapshots(
  before: StructuredVaultPayload,
  after: StructuredVaultPayload,
  at: Timestamp,
): StructuredVaultPayload;
export function recordItemSnapshots(
  before: DatabaseVaultPayload,
  after: DatabaseVaultPayload,
  at: Timestamp,
): DatabaseVaultPayload;
/** Runs inside the same optimistic database mutation as the content edit. */
export function recordItemSnapshots(
  before: DatabaseVaultPayload,
  after: DatabaseVaultPayload,
  at: Timestamp,
): DatabaseVaultPayload {
  if (!isStructuredVaultPayload(before) || !isStructuredVaultPayload(after))
    return after;
  const nextItems = new Map(after.items.map((item) => [item.id, item]));
  const snapshots = [...(after.snapshots ?? before.snapshots ?? [])].filter(
    (snapshot) => nextItems.has(snapshot.item.id),
  );
  for (const item of before.items) {
    const next = nextItems.get(item.id);
    if (next === undefined || canonicalJson(item) === canonicalJson(next)) continue;
    snapshots.push({
      version: 1,
      id: historyIdSchema.parse(`history_${randomUUID()}`),
      createdAt: at,
      item: structuredClone(item),
    });
  }
  if (snapshots.length === 0)
    return after.snapshots === undefined
      ? after
      : structuredVaultPayloadSchema.parse({ ...after, snapshots: [] });
  const counts = new Map<string, number>();
  const retained = snapshots
    .slice()
    .reverse()
    .filter((snapshot) => {
      const count = (counts.get(snapshot.item.id) ?? 0) + 1;
      counts.set(snapshot.item.id, count);
      return count <= 100;
    })
    .reverse();
  return structuredVaultPayloadSchema.parse({
    ...after,
    version: 2,
    snapshots: retained.slice(-10_000),
  });
}

/** Restores content as a fresh revision; unresolved relationships fail closed. */
export function restoreItemSnapshot(
  payload: StructuredVaultPayload,
  contextName: string,
  serviceName: string,
  title: string,
  id: string,
  at: Timestamp,
): StructuredVaultPayload {
  const context = payload.projectContexts.find((entry) => entry.name === contextName);
  const group = payload.groups.find(
    (entry) =>
      entry.projectContextId === context?.id &&
      entry.name === serviceName &&
      entry.deletedAt === undefined,
  );
  const current = payload.items.find(
    (entry) =>
      entry.groupId === group?.id &&
      entry.title === title &&
      entry.deletedAt === undefined,
  );
  if (context === undefined || group === undefined || current === undefined)
    throw credentialMissing();
  const snapshot = payload.snapshots?.find(
    (entry) => entry.id === id && entry.item.id === current.id,
  );
  if (snapshot === undefined) throw credentialMissing();
  const old = snapshot.item;
  if (
    old.vaultId !== payload.vaultId ||
    old.groupId !== group.id ||
    old.templateId !== group.template.id ||
    old.attachmentIds.some(
      (attachmentId) =>
        !payload.attachments.some((attachment) => attachment.id === attachmentId),
    ) ||
    old.relatedItemIds.some(
      (itemId) => !payload.items.some((item) => item.id === itemId),
    )
  ) {
    throw securityIntegrityFailure(
      'Snapshot relationships no longer resolve; restore refused.',
    );
  }
  const restored = itemPayloadSchema.parse({
    ...old,
    title: current.title,
    revision: current.revision + 1,
    updatedAt: at,
  });
  return structuredVaultPayloadSchema.parse({
    ...payload,
    items: payload.items.map((item) => (item.id === current.id ? restored : item)),
  });
}
