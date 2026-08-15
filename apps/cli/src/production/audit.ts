import { NotFoundError } from '@kavrix/core';
import {
  localAuditEventSchema,
  type AuditEventClass,
  type KeySlot,
  type LocalAuditEvent,
  type OpaqueMutation,
  type VaultId,
  type VaultRecord,
} from '@kavrix/schemas';

import type { CliAuditEventDetail, CliAuditEventPage } from '../contracts.js';
import { CliUsageError } from '../errors.js';
import {
  DEFAULT_AUDIT_EVENT_PAGE_SIZE,
  type CliListAuditEventsRequest,
  type CliShowAuditEventRequest,
} from '../mutation-contracts.js';

/**
 * Local projection source. The API and MongoDB store audit records as opaque
 * sidecars and never return them, so the authorized device derives the feed
 * from state it already holds locally.
 */
export interface AuditProjectionSourcePort {
  getVault(vaultId: VaultId): Promise<VaultRecord | null>;
  listPendingMutations(vaultId: VaultId): Promise<readonly OpaqueMutation[]>;
}

export interface AuditProjectionOptions {
  readonly source: AuditProjectionSourcePort;
  readonly vaultId: VaultId;
}

/**
 * Maps one unlock-slot type onto its coarse audit class. Device and recovery
 * slots are reported under their own classes so operators can filter them
 * without inspecting slot internals.
 */
function classifySlot(slot: KeySlot): AuditEventClass {
  switch (slot.type) {
    case 'device-key':
      return 'device';
    case 'recovery-key':
      return 'recovery';
    case 'portable-key':
    case 'passphrase':
      return 'slot';
  }
}

/** Opaque identifier of the entity a queued mutation targets. */
function mutationSubject(mutation: OpaqueMutation): string {
  return mutation.record.id;
}

/**
 * Target revision of a queued mutation. The vault record versions itself with
 * `revision`; every other opaque record uses `recordRevision`.
 */
function mutationRevision(mutation: OpaqueMutation): number {
  return mutation.entityType === 'vault'
    ? mutation.record.revision
    : mutation.record.recordRevision;
}

/**
 * Projects the lifecycle of one unlock slot. `state` always records the slot
 * state the event itself established, so it is omitted from the creation event
 * of a slot that later transitioned: the state at creation time is not retained
 * locally and is never inferred from the slot's current state.
 */
function slotEvents(slot: KeySlot): readonly LocalAuditEvent[] {
  const eventClass = classifySlot(slot);
  const base = {
    version: 1,
    eventClass,
    subject: slot.id,
    keyVersion: slot.keyVersion,
    ...(slot.type === 'device-key' ? { deviceId: slot.deviceId } : {}),
  } as const;
  const transitioned = slot.supersededAt !== undefined || slot.revokedAt !== undefined;

  const events: LocalAuditEvent[] = [
    localAuditEventSchema.parse({
      ...base,
      eventId: `audit.slot.${slot.id}.create`,
      action: 'create',
      occurredAt: slot.createdAt,
      ...(transitioned ? {} : { state: slot.state }),
    }),
  ];
  if (slot.supersededAt !== undefined) {
    events.push(
      localAuditEventSchema.parse({
        ...base,
        eventId: `audit.slot.${slot.id}.supersede`,
        action: 'supersede',
        occurredAt: slot.supersededAt,
        state: 'superseded',
      }),
    );
  }
  if (slot.revokedAt !== undefined) {
    events.push(
      localAuditEventSchema.parse({
        ...base,
        eventId: `audit.slot.${slot.id}.revoke`,
        action: 'revoke',
        occurredAt: slot.revokedAt,
        state: 'revoked',
      }),
    );
  }
  return events;
}

function mutationEvent(mutation: OpaqueMutation): LocalAuditEvent {
  const subject = mutationSubject(mutation);
  const revision = mutationRevision(mutation);
  return localAuditEventSchema.parse({
    version: 1,
    eventId: `audit.mutation.${subject}.r${String(revision)}`,
    eventClass: 'mutation',
    action: 'queue',
    subject,
    occurredAt: mutation.record.updatedAt,
    recordRevision: revision,
  });
}

/**
 * Deterministic newest-first ordering. Identifiers break timestamp ties so the
 * feed and its cursors stay stable across invocations.
 */
function compareEvents(left: LocalAuditEvent, right: LocalAuditEvent): number {
  if (left.occurredAt !== right.occurredAt) {
    return left.occurredAt < right.occurredAt ? 1 : -1;
  }
  if (left.eventId === right.eventId) return 0;
  return left.eventId < right.eventId ? -1 : 1;
}

/**
 * Builds the complete ordered projection. `backup` events have no local
 * persisted source today: archive creation writes only the archive itself, so
 * the class is accepted as a filter and yields nothing rather than inventing a
 * record.
 */
export async function buildLocalAuditProjection(
  options: AuditProjectionOptions,
): Promise<readonly LocalAuditEvent[]> {
  const vault = await options.source.getVault(options.vaultId);
  if (vault === null) throw new NotFoundError();
  const pending = await options.source.listPendingMutations(options.vaultId);

  const events = [
    ...vault.keySlots.flatMap((slot) => slotEvents(slot)),
    ...pending.map((mutation) => mutationEvent(mutation)),
  ];
  return events.sort(compareEvents);
}

export async function executeProductionListAuditEvents(
  options: AuditProjectionOptions,
  request: CliListAuditEventsRequest,
): Promise<CliAuditEventPage> {
  const projection = await buildLocalAuditProjection(options);
  const matching =
    request.eventClass === undefined
      ? projection
      : projection.filter((event) => event.eventClass === request.eventClass);

  let start = 0;
  if (request.cursor !== undefined) {
    const index = matching.findIndex((event) => event.eventId === request.cursor);
    if (index < 0) {
      throw new CliUsageError('The audit page cursor does not match this projection.');
    }
    start = index + 1;
  }

  const limit = request.limit ?? DEFAULT_AUDIT_EVENT_PAGE_SIZE;
  const events = matching.slice(start, start + limit);
  const consumed = start + events.length;
  const last = events.at(-1);
  return {
    events,
    nextCursor: consumed < matching.length && last !== undefined ? last.eventId : null,
    totalCount: matching.length,
  };
}

export async function executeProductionShowAuditEvent(
  options: AuditProjectionOptions,
  request: CliShowAuditEventRequest,
): Promise<CliAuditEventDetail> {
  const projection = await buildLocalAuditProjection(options);
  const event = projection.find((candidate) => candidate.eventId === request.eventId);
  if (event === undefined) throw new NotFoundError();
  return { vaultId: options.vaultId, event };
}
