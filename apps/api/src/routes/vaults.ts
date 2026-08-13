import { isDeepStrictEqual } from 'node:util';

import {
  opaqueMutationRequestSchema,
  vaultKeySlotPathSchema,
  vaultKeySlotUpdateRequestSchema,
  vaultPathSchema,
  vaultRecordSchema,
  type KeySlotId,
  type VaultRecord,
} from '@kavrix/schemas';

import { parseRequest } from '../boundary.js';
import { ApiNotFoundError, ApiValidationError } from '../errors.js';
import type { ApiRoutePlugin } from '../route-context.js';
import { commitOpaqueMutation, requireMutationVault } from '../route-utils.js';
import { assertSafeGenericVaultMutation } from '../vault-policy.js';

export const vaultRoutes: ApiRoutePlugin = (app, context) => {
  app.get('/v1/vaults/:vaultId', async (request) => {
    const { vaultId } = parseRequest(vaultPathSchema, request.params);
    await context.security.authenticate(request, 'sync:read', vaultId);
    const storedVault = await context.ports.storage.getVault(vaultId);
    if (storedVault === null) {
      throw new ApiNotFoundError();
    }
    const vault = vaultRecordSchema.parse(storedVault);
    if (vault.id !== vaultId) {
      throw new Error('Storage returned a vault outside the requested boundary');
    }
    return vault;
  });

  app.put('/v1/vaults/:vaultId/records', async (request, reply) => {
    const { vaultId } = parseRequest(vaultPathSchema, request.params);
    await context.security.authenticate(request, 'sync:write', vaultId);
    const mutation = requireMutationVault(
      parseRequest(opaqueMutationRequestSchema, request.body),
      vaultId,
    );
    await assertSafeGenericVaultMutation(context.ports.storage, [mutation], vaultId);
    await commitOpaqueMutation(context.ports.storage, mutation);
    return reply.status(204).send();
  });

  app.put('/v1/vaults/:vaultId/key-slots/:slotId', async (request, reply) => {
    const { vaultId, slotId } = parseRequest(vaultKeySlotPathSchema, request.params);
    await context.security.authenticate(request, 'device:manage', vaultId);
    const body = parseRequest(vaultKeySlotUpdateRequestSchema, request.body);
    const current = await currentVault(context, vaultId);
    const slot = body.record.keySlots.find((candidate) => candidate.id === slotId);
    if (
      body.record.id !== vaultId ||
      slot === undefined ||
      slot.state === 'revoked' ||
      slot.state === 'superseded'
    ) {
      throw new ApiValidationError();
    }
    assertSlotPublish(current, body.record, slotId, body.expectedVaultRevision);
    const mutation = {
      entityType: 'vault',
      expectedVaultRevision: body.expectedVaultRevision,
      idempotencyKey: body.idempotencyKey,
      record: body.record,
    } as const;
    if (body.audit === undefined) {
      await commitOpaqueMutation(context.ports.storage, mutation);
    } else {
      await context.ports.storage.commitKeySlotMutation(mutation, body.audit);
    }
    return reply.status(204).send();
  });

  app.delete('/v1/vaults/:vaultId/key-slots/:slotId', async (request, reply) => {
    const { vaultId, slotId } = parseRequest(vaultKeySlotPathSchema, request.params);
    await context.security.authenticate(request, 'device:manage', vaultId);
    const body = parseRequest(vaultKeySlotUpdateRequestSchema, request.body);
    const current = await currentVault(context, vaultId);
    const slot = body.record.keySlots.find((candidate) => candidate.id === slotId);
    if (body.record.id !== vaultId || slot?.state !== 'revoked') {
      throw new ApiValidationError();
    }
    assertSlotRevocation(current, body.record, slotId, body.expectedVaultRevision);
    const mutation = {
      entityType: 'vault',
      expectedVaultRevision: body.expectedVaultRevision,
      idempotencyKey: body.idempotencyKey,
      record: body.record,
    } as const;
    if (body.audit === undefined) {
      await commitOpaqueMutation(context.ports.storage, mutation);
    } else {
      await context.ports.storage.commitKeySlotMutation(mutation, body.audit);
    }
    return reply.status(204).send();
  });
  return Promise.resolve();
};

async function currentVault(
  context: Parameters<ApiRoutePlugin>[1],
  vaultId: VaultRecord['id'],
): Promise<VaultRecord> {
  const stored = await context.ports.storage.getVault(vaultId);
  if (stored === null) throw new ApiNotFoundError();
  const current = vaultRecordSchema.parse(stored);
  if (current.id !== vaultId) {
    throw new Error('Storage returned a vault outside the requested boundary');
  }
  return current;
}

function assertSlotPublish(
  current: VaultRecord,
  next: VaultRecord,
  slotId: KeySlotId,
  expectedRevision: number,
): void {
  assertOnlyAddressedSlotChanged(current, next, slotId, expectedRevision);
  const previous = current.keySlots.find((slot) => slot.id === slotId);
  const replacement = next.keySlots.find((slot) => slot.id === slotId);
  if (replacement === undefined) throw new ApiValidationError();
  if (previous === undefined) {
    if (next.keySlots.length !== current.keySlots.length + 1) {
      throw new ApiValidationError();
    }
    return;
  }
  if (
    previous.state !== 'pending' ||
    replacement.state !== 'active' ||
    !isDeepStrictEqual(slotWithoutState(previous), slotWithoutState(replacement))
  ) {
    throw new ApiValidationError();
  }
}

function assertSlotRevocation(
  current: VaultRecord,
  next: VaultRecord,
  slotId: KeySlotId,
  expectedRevision: number,
): void {
  assertOnlyAddressedSlotChanged(current, next, slotId, expectedRevision);
  const previous = current.keySlots.find((slot) => slot.id === slotId);
  const replacement = next.keySlots.find((slot) => slot.id === slotId);
  if (
    previous === undefined ||
    previous.state === 'revoked' ||
    previous.state === 'superseded' ||
    replacement?.state !== 'revoked' ||
    !isDeepStrictEqual(
      slotWithoutLifecycle(previous),
      slotWithoutLifecycle(replacement),
    )
  ) {
    throw new ApiValidationError();
  }
}

function assertOnlyAddressedSlotChanged(
  current: VaultRecord,
  next: VaultRecord,
  slotId: KeySlotId,
  expectedRevision: number,
): void {
  if (
    expectedRevision !== current.revision ||
    next.revision !== current.revision + 1 ||
    Date.parse(next.updatedAt) < Date.parse(current.updatedAt) ||
    !isDeepStrictEqual(vaultStableFields(current), vaultStableFields(next)) ||
    !isDeepStrictEqual(
      current.keySlots.filter((slot) => slot.id !== slotId),
      next.keySlots.filter((slot) => slot.id !== slotId),
    )
  ) {
    throw new ApiValidationError();
  }
}

function vaultStableFields(vault: VaultRecord): object {
  return {
    id: vault.id,
    schemaVersion: vault.schemaVersion,
    cryptographicVersion: vault.cryptographicVersion,
    currentKeyVersion: vault.currentKeyVersion,
    encryptedPreferences: vault.encryptedPreferences,
    createdAt: vault.createdAt,
  };
}

function slotWithoutState(slot: VaultRecord['keySlots'][number]): object {
  const { state, ...stable } = slot;
  void state;
  return stable;
}

function slotWithoutLifecycle(slot: VaultRecord['keySlots'][number]): object {
  const { state, revokedAt, ...stable } = slot;
  void state;
  void revokedAt;
  return stable;
}
