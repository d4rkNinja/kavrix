import {
  syncCursorSchema,
  syncPullQuerySchema,
  syncPushRequestSchema,
  templateMigrationPublicationRequestSchema,
  vaultPathSchema,
  type SyncPushRequest,
  type SyncPushResponse,
  type TemplateMigrationPublicationRequest,
  type TemplateMigrationPublicationResponse,
} from '@kavrix/schemas';
import { SyncConflictError } from '@kavrix/core';

import { parseRequest } from '../boundary.js';
import { ApiAtomicPublicationConflictError, ApiValidationError } from '../errors.js';
import type { ApiRoutePlugin } from '../route-context.js';
import { requireMutationVault } from '../route-utils.js';
import {
  validatePullPage,
  validatePushBatch,
  validateTemplateMigrationPublication,
} from '../sync-validation.js';
import { assertSafeGenericVaultMutation } from '../vault-policy.js';

export const syncRoutes: ApiRoutePlugin = (app, context) => {
  app.get('/v1/vaults/:vaultId/sync', async (request) => {
    const { vaultId } = parseRequest(vaultPathSchema, request.params);
    await context.security.authenticate(request, 'sync:read', vaultId);
    const query = parseRequest(syncPullQuerySchema, request.query);
    const cursor = syncCursorSchema.parse({
      vaultId,
      serverSequence: query.serverSequence,
      highestSeenVaultRevision: query.highestSeenVaultRevision,
    });
    const page = await context.ports.storage.pullSyncPage(cursor, query.limit);
    return validatePullPage(page, vaultId, cursor, query.limit);
  });

  app.post('/v1/vaults/:vaultId/sync', async (request, reply) => {
    const { vaultId } = parseRequest(vaultPathSchema, request.params);
    await context.security.authenticate(request, 'sync:write', vaultId);
    const body = parseRequest(syncPushRequestSchema, request.body);
    if (body.vaultId !== vaultId) {
      throw new ApiValidationError();
    }
    const mutations = body.mutations.map((mutation) =>
      requireMutationVault(mutation, vaultId),
    );
    await assertSafeGenericVaultMutation(context.ports.storage, mutations, vaultId);
    const batch: SyncPushRequest = { ...body, mutations };
    const result: SyncPushResponse = await context.ports.storage.pushSyncBatch(batch);
    return reply.status(200).send(validatePushBatch(result, batch));
  });

  app.post('/v1/vaults/:vaultId/template-migrations', async (request, reply) => {
    const { vaultId } = parseRequest(vaultPathSchema, request.params);
    await context.security.authenticate(request, 'sync:write', vaultId);
    const body = parseRequest(templateMigrationPublicationRequestSchema, request.body);
    if (body.vaultId !== vaultId) throw new ApiValidationError();
    const batch: TemplateMigrationPublicationRequest = body;
    let result: TemplateMigrationPublicationResponse;
    try {
      result = await context.ports.storage.publishTemplateMigration(batch);
    } catch (error) {
      if (error instanceof SyncConflictError) {
        throw new ApiAtomicPublicationConflictError();
      }
      throw error;
    }
    return reply.status(200).send(validateTemplateMigrationPublication(result, batch));
  });
  return Promise.resolve();
};
