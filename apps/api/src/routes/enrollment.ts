import {
  apiSessionResponseSchema,
  deviceRecordSchema,
  enrollmentCompleteRequestSchema,
  enrollmentCompleteResponseSchema,
  inviteIssueRequestSchema,
  inviteIssueResponseSchema,
  inviteListResponseSchema,
  inviteRedeemResponseSchema,
  vaultRecordSchema,
  vaultPathSchema,
  vaultInvitePathSchema,
} from '@kavrix/schemas';

import { parseRequest, successorToken } from '../boundary.js';
import {
  ApiAuthenticationError,
  ApiAuthorizationError,
  ApiNotFoundError,
} from '../errors.js';
import type { ApiRoutePlugin } from '../route-context.js';
import { addSeconds, timestamp } from '../route-utils.js';

export const enrollmentRoutes: ApiRoutePlugin = (app, context) => {
  app.get('/v1/session', async (request) => {
    const principal = await context.security.authenticate(request);
    return apiSessionResponseSchema.parse(principal);
  });

  app.post('/v1/vaults/:vaultId/invites', async (request, reply) => {
    const { vaultId } = parseRequest(vaultPathSchema, request.params);
    const principal = await context.security.authenticate(
      request,
      'device:manage',
      vaultId,
    );
    const body = parseRequest(inviteIssueRequestSchema, request.body);
    if (body.scopes.some((scope) => !principal.scopes.includes(scope))) {
      throw new ApiAuthorizationError();
    }
    const now = context.ports.clock.now();
    const expiresAt = addSeconds(now, body.expiresInSeconds);
    const inviteId = context.ports.inviteIds.next();
    const issued = await context.ports.tokens.issue();
    await context.ports.authorization.createInvite({
      id: inviteId,
      tokenHash: issued.hash,
      vaultId,
      scopes: body.scopes,
      issuedByDeviceId: principal.deviceId,
      createdAt: timestamp(now),
      expiresAt,
    });
    return reply.status(201).send(
      inviteIssueResponseSchema.parse({
        inviteId,
        inviteToken: issued.token,
        expiresAt,
      }),
    );
  });

  app.get('/v1/vaults/:vaultId/invites', async (request) => {
    const { vaultId } = parseRequest(vaultPathSchema, request.params);
    await context.security.authenticate(request, 'device:manage', vaultId);
    const invites = await context.ports.authorization.listInvites(
      vaultId,
      context.ports.clock.now(),
    );
    return inviteListResponseSchema.parse({
      invites: invites.map((invite) => {
        if (invite.vaultId !== vaultId) {
          throw new Error('Authorization storage crossed an invite vault boundary');
        }
        return invite;
      }),
    });
  });

  app.delete('/v1/vaults/:vaultId/invites/:inviteId', async (request, reply) => {
    const { vaultId, inviteId } = parseRequest(vaultInvitePathSchema, request.params);
    await context.security.authenticate(request, 'device:manage', vaultId);
    const revoked = await context.ports.authorization.revokeInvite(
      vaultId,
      inviteId,
      timestamp(context.ports.clock.now()),
    );
    if (!revoked) throw new ApiNotFoundError();
    return reply.status(204).send();
  });

  app.post('/v1/invites/redeem', async (request) => {
    const inviteHash = await context.security.authenticateOneTimeToken(
      request,
      'invite',
    );
    const enrollmentTokenHash = await context.ports.tokens.hash(
      successorToken(request),
    );
    if (enrollmentTokenHash === inviteHash) throw new ApiAuthenticationError();
    const now = context.ports.clock.now();
    const requestedExpiry = addSeconds(now, context.enrollmentLifetimeSeconds);
    const redemption = await context.ports.authorization.redeemInvite(
      inviteHash,
      enrollmentTokenHash,
      requestedExpiry,
      now,
    );
    if (redemption === null) {
      throw new ApiAuthenticationError();
    }
    const storedVault = await context.ports.storage.getVault(redemption.vaultId);
    const parsedVault = vaultRecordSchema.safeParse(storedVault);
    if (!parsedVault.success || parsedVault.data.id !== redemption.vaultId) {
      throw new ApiAuthenticationError();
    }
    return inviteRedeemResponseSchema.parse({
      vaultId: redemption.vaultId,
      expiresAt: redemption.enrollmentExpiresAt,
      vault: parsedVault.data,
    });
  });

  app.post('/v1/enrollments/complete', async (request, reply) => {
    const enrollmentHash = await context.security.authenticateOneTimeToken(
      request,
      'enrollment',
    );
    const body = parseRequest(enrollmentCompleteRequestSchema, request.body);
    const sessionTokenHash = await context.ports.tokens.hash(successorToken(request));
    if (sessionTokenHash === enrollmentHash) throw new ApiAuthenticationError();
    const device = await context.ports.authorization.completeEnrollment(
      enrollmentHash,
      {
        vaultId: body.vaultId,
        deviceId: body.deviceId,
        schemaVersion: body.schemaVersion,
        ...(body.encryptedLabel === undefined
          ? {}
          : { encryptedLabel: body.encryptedLabel }),
        sessionTokenHash,
      },
      context.ports.clock.now(),
    );
    if (device === null) {
      throw new ApiAuthenticationError();
    }
    const parsedDevice = deviceRecordSchema.parse(device);
    if (
      parsedDevice.vaultId !== body.vaultId ||
      parsedDevice.id !== body.deviceId ||
      parsedDevice.tokenHash !== sessionTokenHash
    ) {
      throw new Error('Authorization storage returned a different enrollment');
    }
    return reply.status(201).send(
      enrollmentCompleteResponseSchema.parse({
        vaultId: parsedDevice.vaultId,
        deviceId: parsedDevice.id,
      }),
    );
  });
  return Promise.resolve();
};
