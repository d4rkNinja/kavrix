import {
  controlListPageQuerySchema,
  decodeControlListCursor,
  deviceListPageResponseSchema,
  vaultDevicePathSchema,
  vaultPathSchema,
} from '@kavrix/schemas';

import { parseRequest } from '../boundary.js';
import {
  ApiAuthorizationError,
  ApiNotFoundError,
  ApiValidationError,
} from '../errors.js';
import type { ApiRoutePlugin } from '../route-context.js';
import { timestamp } from '../route-utils.js';

export const deviceRoutes: ApiRoutePlugin = (app, context) => {
  app.get('/v1/vaults/:vaultId/devices', async (request) => {
    const { vaultId } = parseRequest(vaultPathSchema, request.params);
    await context.security.authenticate(request, 'device:manage', vaultId);
    const options = parseRequest(controlListPageQuerySchema, request.query);
    assertDeviceRequestCursorContext(options.cursor, vaultId);
    const page = await context.ports.authorization.listDevicePage(vaultId, options);
    const devices = page.devices.map((device) => {
      if (device.vaultId !== vaultId) {
        throw new Error('Authorization storage crossed a vault boundary');
      }
      const { tokenHash, ...publicDevice } = device;
      void tokenHash;
      return publicDevice;
    });
    assertDeviceCursorContext(page.nextCursor, vaultId);
    return deviceListPageResponseSchema.parse({
      devices,
      nextCursor: page.nextCursor,
    });
  });

  app.delete('/v1/vaults/:vaultId/devices/:deviceId', async (request, reply) => {
    const { vaultId, deviceId } = parseRequest(vaultDevicePathSchema, request.params);
    await context.security.authenticate(request, 'device:manage', vaultId);
    const result = await context.ports.authorization.revokeDevice(
      vaultId,
      deviceId,
      timestamp(context.ports.clock.now()),
    );
    if (result === 'not-found') {
      throw new ApiNotFoundError();
    }
    if (result === 'last-active-device') {
      throw new ApiAuthorizationError();
    }
    return reply.status(204).send();
  });
  return Promise.resolve();
};

function assertDeviceCursorContext(
  cursor: string | null | undefined,
  vaultId: string,
): void {
  if (cursor === null || cursor === undefined) return;
  const payload = decodeControlListCursor(cursor);
  if (payload.resource !== 'devices' || payload.vaultId !== vaultId) {
    throw new Error('Authorization storage returned a misbound control-list cursor');
  }
}

function assertDeviceRequestCursorContext(
  cursor: string | null | undefined,
  vaultId: string,
): void {
  if (cursor === null || cursor === undefined) return;
  const payload = decodeControlListCursor(cursor);
  if (payload.resource !== 'devices' || payload.vaultId !== vaultId) {
    throw new ApiValidationError();
  }
}
