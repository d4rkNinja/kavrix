import {
  deviceListResponseSchema,
  vaultDevicePathSchema,
  vaultPathSchema,
} from '@kavrix/schemas';

import { parseRequest } from '../boundary.js';
import { ApiNotFoundError } from '../errors.js';
import type { ApiRoutePlugin } from '../route-context.js';
import { timestamp } from '../route-utils.js';

export const deviceRoutes: ApiRoutePlugin = (app, context) => {
  app.get('/v1/vaults/:vaultId/devices', async (request) => {
    const { vaultId } = parseRequest(vaultPathSchema, request.params);
    await context.security.authenticate(request, 'device:manage', vaultId);
    const devices = await context.ports.authorization.listDevices(vaultId);
    return deviceListResponseSchema.parse({
      devices: devices.map((device) => {
        if (device.vaultId !== vaultId) {
          throw new Error('Authorization storage crossed a vault boundary');
        }
        const { tokenHash, ...publicDevice } = device;
        void tokenHash;
        return publicDevice;
      }),
    });
  });

  app.delete('/v1/vaults/:vaultId/devices/:deviceId', async (request, reply) => {
    const { vaultId, deviceId } = parseRequest(vaultDevicePathSchema, request.params);
    await context.security.authenticate(request, 'device:manage', vaultId);
    const revoked = await context.ports.authorization.revokeDevice(
      vaultId,
      deviceId,
      timestamp(context.ports.clock.now()),
    );
    if (!revoked) {
      throw new ApiNotFoundError();
    }
    return reply.status(204).send();
  });
  return Promise.resolve();
};
