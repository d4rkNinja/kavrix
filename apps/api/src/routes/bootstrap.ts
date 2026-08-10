import {
  vaultBootstrapRequestSchema,
  vaultBootstrapResponseSchema,
} from '@kavrix/schemas';

import { parseRequest } from '../boundary.js';
import { ApiAuthenticationError } from '../errors.js';
import type { ApiRoutePlugin } from '../route-context.js';

export const bootstrapRoutes: ApiRoutePlugin = (app, context) => {
  app.post('/v1/vaults', async (request, reply) => {
    const sessionTokenHash = await context.security.authenticateOneTimeToken(
      request,
      'bootstrap',
    );
    const body = parseRequest(vaultBootstrapRequestSchema, request.body);
    const receipt = await context.ports.bootstrap.bootstrap({
      ...body,
      sessionTokenHash,
    });
    if (receipt === null) throw new ApiAuthenticationError();
    return reply.status(201).send(vaultBootstrapResponseSchema.parse(receipt));
  });
  return Promise.resolve();
};
