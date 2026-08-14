import { healthResponseSchema, readinessResponseSchema } from '@kavrix/schemas';

import type { ApiRoutePlugin } from '../route-context.js';

export const healthRoutes: ApiRoutePlugin = (app, context) => {
  app.get('/health', () => healthResponseSchema.parse({ status: 'ok' }));
  app.get('/ready', async (_request, reply) => {
    try {
      if (await context.readiness()) {
        return readinessResponseSchema.parse({ status: 'ready' });
      }
    } catch {
      // Dependency details are intentionally not observable at this boundary.
    }
    return reply
      .status(503)
      .send(readinessResponseSchema.parse({ status: 'not_ready' }));
  });
  return Promise.resolve();
};
