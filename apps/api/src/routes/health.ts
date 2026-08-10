import { healthResponseSchema } from '@kavrix/schemas';

import type { ApiRoutePlugin } from '../route-context.js';

export const healthRoutes: ApiRoutePlugin = (app) => {
  app.get('/health', () => healthResponseSchema.parse({ status: 'ok' }));
  return Promise.resolve();
};
