import type { FastifyPluginAsync } from 'fastify';

import type { ApiPorts } from './ports.js';
import type { RequestSecurity } from './security.js';

export interface RouteContext {
  readonly ports: ApiPorts;
  readonly security: RequestSecurity;
  readonly enrollmentLifetimeSeconds: number;
}

export type ApiRoutePlugin = FastifyPluginAsync<RouteContext>;
