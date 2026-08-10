import type { FastifyRequest } from 'fastify';

import {
  apiSessionResponseSchema,
  type ApiScope,
  type Sha256Digest,
  type VaultId,
} from '@kavrix/schemas';

import { bearerToken } from './boundary.js';
import {
  ApiAuthenticationError,
  ApiAuthorizationError,
  ApiRateLimitError,
} from './errors.js';
import type { ApiPorts, SessionPrincipal } from './ports.js';

export interface ApiRatePolicy {
  readonly limit: number;
  readonly windowSeconds: number;
}

export class RequestSecurity {
  public constructor(
    private readonly ports: ApiPorts,
    private readonly authenticatedPolicy: ApiRatePolicy,
    private readonly anonymousPolicy: ApiRatePolicy,
    private readonly sourcePolicy: ApiRatePolicy,
  ) {}

  public async authenticate(
    request: FastifyRequest,
    requiredScope?: ApiScope,
    vaultId?: VaultId,
  ): Promise<SessionPrincipal> {
    const token = bearerToken(request);
    const tokenHash = await this.ports.tokens.hash(token);
    await this.consume(
      `session:${request.routeOptions.url ?? 'unknown'}:${tokenHash}`,
      this.authenticatedPolicy,
    );
    const storedPrincipal = await this.ports.authorization.findSession(
      tokenHash,
      this.ports.clock.now(),
    );
    const principal = apiSessionResponseSchema.safeParse(storedPrincipal);
    if (!principal.success) {
      throw new ApiAuthenticationError();
    }
    if (
      (requiredScope !== undefined && !principal.data.scopes.includes(requiredScope)) ||
      (vaultId !== undefined && principal.data.vaultId !== vaultId)
    ) {
      throw new ApiAuthorizationError();
    }
    return principal.data;
  }

  public async authenticateOneTimeToken(
    request: FastifyRequest,
    purpose: 'bootstrap' | 'invite' | 'enrollment',
  ): Promise<Sha256Digest> {
    const token = bearerToken(request);
    const tokenHash = await this.ports.tokens.hash(token);
    await this.consume(
      `${purpose}:${request.routeOptions.url ?? 'unknown'}:${tokenHash}`,
      this.anonymousPolicy,
    );
    return tokenHash;
  }

  private async consume(key: string, policy: ApiRatePolicy): Promise<void> {
    const allowed = await this.ports.rateLimits.consume({
      key,
      limit: policy.limit,
      windowSeconds: policy.windowSeconds,
      now: this.ports.clock.now(),
    });
    if (!allowed) {
      throw new ApiRateLimitError();
    }
  }

  public consumeSource(request: FastifyRequest): Promise<void> {
    return this.consume(
      `source:${request.routeOptions.url ?? 'unknown'}:${request.ip}`,
      this.sourcePolicy,
    );
  }
}
