import {
  apiBearerTokenSchema,
  syncCursorSchema,
  syncPullResponseSchema,
  syncPushRequestSchema,
  syncPushResponseSchema,
  templateMigrationPublicationRequestSchema,
  vaultIdSchema,
  type ApiBearerToken,
  type TemplateMigrationPublicationRequest,
  type TemplateMigrationPublicationResponse,
} from '@kavrix/schemas';
import {
  parseTemplateMigrationPublicationResponse,
  SyncProtocolError,
  SyncRollbackError,
  type PullPageRequest,
  type PullPageResponse,
  type PushBatchRequest,
  type PushBatchResponse,
  type SyncTransportPort,
} from '@kavrix/sync';

import {
  SecureFetchClient,
  SecureFetchFailure,
  type SecureFetchOptions,
} from './secure-fetch.js';
import { throwMappedSecureFetchError } from './secure-fetch-sync-errors.js';

export type FetchSyncTransportOptions = SecureFetchOptions &
  Readonly<{ bearerToken: ApiBearerToken }>;

/** HTTPS-only opaque sync transport. It never places the bearer token in a URL. */
export class FetchSyncTransport implements SyncTransportPort {
  readonly #fetch: SecureFetchClient;
  readonly #bearerToken: ApiBearerToken;

  constructor(options: FetchSyncTransportOptions) {
    this.#fetch = new SecureFetchClient(options);
    const token = apiBearerTokenSchema.safeParse(options.bearerToken);
    if (!token.success) throw new TypeError('The bearer token is invalid.');
    this.#bearerToken = token.data;
  }

  async pull(request: PullPageRequest): Promise<PullPageResponse> {
    const parsedVaultId = vaultIdSchema.safeParse(request.vaultId);
    const parsedCursor = syncCursorSchema.safeParse(request.cursor);
    if (
      !parsedVaultId.success ||
      !parsedCursor.success ||
      parsedCursor.data.vaultId !== parsedVaultId.data ||
      !Number.isSafeInteger(request.limit) ||
      request.limit < 1 ||
      request.limit > 500
    ) {
      throw new SyncProtocolError();
    }
    const vaultId = parsedVaultId.data;
    const cursor = parsedCursor.data;
    let value: unknown;
    try {
      value = await this.#fetch.requestJson({
        method: 'GET',
        path: ['v1', 'vaults', vaultId, 'sync'],
        expectedStatus: 200,
        bearerToken: this.#bearerToken,
        query: [
          ['serverSequence', String(cursor.serverSequence)],
          ['highestSeenVaultRevision', String(cursor.highestSeenVaultRevision)],
          ['limit', String(request.limit)],
        ],
      });
    } catch (error) {
      if (error instanceof SecureFetchFailure && error.kind === 'conflict') {
        throw new SyncRollbackError();
      }
      throwMappedSecureFetchError(error);
    }
    const parsed = syncPullResponseSchema.safeParse(value);
    if (!parsed.success) throw new SyncProtocolError();
    return parsed.data;
  }

  async push(request: PushBatchRequest): Promise<PushBatchResponse> {
    const parsedRequest = syncPushRequestSchema.safeParse(request);
    if (!parsedRequest.success) throw new SyncProtocolError();
    const value = await this.#requestJson({
      method: 'POST',
      path: ['v1', 'vaults', parsedRequest.data.vaultId, 'sync'],
      expectedStatus: 200,
      bearerToken: this.#bearerToken,
      body: JSON.stringify(parsedRequest.data),
    });
    const parsed = syncPushResponseSchema.safeParse(value);
    if (!parsed.success) throw new SyncProtocolError();
    return parsed.data;
  }

  async publishTemplateMigration(
    request: TemplateMigrationPublicationRequest,
  ): Promise<TemplateMigrationPublicationResponse> {
    const parsedRequest = templateMigrationPublicationRequestSchema.safeParse(request);
    if (!parsedRequest.success) throw new SyncProtocolError();
    const publication = parsedRequest.data;
    const value = await this.#requestJson({
      method: 'POST',
      path: ['v1', 'vaults', publication.vaultId, 'template-migrations'],
      expectedStatus: 200,
      bearerToken: this.#bearerToken,
      body: JSON.stringify(publication),
    });
    return parseTemplateMigrationPublicationResponse(value, publication);
  }

  async #requestJson(
    options: Parameters<SecureFetchClient['requestJson']>[0],
  ): Promise<unknown> {
    try {
      return await this.#fetch.requestJson(options);
    } catch (error) {
      throwMappedSecureFetchError(error);
    }
  }
}
