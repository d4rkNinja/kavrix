import {
  apiBearerTokenSchema,
  apiSessionResponseSchema,
  deviceIdSchema,
  deviceListResponseSchema,
  enrollmentCompleteRequestSchema,
  enrollmentCompleteResponseSchema,
  healthResponseSchema,
  inviteIdSchema,
  inviteIssueRequestSchema,
  inviteIssueResponseSchema,
  inviteListResponseSchema,
  inviteRedeemResponseSchema,
  keySlotIdSchema,
  vaultBootstrapRequestSchema,
  vaultBootstrapResponseSchema,
  vaultIdSchema,
  vaultKeySlotUpdateRequestSchema,
  vaultRecordSchema,
  type ApiBearerToken,
  type ApiSessionResponse,
  type DeviceId,
  type EnrollmentCompleteRequest,
  type HealthResponse,
  type InviteId,
  type InviteIssueRequest,
  type InviteRedeemResponse,
  type KeySlotId,
  type PublicDeviceRecord,
  type VaultBootstrapRequest,
  type VaultBootstrapResponse,
  type VaultId,
  type VaultKeySlotUpdateRequest,
  type VaultRecord,
} from '@kavrix/schemas';

import { ControlPlaneFailure } from './errors.js';
import {
  SecureFetchClient,
  SecureFetchFailure,
  type SecureFetchOptions,
} from './secure-fetch.js';

const SUCCESSOR_BYTES = 32;

interface RuntimeSchema<Output> {
  safeParse(
    value: unknown,
  ): Readonly<{ success: true; data: Output }> | Readonly<{ success: false }>;
}

export type ControlPlaneClientOptions = SecureFetchOptions;

/**
 * Low-level HTTPS client for the canonical zero-knowledge control-plane routes.
 * Credential lifecycle and durable successor persistence remain caller-owned.
 */
export class ControlPlaneClient {
  readonly #fetch: SecureFetchClient;

  constructor(options: ControlPlaneClientOptions) {
    this.#fetch = new SecureFetchClient(options);
  }

  /** Canonical non-secret endpoint to bind durable local profiles. */
  get baseUrl(): string {
    return this.#fetch.baseUrl;
  }

  health(): Promise<HealthResponse> {
    return this.#canonicalRequest(healthResponseSchema, {
      method: 'GET',
      path: ['health'],
      expectedStatus: 200,
    });
  }

  async getSession(
    bearerToken: ApiBearerToken,
    expectedVaultId: VaultId,
    expectedDeviceId: DeviceId,
  ): Promise<ApiSessionResponse> {
    const vaultId = parse(vaultIdSchema, expectedVaultId);
    const deviceId = parse(deviceIdSchema, expectedDeviceId);
    const session = await this.#canonicalRequest(apiSessionResponseSchema, {
      method: 'GET',
      path: ['v1', 'session'],
      expectedStatus: 200,
      bearerToken,
    });
    if (session.vaultId !== vaultId || session.deviceId !== deviceId) {
      throw new ControlPlaneFailure('protocol');
    }
    return session;
  }

  async bootstrap(
    sessionBearer: ApiBearerToken,
    request: VaultBootstrapRequest,
  ): Promise<VaultBootstrapResponse> {
    const body = parse(vaultBootstrapRequestSchema, request);
    const response = await this.#canonicalRequest(vaultBootstrapResponseSchema, {
      method: 'POST',
      path: ['v1', 'vaults'],
      expectedStatus: 201,
      bearerToken: sessionBearer,
      body: stringify(body),
    });
    if (response.vaultId !== body.vault.id || response.deviceId !== body.device.id) {
      throw new ControlPlaneFailure('protocol');
    }
    return response;
  }

  async fetchVault(
    bearerToken: ApiBearerToken,
    requestedVaultId: VaultId,
  ): Promise<VaultRecord> {
    const vaultId = parse(vaultIdSchema, requestedVaultId);
    const vault = await this.#canonicalRequest(vaultRecordSchema, {
      method: 'GET',
      path: ['v1', 'vaults', vaultId],
      expectedStatus: 200,
      bearerToken,
    });
    if (vault.id !== vaultId) throw new ControlPlaneFailure('protocol');
    return vault;
  }

  async issueInvite(
    bearerToken: ApiBearerToken,
    requestedVaultId: VaultId,
    request: InviteIssueRequest,
  ): Promise<ReturnType<typeof inviteIssueResponseSchema.parse>> {
    const vaultId = parse(vaultIdSchema, requestedVaultId);
    const body = parse(inviteIssueRequestSchema, request);
    return this.#canonicalRequest(inviteIssueResponseSchema, {
      method: 'POST',
      path: ['v1', 'vaults', vaultId, 'invites'],
      expectedStatus: 201,
      bearerToken,
      body: stringify(body),
    });
  }

  async listInvites(
    bearerToken: ApiBearerToken,
    requestedVaultId: VaultId,
  ): Promise<
    readonly ReturnType<typeof inviteListResponseSchema.parse>['invites'][number][]
  > {
    const vaultId = parse(vaultIdSchema, requestedVaultId);
    const response = await this.#canonicalRequest(inviteListResponseSchema, {
      method: 'GET',
      path: ['v1', 'vaults', vaultId, 'invites'],
      expectedStatus: 200,
      bearerToken,
    });
    if (response.invites.some((invite) => invite.vaultId !== vaultId)) {
      throw new ControlPlaneFailure('protocol');
    }
    return response.invites;
  }

  async revokeInvite(
    bearerToken: ApiBearerToken,
    requestedVaultId: VaultId,
    requestedInviteId: InviteId,
  ): Promise<void> {
    const vaultId = parse(vaultIdSchema, requestedVaultId);
    const inviteId = parse(inviteIdSchema, requestedInviteId);
    await this.#requestEmpty({
      method: 'DELETE',
      path: ['v1', 'vaults', vaultId, 'invites', inviteId],
      expectedStatus: 204,
      bearerToken,
    });
  }

  async redeemInvite(
    inviteBearer: ApiBearerToken,
    enrollmentSuccessor: Uint8Array,
    expectedVaultId: VaultId,
  ): Promise<InviteRedeemResponse> {
    const vaultId = parse(vaultIdSchema, expectedVaultId);
    return this.#withSuccessor(
      inviteBearer,
      enrollmentSuccessor,
      async (successorToken) => {
        const response = await this.#canonicalRequest(inviteRedeemResponseSchema, {
          method: 'POST',
          path: ['v1', 'invites', 'redeem'],
          expectedStatus: 200,
          bearerToken: inviteBearer,
          successorToken,
        });
        if (response.vaultId !== vaultId || response.vault.id !== vaultId) {
          throw new ControlPlaneFailure('protocol');
        }
        return response;
      },
    );
  }

  async completeEnrollment(
    enrollmentBearer: ApiBearerToken,
    sessionSuccessor: Uint8Array,
    request: EnrollmentCompleteRequest,
  ): Promise<ReturnType<typeof enrollmentCompleteResponseSchema.parse>> {
    const body = parse(enrollmentCompleteRequestSchema, request);
    return this.#withSuccessor(
      enrollmentBearer,
      sessionSuccessor,
      async (successorToken) => {
        const response = await this.#canonicalRequest(
          enrollmentCompleteResponseSchema,
          {
            method: 'POST',
            path: ['v1', 'enrollments', 'complete'],
            expectedStatus: 201,
            bearerToken: enrollmentBearer,
            successorToken,
            body: stringify(body),
          },
        );
        if (response.vaultId !== body.vaultId || response.deviceId !== body.deviceId) {
          throw new ControlPlaneFailure('protocol');
        }
        return response;
      },
    );
  }

  async listDevices(
    bearerToken: ApiBearerToken,
    requestedVaultId: VaultId,
  ): Promise<readonly PublicDeviceRecord[]> {
    const vaultId = parse(vaultIdSchema, requestedVaultId);
    const response = await this.#canonicalRequest(deviceListResponseSchema, {
      method: 'GET',
      path: ['v1', 'vaults', vaultId, 'devices'],
      expectedStatus: 200,
      bearerToken,
    });
    if (response.devices.some((device) => device.vaultId !== vaultId)) {
      throw new ControlPlaneFailure('protocol');
    }
    return response.devices;
  }

  async revokeDevice(
    bearerToken: ApiBearerToken,
    requestedVaultId: VaultId,
    requestedDeviceId: DeviceId,
  ): Promise<void> {
    const vaultId = parse(vaultIdSchema, requestedVaultId);
    const deviceId = parse(deviceIdSchema, requestedDeviceId);
    await this.#requestEmpty({
      method: 'DELETE',
      path: ['v1', 'vaults', vaultId, 'devices', deviceId],
      expectedStatus: 204,
      bearerToken,
    });
  }

  publishKeySlot(
    bearerToken: ApiBearerToken,
    requestedVaultId: VaultId,
    requestedSlotId: KeySlotId,
    request: VaultKeySlotUpdateRequest,
  ): Promise<void> {
    return this.#updateKeySlot(
      'PUT',
      bearerToken,
      requestedVaultId,
      requestedSlotId,
      request,
    );
  }

  revokeKeySlot(
    bearerToken: ApiBearerToken,
    requestedVaultId: VaultId,
    requestedSlotId: KeySlotId,
    request: VaultKeySlotUpdateRequest,
  ): Promise<void> {
    return this.#updateKeySlot(
      'DELETE',
      bearerToken,
      requestedVaultId,
      requestedSlotId,
      request,
    );
  }

  async #updateKeySlot(
    method: 'PUT' | 'DELETE',
    bearerToken: ApiBearerToken,
    requestedVaultId: VaultId,
    requestedSlotId: KeySlotId,
    request: VaultKeySlotUpdateRequest,
  ): Promise<void> {
    const vaultId = parse(vaultIdSchema, requestedVaultId);
    const slotId = parse(keySlotIdSchema, requestedSlotId);
    const body = parse(vaultKeySlotUpdateRequestSchema, request);
    const slot = body.record.keySlots.find((candidate) => candidate.id === slotId);
    if (
      body.record.id !== vaultId ||
      slot === undefined ||
      (method === 'PUT' && (slot.state === 'revoked' || slot.state === 'superseded')) ||
      (method === 'DELETE' && slot.state !== 'revoked')
    ) {
      throw new ControlPlaneFailure('protocol');
    }
    await this.#requestEmpty({
      method,
      path: ['v1', 'vaults', vaultId, 'key-slots', slotId],
      expectedStatus: 204,
      bearerToken,
      body: stringify(body),
    });
  }

  async #canonicalRequest<Output>(
    schema: RuntimeSchema<Output>,
    options: Parameters<SecureFetchClient['requestJson']>[0],
  ): Promise<Output> {
    return parse(schema, await this.#requestJson(options));
  }

  async #requestJson(
    options: Parameters<SecureFetchClient['requestJson']>[0],
  ): Promise<unknown> {
    try {
      return await this.#fetch.requestJson(options);
    } catch (error) {
      throw controlPlaneError(error);
    }
  }

  async #requestEmpty(
    options: Parameters<SecureFetchClient['requestEmpty']>[0],
  ): Promise<void> {
    try {
      await this.#fetch.requestEmpty(options);
    } catch (error) {
      throw controlPlaneError(error);
    }
  }

  async #withSuccessor<Output>(
    currentBearer: ApiBearerToken,
    successorBytes: Uint8Array,
    operation: (successorToken: ApiBearerToken) => Promise<Output>,
  ): Promise<Output> {
    const bearer = parse(apiBearerTokenSchema, currentBearer);
    if (
      !(successorBytes instanceof Uint8Array) ||
      successorBytes.byteLength !== SUCCESSOR_BYTES
    ) {
      throw new ControlPlaneFailure('protocol');
    }
    const ownedBytes = Uint8Array.from(successorBytes);
    try {
      const successorToken = parse(
        apiBearerTokenSchema,
        Buffer.from(
          ownedBytes.buffer,
          ownedBytes.byteOffset,
          ownedBytes.byteLength,
        ).toString('base64url'),
      );
      if (successorToken === bearer) throw new ControlPlaneFailure('protocol');
      return await operation(successorToken);
    } finally {
      ownedBytes.fill(0);
    }
  }
}

function parse<Output>(schema: RuntimeSchema<Output>, value: unknown): Output {
  try {
    const parsed = schema.safeParse(value);
    if (parsed.success) return parsed.data;
  } catch {
    // Fall through to one generic protocol failure.
  }
  throw new ControlPlaneFailure('protocol');
}

function stringify(value: unknown): string {
  try {
    return JSON.stringify(value);
  } catch {
    throw new ControlPlaneFailure('protocol');
  }
}

function controlPlaneError(error: unknown): ControlPlaneFailure {
  return error instanceof SecureFetchFailure
    ? new ControlPlaneFailure(error.kind, error.retryAfterMs)
    : error instanceof ControlPlaneFailure
      ? error
      : new ControlPlaneFailure('client');
}
