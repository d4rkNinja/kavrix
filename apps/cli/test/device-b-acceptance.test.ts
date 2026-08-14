import { createHash, randomBytes } from 'node:crypto';
import { PassThrough, Readable, Writable } from 'node:stream';
import { readFile, readdir, realpath, rm } from 'node:fs/promises';
import { resolve, join } from 'node:path';
import { tmpdir } from 'node:os';

import { vi, afterEach, describe, expect, it } from 'vitest';
import type * as ClipboardModule from '@kavrix/clipboard';
import type * as KeychainModule from '@kavrix/keychain';

const testAdapters = vi.hoisted(() => {
  const entries = new Map<string, Uint8Array>();
  let copyCount = 0;

  const entryFactory: KeychainModule.NativeEntryFactory = (
    service: string,
    account: string,
  ) => {
    const key = `${service}\u0000${account}`;
    return {
      setSecret: (secret: Uint8Array): Promise<void> => {
        const previous = entries.get(key);
        previous?.fill(0);
        entries.set(key, Uint8Array.from(secret));
        return Promise.resolve();
      },
      getSecret: (): Promise<Uint8Array | null> => {
        const secret = entries.get(key);
        return Promise.resolve(secret === undefined ? null : Uint8Array.from(secret));
      },
      deleteCredential: (): Promise<void> => {
        const previous = entries.get(key);
        previous?.fill(0);
        entries.delete(key);
        return Promise.resolve();
      },
    };
  };

  const createClipboard = (): ClipboardModule.SecureClipboardPort => ({
    copy: (
      secret: Uint8Array,
      options: ClipboardModule.ClipboardCopyOptions,
    ): Promise<ClipboardModule.ClipboardCopyReceipt> => {
      void secret;
      void options;
      copyCount += 1;
      return Promise.resolve({
        generation: copyCount,
        requestedClearAfterMs: 30_000,
        cleanupRetryDeadlineAfterMs: 30_700,
        maxCleanupAttempts: 4,
        clearAfterMs: 30_000,
      });
    },
    lock: (): Promise<boolean> => Promise.resolve(false),
    dispose: (): Promise<boolean> => Promise.resolve(false),
    takeBackgroundError: (): Error | null => null,
  });

  return {
    entryFactory,
    createClipboard,
    reset: (): void => {
      for (const secret of entries.values()) secret.fill(0);
      entries.clear();
      copyCount = 0;
    },
  };
});

vi.mock('@kavrix/keychain', async () => {
  const actual = await vi.importActual<typeof KeychainModule>('@kavrix/keychain');
  return {
    ...actual,
    loadNativeEntryFactory: (): Promise<KeychainModule.NativeEntryFactory> =>
      Promise.resolve(testAdapters.entryFactory),
  };
});

vi.mock('@kavrix/clipboard', async () => {
  const actual = await vi.importActual<typeof ClipboardModule>('@kavrix/clipboard');
  return { ...actual, createSecureClipboard: testAdapters.createClipboard };
});

import {
  apiBearerTokenSchema,
  apiScopesSchema,
  apiSessionResponseSchema,
  changeRecordSchema,
  contentHashForRecord,
  deviceIdSchema,
  enrollmentCompleteRequestSchema,
  enrollmentCompleteResponseSchema,
  inviteIssueRequestSchema,
  inviteIssueResponseSchema,
  inviteRedeemResponseSchema,
  syncCursorSchema,
  syncPullQuerySchema,
  syncPullResponseSchema,
  syncPushRequestSchema,
  syncPushResponseSchema,
  vaultBootstrapRequestSchema,
  vaultBootstrapResponseSchema,
  vaultIdSchema,
  vaultKeySlotUpdateRequestSchema,
  vaultRecordSchema,
  type ApiBearerToken,
  type ChangeRecord,
  type OpaqueMutation,
  type OpaqueSyncRecord,
  type VaultId,
  type VaultRecord,
} from '@kavrix/schemas';
import { unlockPortableKeySlot, zeroize } from '@kavrix/crypto';
import { acquiredSecretSchema, runCli, type CliDependencies } from '../src/index.js';
import type { SecretInputPort } from '../src/secret-input.js';

const SERVER_URL = 'https://device-b.acceptance/';
const GROUP_NAME = 'Personal';
const CREDENTIAL_NAME = 'Primary';
const PUBLIC_VALUE = 'device-b-username-canary';
const SECRET_VALUE = 'device-b-password-canary';
const INVITE_ID = 'invite.deviceb.acceptance0001';
const TEST_TMPDIR = await realpath(tmpdir());

type ActiveMutationRecord = Extract<
  OpaqueMutation,
  { entityType: 'vault' | 'group' | 'item' }
>['record'];

type StoredChange = Readonly<{
  change: ChangeRecord;
  record: OpaqueSyncRecord;
}>;

type SessionState = Readonly<{
  vaultId: VaultId;
  deviceId: ReturnType<typeof deviceIdSchema.parse>;
  scopes: ReturnType<typeof apiScopesSchema.parse>;
  active: boolean;
}>;

type InviteState = Readonly<{
  inviteId: string;
  vaultId: VaultId;
  tokenHash: string;
  scopes: ReturnType<typeof apiScopesSchema.parse>;
  expiresAt: string;
  state: 'active' | 'redeemed';
}>;

type EnrollmentState = Readonly<{
  vaultId: VaultId;
  scopes: ReturnType<typeof apiScopesSchema.parse>;
  deviceId?: ReturnType<typeof deviceIdSchema.parse>;
}>;

class DeviceAcceptanceControlPlane {
  readonly requestBodies: string[] = [];
  readonly requestHeaders: string[] = [];
  readonly #active = new Map<string, ActiveMutationRecord>();
  readonly #visible = new Map<string, OpaqueSyncRecord>();
  readonly #changes: StoredChange[] = [];
  readonly #accepted = new Map<
    string,
    Readonly<{ body: string; change: ChangeRecord }>
  >();
  readonly #batches = new Map<string, Readonly<{ body: string; response: unknown }>>();
  readonly #sessions = new Map<string, SessionState>();
  readonly #invites = new Map<string, InviteState>();
  readonly #enrollments = new Map<string, EnrollmentState>();
  #vault: VaultRecord | null = null;
  #serverVaultRevision = 0;

  get vault(): VaultRecord | null {
    return this.#vault === null ? null : structuredClone(this.#vault);
  }

  fetch(input: Request | URL, init?: RequestInit): Response {
    const url = new URL(input instanceof Request ? input.url : String(input));
    const method = init?.method ?? (input instanceof Request ? input.method : 'GET');
    const body = typeof init?.body === 'string' ? init.body : '';
    if (body.length > 0) this.requestBodies.push(body);
    const headers = new Headers(
      input instanceof Request ? input.headers : (init?.headers ?? undefined),
    );
    this.requestHeaders.push(
      JSON.stringify({
        authorization: headers.get('authorization'),
        successor: headers.get('x-kavrix-successor-token'),
      }),
    );
    const path = url.pathname.split('/').filter((segment) => segment.length > 0);

    try {
      if (
        method === 'POST' &&
        path.length === 2 &&
        path[0] === 'v1' &&
        path[1] === 'vaults'
      ) {
        return this.bootstrap(url, headers, body);
      }
      if (
        method === 'GET' &&
        path.length === 2 &&
        path[0] === 'v1' &&
        path[1] === 'session'
      ) {
        return this.session(url, headers);
      }
      if (
        method === 'POST' &&
        path.length === 4 &&
        path[0] === 'v1' &&
        path[1] === 'vaults' &&
        path[2] !== undefined &&
        path[3] === 'invites'
      ) {
        return this.issueInvite(url, headers, path[2], body);
      }
      if (
        method === 'GET' &&
        path.length === 3 &&
        path[0] === 'v1' &&
        path[1] === 'vaults' &&
        path[2] !== undefined
      ) {
        return this.fetchVault(url, headers, path[2]);
      }
      if (
        method === 'POST' &&
        path.length === 3 &&
        path[0] === 'v1' &&
        path[1] === 'invites' &&
        path[2] === 'redeem'
      ) {
        return this.redeemInvite(url, headers);
      }
      if (
        method === 'POST' &&
        path.length === 3 &&
        path[0] === 'v1' &&
        path[1] === 'enrollments' &&
        path[2] === 'complete'
      ) {
        return this.completeEnrollment(url, headers, body);
      }
      if (
        path.length === 4 &&
        path[0] === 'v1' &&
        path[1] === 'vaults' &&
        path[3] === 'sync' &&
        path[2] !== undefined
      ) {
        return method === 'GET'
          ? this.pull(url, headers, path[2])
          : method === 'POST'
            ? this.push(url, headers, path[2], body)
            : this.error(url, 404, 'NOT_FOUND');
      }
      if (
        method === 'PUT' &&
        path.length === 5 &&
        path[0] === 'v1' &&
        path[1] === 'vaults' &&
        path[3] === 'key-slots' &&
        path[2] !== undefined &&
        path[4] !== undefined
      ) {
        return this.publishKeySlot(url, headers, path[2], path[4], body);
      }
      if (
        method === 'DELETE' &&
        path.length === 5 &&
        path[0] === 'v1' &&
        path[1] === 'vaults' &&
        path[3] === 'devices' &&
        path[2] !== undefined &&
        path[4] !== undefined
      ) {
        return this.revokeDevice(url, headers, path[2], path[4]);
      }
      return this.error(url, 404, 'NOT_FOUND');
    } catch {
      return this.error(url, 400, 'INVALID_REQUEST');
    }
  }

  assertNoPlaintext(portableKey: string, rootKey: Uint8Array): void {
    const state = this.stateText();
    const captured = `${this.requestBodies.join('\n')}\n${this.requestHeaders.join('\n')}\n${state}`;
    expect(captured).not.toContain(PUBLIC_VALUE);
    expect(captured).not.toContain(SECRET_VALUE);
    expect(captured).not.toContain(portableKey);
    for (const encoded of [
      Buffer.from(rootKey).toString('base64url'),
      Buffer.from(rootKey).toString('base64'),
      Buffer.from(rootKey).toString('hex'),
    ]) {
      expect(captured).not.toContain(encoded);
    }
  }

  private bootstrap(url: URL, headers: Headers, body: string): Response {
    if (this.#vault !== null) return this.error(url, 409, 'ALREADY_EXISTS');
    const bearer = bearerFromHeaders(headers);
    if (bearer === null) return this.error(url, 401, 'UNAUTHORIZED');
    const request = vaultBootstrapRequestSchema.parse(JSON.parse(body) as unknown);
    this.#vault = request.vault;
    const scopes = apiScopesSchema.parse(['sync:read', 'sync:write', 'device:manage']);
    this.#sessions.set(hashToken(bearer), {
      vaultId: request.vault.id,
      deviceId: request.device.id,
      scopes,
      active: true,
    });
    this.#active.set(this.key('vault', request.vault.id), request.vault);
    this.#visible.set(this.key('vault', request.vault.id), request.vault);
    this.#changes.push({
      change: changeRecordSchema.parse({
        id: 'change.deviceb.acceptance.1',
        vaultId: request.vault.id,
        serverSequence: 1,
        recordRevision: request.vault.revision,
        operation: 'upsert',
        ciphertextHash: contentHashForRecord(request.vault),
        createdAt: request.vault.updatedAt,
        entityType: 'vault',
        entityId: request.vault.id,
      }),
      record: request.vault,
    });
    return jsonResponse(
      url,
      201,
      vaultBootstrapResponseSchema.parse({
        vaultId: request.vault.id,
        deviceId: request.device.id,
      }),
    );
  }

  private session(url: URL, headers: Headers): Response {
    const session = this.authenticated(headers);
    if (session === null) return this.error(url, 401, 'UNAUTHORIZED');
    return jsonResponse(
      url,
      200,
      apiSessionResponseSchema.parse({
        vaultId: session.vaultId,
        deviceId: session.deviceId,
        scopes: session.scopes,
      }),
    );
  }

  private fetchVault(url: URL, headers: Headers, vaultIdInput: string): Response {
    const vaultId = vaultIdSchema.parse(vaultIdInput);
    const session = this.authenticated(headers, vaultId, 'sync:read');
    if (session === null || this.#vault?.id !== vaultId) {
      return this.error(url, session === null ? 401 : 404, 'UNAUTHORIZED');
    }
    return jsonResponse(url, 200, this.#vault);
  }

  private issueInvite(
    url: URL,
    headers: Headers,
    vaultIdInput: string,
    body: string,
  ): Response {
    const vaultId = vaultIdSchema.parse(vaultIdInput);
    const session = this.authenticated(headers, vaultId, 'device:manage');
    if (session === null) return this.error(url, 401, 'UNAUTHORIZED');
    const request = inviteIssueRequestSchema.parse(JSON.parse(body) as unknown);
    const inviteToken = apiBearerTokenSchema.parse(
      randomBytes(32).toString('base64url'),
    );
    const expiresAt = new Date(
      Date.now() + request.expiresInSeconds * 1_000,
    ).toISOString();
    this.#invites.set(INVITE_ID, {
      inviteId: INVITE_ID,
      vaultId,
      tokenHash: hashToken(inviteToken),
      scopes: request.scopes,
      expiresAt,
      state: 'active',
    });
    return jsonResponse(
      url,
      201,
      inviteIssueResponseSchema.parse({
        inviteId: INVITE_ID,
        inviteToken,
        expiresAt,
      }),
    );
  }

  private redeemInvite(url: URL, headers: Headers): Response {
    const inviteBearer = bearerFromHeaders(headers);
    const successor = successorFromHeaders(headers);
    if (inviteBearer === null || successor === null) {
      return this.error(url, 401, 'UNAUTHORIZED');
    }
    const invite = [...this.#invites.values()].find(
      (candidate) => candidate.tokenHash === hashToken(inviteBearer),
    );
    if (invite?.state !== 'active') {
      return this.error(url, 401, 'UNAUTHORIZED');
    }
    if (Date.parse(invite.expiresAt) <= Date.now()) {
      return this.error(url, 401, 'UNAUTHORIZED');
    }
    if (this.#vault === null || invite.vaultId !== this.#vault.id) {
      return this.error(url, 404, 'NOT_FOUND');
    }
    this.#invites.set(invite.inviteId, { ...invite, state: 'redeemed' });
    this.#enrollments.set(hashToken(successor), {
      vaultId: invite.vaultId,
      scopes: invite.scopes,
    });
    return jsonResponse(
      url,
      200,
      inviteRedeemResponseSchema.parse({
        vaultId: invite.vaultId,
        expiresAt: invite.expiresAt,
        vault: this.#vault,
      }),
    );
  }

  private completeEnrollment(url: URL, headers: Headers, body: string): Response {
    const enrollmentBearer = bearerFromHeaders(headers);
    const sessionSuccessor = successorFromHeaders(headers);
    if (enrollmentBearer === null || sessionSuccessor === null) {
      return this.error(url, 401, 'UNAUTHORIZED');
    }
    const enrollment = this.#enrollments.get(hashToken(enrollmentBearer));
    if (enrollment === undefined) return this.error(url, 401, 'UNAUTHORIZED');
    const request = enrollmentCompleteRequestSchema.parse(JSON.parse(body) as unknown);
    if (request.vaultId !== enrollment.vaultId)
      return this.error(url, 403, 'FORBIDDEN');
    const existing = this.#sessions.get(hashToken(sessionSuccessor));
    if (existing !== undefined) {
      if (
        existing.deviceId !== request.deviceId ||
        existing.vaultId !== request.vaultId
      ) {
        return this.error(url, 409, 'CONFLICT');
      }
    } else {
      this.#sessions.set(hashToken(sessionSuccessor), {
        vaultId: request.vaultId,
        deviceId: request.deviceId,
        scopes: enrollment.scopes,
        active: true,
      });
    }
    this.#enrollments.set(hashToken(enrollmentBearer), {
      ...enrollment,
      deviceId: request.deviceId,
    });
    return jsonResponse(
      url,
      201,
      enrollmentCompleteResponseSchema.parse({
        vaultId: request.vaultId,
        deviceId: request.deviceId,
      }),
    );
  }

  private publishKeySlot(
    url: URL,
    headers: Headers,
    vaultIdInput: string,
    slotIdInput: string,
    body: string,
  ): Response {
    const vaultId = vaultIdSchema.parse(vaultIdInput);
    const session = this.authenticated(headers, vaultId, 'sync:write');
    if (session === null || this.#vault === null) {
      return this.error(url, 401, 'UNAUTHORIZED');
    }
    const slotId = slotIdInput;
    const request = vaultKeySlotUpdateRequestSchema.parse(JSON.parse(body) as unknown);
    if (
      request.record.id !== vaultId ||
      request.record.revision !== this.#vault.revision + 1 ||
      request.expectedVaultRevision !== this.#vault.revision ||
      !request.record.keySlots.some((slot) => slot.id === slotId)
    ) {
      return this.error(url, 409, 'CONFLICT');
    }
    this.#vault = vaultRecordSchema.parse(request.record);
    this.#active.set(this.key('vault', vaultId), this.#vault);
    this.#visible.set(this.key('vault', vaultId), this.#vault);
    this.#serverVaultRevision = this.#vault.revision;
    this.#changes.push({
      change: changeRecordSchema.parse({
        id: `change.deviceb.acceptance.${String(this.#changes.length + 1)}`,
        vaultId,
        serverSequence: this.#changes.length + 1,
        recordRevision: this.#vault.revision,
        operation: 'upsert',
        ciphertextHash: contentHashForRecord(this.#vault),
        createdAt: this.#vault.updatedAt,
        entityType: 'vault',
        entityId: vaultId,
      }),
      record: this.#vault,
    });
    return emptyResponse(url, 204);
  }

  private revokeDevice(
    url: URL,
    headers: Headers,
    vaultIdInput: string,
    deviceIdInput: string,
  ): Response {
    const vaultId = vaultIdSchema.parse(vaultIdInput);
    const deviceId = deviceIdSchema.parse(deviceIdInput);
    const session = this.authenticated(headers, vaultId, 'device:manage');
    if (session === null || this.#vault === null) {
      return this.error(url, 401, 'UNAUTHORIZED');
    }
    const target = [...this.#sessions.entries()].find(
      ([, candidate]) =>
        candidate.vaultId === vaultId && candidate.deviceId === deviceId,
    );
    if (target === undefined) return this.error(url, 404, 'NOT_FOUND');
    const [tokenHash, targetSession] = target;
    this.#sessions.set(tokenHash, { ...targetSession, active: false });
    const updatedAt = new Date().toISOString();
    this.#vault = vaultRecordSchema.parse({
      ...this.#vault,
      keySlots: this.#vault.keySlots.map((slot) =>
        slot.type === 'device-key' &&
        slot.deviceId === deviceId &&
        slot.state === 'active'
          ? { ...slot, state: 'revoked', revokedAt: updatedAt }
          : slot,
      ),
      revision: this.#vault.revision + 1,
      updatedAt,
    });
    this.#active.set(this.key('vault', vaultId), this.#vault);
    this.#visible.set(this.key('vault', vaultId), this.#vault);
    this.#serverVaultRevision = this.#vault.revision;
    this.#changes.push({
      change: changeRecordSchema.parse({
        id: `change.deviceb.acceptance.${String(this.#changes.length + 1)}`,
        vaultId,
        serverSequence: this.#changes.length + 1,
        recordRevision: this.#vault.revision,
        operation: 'upsert',
        ciphertextHash: contentHashForRecord(this.#vault),
        createdAt: updatedAt,
        entityType: 'vault',
        entityId: vaultId,
      }),
      record: this.#vault,
    });
    return emptyResponse(url, 204);
  }

  private pull(url: URL, headers: Headers, vaultIdInput: string): Response {
    const vaultId = vaultIdSchema.parse(vaultIdInput);
    const session = this.authenticated(headers, vaultId, 'sync:read');
    if (session === null || this.#vault === null) {
      return this.error(url, 401, 'UNAUTHORIZED');
    }
    const query = syncPullQuerySchema.parse(
      Object.fromEntries(url.searchParams.entries()),
    );
    const pending = this.#changes.filter(
      ({ change }) => change.serverSequence > query.serverSequence,
    );
    const page = pending.slice(0, query.limit);
    const serverSequence = page.at(-1)?.change.serverSequence ?? query.serverSequence;
    return jsonResponse(
      url,
      200,
      syncPullResponseSchema.parse({
        vaultId,
        serverVaultRevision: this.#serverVaultRevision,
        changes: page,
        nextCursor: syncCursorSchema.parse({
          vaultId,
          serverSequence,
          highestSeenVaultRevision: this.#serverVaultRevision,
        }),
        hasMore: pending.length > page.length,
      }),
    );
  }

  private push(
    url: URL,
    headers: Headers,
    vaultIdInput: string,
    body: string,
  ): Response {
    const vaultId = vaultIdSchema.parse(vaultIdInput);
    const session = this.authenticated(headers, vaultId, 'sync:write');
    if (session === null || this.#vault === null) {
      return this.error(url, 401, 'UNAUTHORIZED');
    }
    const batch = syncPushRequestSchema.parse(JSON.parse(body) as unknown);
    const previousBatch = this.#batches.get(batch.batchIdempotencyKey);
    if (previousBatch !== undefined) {
      if (previousBatch.body !== body) return this.error(url, 409, 'CONFLICT');
      return jsonResponse(url, 200, previousBatch.response);
    }

    const results: (
      | Readonly<{
          status: 'accepted';
          idempotencyKey: string;
          disposition: 'committed' | 'duplicate';
          change: ChangeRecord;
        }>
      | Readonly<{
          status: 'conflict';
          idempotencyKey: string;
          currentRevision: number;
          current: OpaqueSyncRecord | null;
        }>
    )[] = [];

    for (const mutation of batch.mutations) {
      const prior = this.#accepted.get(mutation.idempotencyKey);
      if (prior !== undefined) {
        if (prior.body !== JSON.stringify(mutation))
          return this.error(url, 409, 'CONFLICT');
        results.push({
          status: 'accepted',
          idempotencyKey: mutation.idempotencyKey,
          disposition: 'duplicate',
          change: prior.change,
        });
        continue;
      }
      const key = this.key(mutation.entityType, mutation.record.id);
      const predecessor = this.#active.get(key);
      const expected = expectedRevision(predecessor, mutation.entityType);
      const supplied =
        mutation.entityType === 'vault'
          ? mutation.expectedVaultRevision
          : mutation.expectedRecordRevision;
      if (supplied !== expected) {
        results.push({
          status: 'conflict',
          idempotencyKey: mutation.idempotencyKey,
          currentRevision: expected ?? 0,
          current: this.#visible.get(key) ?? null,
        });
        continue;
      }
      const change = changeRecordSchema.parse({
        id: `change.deviceb.acceptance.${String(this.#changes.length + 1)}`,
        vaultId,
        serverSequence: this.#changes.length + 1,
        recordRevision:
          mutation.entityType === 'vault'
            ? mutation.record.revision
            : mutation.record.recordRevision,
        operation: 'upsert',
        ciphertextHash: contentHashForRecord(mutation.record),
        createdAt: '2026-08-14T00:00:00.000Z',
        entityType: mutation.entityType,
        entityId: mutation.record.id,
      });
      this.#active.set(key, mutation.record);
      this.#visible.set(key, mutation.record);
      this.#changes.push({ change, record: mutation.record });
      if (mutation.entityType === 'vault') this.#vault = mutation.record;
      this.#accepted.set(mutation.idempotencyKey, {
        body: JSON.stringify(mutation),
        change,
      });
      results.push({
        status: 'accepted',
        idempotencyKey: mutation.idempotencyKey,
        disposition: 'committed',
        change,
      });
    }
    const response = syncPushResponseSchema.parse({
      vaultId,
      serverVaultRevision: this.#serverVaultRevision,
      batchIdempotencyKey: batch.batchIdempotencyKey,
      results,
    });
    this.#batches.set(batch.batchIdempotencyKey, { body, response });
    return jsonResponse(url, 200, response);
  }

  private authenticated(
    headers: Headers,
    vaultId?: VaultId,
    scope?: 'sync:read' | 'sync:write' | 'device:manage',
  ): SessionState | null {
    const bearer = bearerFromHeaders(headers);
    if (bearer === null) return null;
    const session = this.#sessions.get(hashToken(bearer));
    if (
      session === undefined ||
      !session.active ||
      (vaultId !== undefined && session.vaultId !== vaultId) ||
      (scope !== undefined && !session.scopes.includes(scope))
    ) {
      return null;
    }
    return session;
  }

  private key(entityType: string, entityId: string): string {
    return `${entityType}:${entityId}`;
  }

  private stateText(): string {
    return JSON.stringify({
      vault: this.#vault,
      active: [...this.#active.entries()],
      visible: [...this.#visible.entries()],
      changes: this.#changes,
      invites: [...this.#invites.values()],
      enrollments: [...this.#enrollments.entries()],
      sessions: [...this.#sessions.entries()],
    });
  }

  private error(url: URL, status: number, code: string): Response {
    return jsonResponse(url, status, { error: { code, message: 'Request rejected.' } });
  }
}

describe('fresh-home second-device acceptance', () => {
  let homeA = '';
  let homeB = '';

  afterEach(async () => {
    vi.unstubAllGlobals();
    testAdapters.reset();
    await removeTestHome(homeA, 'a');
    await removeTestHome(homeB, 'b');
    homeA = '';
    homeB = '';
  });

  it('creates on Device A, joins and decrypts on Device B, then denies the revoked device', async () => {
    homeA = await freshHome('a');
    homeB = await freshHome('b');
    const controlPlane = new DeviceAcceptanceControlPlane();
    vi.stubGlobal('fetch', controlPlane.fetch.bind(controlPlane));

    const initialized = await expectSuccess(
      homeA,
      [
        'init',
        '--server',
        SERVER_URL,
        '--secret-backend',
        'native',
        '--confirmation-stdin',
      ],
      { interactive: true },
    );
    const portableKey = matchRequired(initialized.stderr, /Portable key: ([^\r\n]+)/u);
    const initializedVault = controlPlane.vault;
    if (initializedVault === null)
      throw new Error('Device A initialization did not bootstrap a vault.');
    const vaultId = initializedVault.id;
    expect(initialized.stderr).not.toContain(SECRET_VALUE);

    await expectSuccess(homeA, [
      'group',
      'create',
      GROUP_NAME,
      '--secret-backend',
      'native',
    ]);
    await expectSuccess(homeA, [
      'credential',
      'create',
      GROUP_NAME,
      CREDENTIAL_NAME,
      '--secret-backend',
      'native',
    ]);
    await expectSuccess(
      homeA,
      [
        'field',
        'add',
        GROUP_NAME,
        CREDENTIAL_NAME,
        'username',
        '--type',
        'text',
        '--label',
        'Username',
        '--value-stdin',
        '--secret-backend',
        'native',
      ],
      { secretFrames: [PUBLIC_VALUE] },
    );
    await expectSuccess(
      homeA,
      [
        'field',
        'add',
        GROUP_NAME,
        CREDENTIAL_NAME,
        'password',
        '--type',
        'secret',
        '--label',
        'Password',
        '--sensitive',
        '--value-stdin',
        '--secret-backend',
        'native',
      ],
      { secretFrames: [SECRET_VALUE] },
    );
    await expectSuccess(homeA, ['sync', '--secret-backend', 'native']);

    const inviteOutput = await expectSuccess(homeA, [
      'device',
      'invite',
      'create',
      '--vault',
      vaultId,
      '--scope',
      'sync:read',
      'sync:write',
      'device:manage',
      '--stdout',
      '--json',
      '--secret-backend',
      'native',
    ]);
    const invite = inviteIssueResponseSchema.parse(
      JSON.parse(inviteOutput.stdout) as unknown,
    );
    expect(invite.inviteId).toBe(INVITE_ID);
    expect(inviteOutput.stdout).not.toContain(SECRET_VALUE);
    expect(inviteOutput.stderr).not.toContain(SECRET_VALUE);

    const joinedOutput = await expectSuccess(
      homeB,
      [
        'device',
        'join',
        '--server',
        SERVER_URL,
        '--vault',
        vaultId,
        '--invite-stdin',
        '--portable-key-stdin',
        '--json',
        '--secret-backend',
        'native',
      ],
      { secretFrames: [invite.inviteToken, portableKey] },
    );
    const joined = JSON.parse(joinedOutput.stdout) as Readonly<{
      operationId: string;
      vaultId: string;
      deviceId: string;
    }>;
    expect(joined.vaultId).toBe(vaultId);
    expect(deviceIdSchema.safeParse(joined.deviceId).success).toBe(true);
    expect(joinedOutput.stdout).not.toContain(portableKey);
    expect(joinedOutput.stderr).not.toContain(SECRET_VALUE);

    const shown = await expectSuccess(homeB, [
      'show',
      GROUP_NAME,
      CREDENTIAL_NAME,
      '--secret-backend',
      'native',
    ]);
    expect(shown.stdout).toContain(PUBLIC_VALUE);
    expect(shown.stdout).toContain('[REDACTED]');
    expect(shown.stdout).not.toContain(SECRET_VALUE);
    expect(shown.stderr).not.toContain(SECRET_VALUE);

    const revoked = await expectSuccess(homeA, [
      'device',
      'revoke',
      joined.deviceId,
      '--vault',
      vaultId,
      '--confirm',
      '--secret-backend',
      'native',
    ]);
    expect(revoked.stdout).toBe('Device revoked.\n');

    const denied = await execute(homeB, ['sync', '--secret-backend', 'native']);
    expect(denied.code).not.toBe(0);
    expect(denied.stderr).toBe(
      'Error [UNEXPECTED_FAILURE]: The command failed without exposing internal details.\n',
    );
    expect(denied.stderr).not.toContain(invite.inviteToken);
    expect(denied.stderr).not.toContain(portableKey);
    expect(denied.stderr).not.toContain(SECRET_VALUE);

    const serverVault = controlPlane.vault;
    if (serverVault === null) throw new Error('Device acceptance server has no vault.');
    const portableSlot = serverVault.keySlots.find(
      (slot) => slot.type === 'portable-key' && slot.state === 'active',
    );
    if (portableSlot?.type !== 'portable-key') {
      throw new Error('Device acceptance server lost its portable slot.');
    }
    const rootKey = await unlockPortableKeySlot(portableSlot, portableKey, {
      vaultId: serverVault.id,
      slotId: portableSlot.id,
      schemaVersion: serverVault.schemaVersion,
      keyVersion: portableSlot.keyVersion,
    });
    try {
      controlPlane.assertNoPlaintext(portableKey, rootKey);
    } finally {
      zeroize(rootKey);
    }
    expect(await treeContains(homeA, SECRET_VALUE)).toBe(false);
    expect(await treeContains(homeB, SECRET_VALUE)).toBe(false);
    expect(await treeContains(homeA, portableKey)).toBe(false);
    expect(await treeContains(homeB, portableKey)).toBe(false);
  }, 180_000);
});

async function expectSuccess(
  home: string,
  arguments_: readonly string[],
  options: ExecuteOptions = {},
): Promise<Readonly<{ stdout: string; stderr: string }>> {
  const result = await execute(home, arguments_, options);
  if (result.code !== 0) {
    throw new Error(
      `Acceptance command failed with exit code ${String(result.code)}: ${result.stderr}`,
    );
  }
  return result;
}

type ExecuteOptions = Readonly<{
  interactive?: boolean;
  secretFrames?: readonly string[];
}>;

async function execute(
  home: string,
  arguments_: readonly string[],
  options: ExecuteOptions = {},
): Promise<Readonly<{ stdout: string; stderr: string; code: number }>> {
  const stdout = capture(false);
  const terminal = options.interactive === true ? interactiveTerminal() : undefined;
  const stderr = terminal?.output ?? capture(false);
  const secrets = scriptedSecrets(options.secretFrames ?? [], terminal?.output.value);
  const dependencies: CliDependencies = {
    ports: undefined as never,
    secrets,
    environment: { CREDS_HOME: home },
    runtime: {
      stdin: terminal?.input ?? Readable.from([]),
      stdout: stdout.stream,
      stderr: stderr.stream,
    },
  };
  const code = await runCli(arguments_, dependencies);
  terminal?.input.destroy();
  return { stdout: stdout.value(), stderr: stderr.value(), code };
}

function scriptedSecrets(
  frames: readonly string[],
  terminalOutput: (() => string) | undefined,
): SecretInputPort {
  let index = 0;
  return {
    read: ({ fromStdin }) => {
      if (!fromStdin)
        throw new Error('Device acceptance unexpectedly requested masked input.');
      const value = frames[index];
      index += 1;
      if (value === undefined)
        throw new Error('Device acceptance secret input was incomplete.');
      return Promise.resolve(acquiredSecretSchema.parse(value));
    },
    readBatch: (request) => {
      if (
        request.kinds.length === 2 &&
        request.kinds[0] === 'portable-key' &&
        request.kinds[1] === 'recovery-key'
      ) {
        const output = terminalOutput?.() ?? '';
        const portable = /Portable key: ([^\r\n]+)/u.exec(output)?.[1];
        const recovery = /Recovery key: ([^\r\n]+)/u.exec(output)?.[1];
        if (portable === undefined || recovery === undefined) {
          throw new Error(
            'Device acceptance initialization material was not displayed.',
          );
        }
        return Promise.resolve([
          acquiredSecretSchema.parse(portable),
          acquiredSecretSchema.parse(recovery),
        ]);
      }
      if (
        request.kinds.length === 2 &&
        request.kinds[0] === 'invite' &&
        request.kinds[1] === 'portable-key'
      ) {
        if (!request.fromStdin || !request.requireEnd) {
          throw new Error('Device acceptance join input was not framed.');
        }
        const invite = frames[index];
        const portable = frames[index + 1];
        index += 2;
        if (invite === undefined || portable === undefined) {
          throw new Error('Device acceptance join input was incomplete.');
        }
        return Promise.resolve([
          acquiredSecretSchema.parse(invite),
          acquiredSecretSchema.parse(portable),
        ]);
      }
      return Promise.reject(
        new Error('Device acceptance secret batch was unexpected.'),
      );
    },
  };
}

class FakeTtyInput extends PassThrough {
  readonly isTTY = true;
  isRaw = false;

  setRawMode(enabled: boolean): void {
    this.isRaw = enabled;
  }
}

function interactiveTerminal(): Readonly<{
  input: FakeTtyInput;
  output: CapturedOutput;
}> {
  const input = new FakeTtyInput();
  const output = capture(true, (value) => {
    if (value.includes('Type saved and press Enter')) input.write('saved\n');
  });
  return { input, output };
}

type CapturedOutput = Readonly<{
  stream: Writable;
  value: () => string;
}>;

function capture(isTTY: boolean, onWrite?: (value: string) => void): CapturedOutput {
  let content = '';
  const stream = new Writable({
    write(chunk, _encoding, callback) {
      const value = Buffer.from(chunk).toString('utf8');
      content += value;
      onWrite?.(value);
      callback();
    },
  }) as Writable & { isTTY?: boolean };
  if (isTTY) stream.isTTY = true;
  return { stream, value: () => content };
}

function bearerFromHeaders(headers: Headers): ApiBearerToken | null {
  const value = headers.get('authorization');
  if (value?.startsWith('Bearer ') !== true) return null;
  const parsed = apiBearerTokenSchema.safeParse(value.slice('Bearer '.length));
  return parsed.success ? parsed.data : null;
}

function successorFromHeaders(headers: Headers): ApiBearerToken | null {
  const parsed = apiBearerTokenSchema.safeParse(
    headers.get('x-kavrix-successor-token'),
  );
  return parsed.success ? parsed.data : null;
}

function hashToken(token: string): string {
  return createHash('sha256').update(token, 'utf8').digest('hex');
}

function expectedRevision(
  predecessor: ActiveMutationRecord | undefined,
  entityType: OpaqueMutation['entityType'],
): number | null {
  if (predecessor === undefined) return null;
  if (entityType === 'vault') {
    return 'revision' in predecessor ? predecessor.revision : null;
  }
  return 'recordRevision' in predecessor ? predecessor.recordRevision : null;
}

function jsonResponse(url: URL, status: number, value: unknown): Response {
  const response = new Response(JSON.stringify(value), {
    status,
    headers: { 'content-type': 'application/json; charset=utf-8' },
  });
  Object.defineProperty(response, 'url', { value: url.href });
  return response;
}

function emptyResponse(url: URL, status: number): Response {
  const response = new Response(null, { status });
  Object.defineProperty(response, 'url', { value: url.href });
  return response;
}

function matchRequired(value: string, expression: RegExp): string {
  const matched = expression.exec(value)?.[1];
  if (matched === undefined)
    throw new Error('Device acceptance output was incomplete.');
  return matched;
}

async function freshHome(label: string): Promise<string> {
  const root = await realpath(TEST_TMPDIR);
  return join(root, `kavrix-device-b-${label}-${randomBytes(12).toString('hex')}`);
}

async function removeTestHome(path: string, label: string): Promise<void> {
  if (path.length === 0) return;
  const root = await realpath(TEST_TMPDIR);
  const resolved = resolve(path);
  const prefix = join(root, `kavrix-device-b-${label}-`);
  if (!resolved.startsWith(prefix)) {
    throw new Error(`Refusing to remove an unverified Device ${label} test home.`);
  }
  await rm(resolved, { recursive: true, force: true });
}

async function treeContains(root: string, needle: string): Promise<boolean> {
  try {
    for (const entry of await readdir(root, { withFileTypes: true })) {
      const path = resolve(root, entry.name);
      if (entry.isDirectory() && (await treeContains(path, needle))) return true;
      if (entry.isFile()) {
        const bytes = await readFile(path);
        try {
          if (bytes.includes(Buffer.from(needle, 'utf8'))) return true;
        } finally {
          bytes.fill(0);
        }
      }
    }
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === 'ENOENT') return false;
    throw error;
  }
  return false;
}
