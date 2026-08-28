import {
  AuthorizationStateFileError,
  authorizationStatePath,
  initializeAuthorizationStateFile,
  readAuthorizationStateFile,
  transitionAuthorizationStateFile,
  type AuthorizationScope,
} from '@kavrix/key-files';
import {
  grantIdSchema,
  policyIdSchema,
  runtimeAuditEventSchema,
  timestampSchema,
  type AuthorizationStateDocument,
  type GrantRecord,
  type PermissionEntry,
  type PolicyId,
  type RuntimeAuditEvent,
  type StoredPolicyRecord,
} from '@kavrix/schemas';

import {
  CodedCliError,
  authorizationDenied,
  datastoreFailure,
  grantInvalid,
  invalidConfiguration,
  securityIntegrityFailure,
} from './exit-codes.js';

const MAX_AUDIT_RING = 512;

/**
 * Loosened construction input for one audit event: optional metadata may be
 * omitted or explicitly undefined at call sites; strict validation happens
 * inside the sealed transition before anything is persisted.
 */
export type RuntimeAuditEventInput = Readonly<
  Partial<RuntimeAuditEvent> & Pick<RuntimeAuditEvent, 'actor' | 'action'>
>;

export type AuthorizationStateSnapshot = Readonly<{
  policies: Readonly<Record<string, StoredPolicyRecord>>;
  grants: Readonly<Record<string, GrantRecord>>;
  audit: readonly RuntimeAuditEvent[];
}>;

export interface StateMutationDraft {
  policies: Record<string, StoredPolicyRecord>;
  grants: Record<string, GrantRecord>;
  audit: RuntimeAuditEvent[];
}

export type StateMutation<T> = (
  view: Readonly<{
    snapshot: AuthorizationStateSnapshot;
    next: (apply: (draft: StateMutationDraft) => void) => void;
  }>,
) => Promise<T> | T;

/**
 * One unlocked scope's sealed authorization state. Every mutation runs under
 * the protected-file lock and republishes the complete authenticated document
 * with a bumped sequence; readers re-read sealed bytes instead of trusting any
 * cached state across mutations.
 */
export class AuthorizationState {
  private constructor(
    readonly statePath: string,
    private readonly keyBytes: Uint8Array,
    private readonly scope: AuthorizationScope,
  ) {}

  public static async open(
    keyFile: string,
    keyBytes: Uint8Array,
    scope: AuthorizationScope,
  ): Promise<AuthorizationState> {
    const statePath = authorizationStatePath(keyFile);
    try {
      const existing = await readAuthorizationStateFile(statePath, keyBytes, scope);
      if (existing === null) {
        await initializeAuthorizationStateFile(statePath, keyBytes, scope, {
          version: 1,
          policies: {},
          grants: {},
          audit: [],
        });
      }
    } catch (error) {
      throw mapStateError(error);
    }
    return new AuthorizationState(statePath, Uint8Array.from(keyBytes), scope);
  }

  /**
   * Reads the current sealed document without creating a missing sidecar. This
   * is the authoritative entry point for inspection and simulation commands:
   * an empty result is a read-only view, not an implicit state mutation.
   */
  public static async readSnapshot(
    keyFile: string,
    keyBytes: Uint8Array,
    scope: AuthorizationScope,
  ): Promise<AuthorizationStateSnapshot> {
    try {
      const loaded = await readAuthorizationStateFile(
        authorizationStatePath(keyFile),
        keyBytes,
        scope,
      );
      return loaded?.state ?? { policies: {}, grants: {}, audit: [] };
    } catch (error) {
      throw mapStateError(error);
    }
  }

  public async read(): Promise<AuthorizationStateSnapshot> {
    try {
      const loaded = await readAuthorizationStateFile(
        this.statePath,
        this.keyBytes,
        this.scope,
      );
      if (loaded === null)
        throw securityIntegrityFailure('Authorization state disappeared.');
      return loaded.state;
    } catch (error) {
      throw mapStateError(error);
    }
  }

  /** Runs one locked transition; the callback may read first, then mutate once. */
  public async mutate<T>(mutation: StateMutation<T>): Promise<T> {
    try {
      return await transitionAuthorizationStateFile<T>(
        this.statePath,
        this.keyBytes,
        this.scope,
        async (current) => {
          const snapshot: AuthorizationStateSnapshot = current;
          let draft: StateMutationDraft | undefined;
          const result = await mutation({
            snapshot,
            next(apply) {
              if (draft !== undefined) {
                throw new Error('A state mutation may publish exactly one change set.');
              }
              draft = { ...current };
              apply(draft);
            },
          });
          if (draft === undefined) {
            return { nextState: current, result };
          }
          const nextState: AuthorizationStateDocument = {
            version: 1,
            policies: draft.policies,
            grants: draft.grants,
            audit: [...draft.audit],
          };
          return { nextState, result };
        },
      );
    } catch (error) {
      throw mapStateError(error);
    }
  }

  public close(): void {
    this.keyBytes.fill(0);
  }

  // ---- convenience mutations -------------------------------------------------

  public async putPolicy(
    id: string,
    entry: PermissionEntry,
  ): Promise<StoredPolicyRecord> {
    const policyId = parsePolicyId(id);
    return this.mutate((view) => {
      const record: StoredPolicyRecord = { definition: entry, createdAt: nowIso() };
      view.next((draft) => {
        draft.policies[policyId] = record;
        appendAudit(draft.audit, {
          actor: 'user',
          action: 'policy-created',
          policyId,
          ...(entry.secret === undefined ? {} : { secret: entry.secret }),
        });
      });
      return record;
    });
  }

  public async removePolicy(id: string): Promise<void> {
    const policyId = parsePolicyId(id);
    await this.mutate((view) => {
      const existing = view.snapshot.policies[policyId];
      if (existing === undefined) {
        throw new CodedCliError('GRANT_INVALID', `Policy '${policyId}' was not found.`);
      }
      view.next((draft) => {
        const { [policyId]: _removed, ...remaining } = draft.policies;
        void _removed;
        draft.policies = remaining;
        appendAudit(draft.audit, {
          actor: 'user',
          action: 'policy-removed',
          policyId,
          ...(existing.definition.secret === undefined
            ? {}
            : { secret: existing.definition.secret }),
        });
      });
    });
  }

  public async putGrant(record: GrantRecord): Promise<void> {
    await this.mutate((view) => {
      view.next((draft) => {
        draft.grants[record.grantId] = record;
        appendAudit(draft.audit, {
          actor: record.actor === 'agent' ? 'agent' : 'user',
          action: 'grant-created',
          grantId: record.grantId,
          secret: record.secret,
        });
      });
    });
  }

  public async revokeGrant(grantIdInput: string): Promise<GrantRecord> {
    const grantId = parseGrantId(grantIdInput);
    return this.mutate((view) => {
      const grant = view.snapshot.grants[grantId];
      if (grant === undefined || grant.revokedAt !== undefined) {
        throw new CodedCliError(
          'GRANT_INVALID',
          `Grant '${grantId}' was not found or is already revoked.`,
        );
      }
      const revoked: GrantRecord = { ...grant, revokedAt: nowIso() };
      view.next((draft) => {
        draft.grants[grantId] = revoked;
        appendAudit(draft.audit, {
          actor: 'user',
          action: 'grant-revoked',
          grantId,
          secret: grant.secret,
        });
      });
      return revoked;
    });
  }

  /**
   * Reserves one use of a grant inside the locked transition. Expiry and the
   * use count are revalidated against freshly-read state, so concurrent
   * invocations can never both claim the final use.
   */
  public async consumeGrantUse(
    grantIdInput: string,
    meta: Readonly<{ executable: string; argvPreview?: readonly string[] | undefined }>,
  ): Promise<GrantRecord> {
    const grantId = parseGrantId(grantIdInput);
    return this.mutate((view) => {
      const grant = view.snapshot.grants[grantId];
      if (grant === undefined) {
        throw grantInvalid(`Grant '${grantId}' was not found.`);
      }
      const nowMs = Date.now();
      if (grant.revokedAt !== undefined) {
        throw authorizationDenied('The requested grant has been revoked.');
      }
      if (grant.expiresAt !== undefined && nowMs > Date.parse(grant.expiresAt)) {
        view.next((draft) => {
          appendAudit(draft.audit, {
            actor: grant.actor === 'agent' ? 'agent' : 'user',
            action: 'grant-expired',
            grantId,
            secret: grant.secret,
            command: meta.executable,
          });
        });
        throw grantInvalid('The temporary grant has expired.');
      }
      if (grant.maxUses !== undefined && grant.usedCount >= grant.maxUses) {
        view.next((draft) => {
          appendAudit(draft.audit, {
            actor: grant.actor === 'agent' ? 'agent' : 'user',
            action: 'grant-exhausted',
            grantId,
            secret: grant.secret,
            command: meta.executable,
          });
        });
        throw grantInvalid('The temporary grant has no remaining uses.');
      }
      let updated: GrantRecord | undefined;
      view.next((draft) => {
        const current = draft.grants[grantId];
        if (current === undefined) return;
        updated = {
          ...current,
          usedCount: current.usedCount + 1,
          lastUsedAt: nowIso(),
        };
        draft.grants[grantId] = updated;
        appendAudit(draft.audit, {
          actor: grant.actor === 'agent' ? 'agent' : 'user',
          action: 'authorization-allowed',
          grantId,
          secret: grant.secret,
          command: meta.executable,
          ...(meta.argvPreview === undefined
            ? {}
            : { argvPreview: [...meta.argvPreview] }),
        });
      });
      return updated ?? grant;
    });
  }

  public async recordEvent(event: RuntimeAuditEventInput): Promise<number> {
    return this.mutate((view) => {
      let seq = -1;
      view.next((draft) => {
        seq = appendAudit(draft.audit, event);
      });
      return seq;
    });
  }
}

function appendAudit(
  audit: RuntimeAuditEvent[],
  event: RuntimeAuditEventInput,
): number {
  const previous = audit.at(-1);
  const seq = (previous?.seq ?? 0) + 1;
  audit.push(runtimeAuditEventSchema.parse({ ...event, seq, occurredAt: nowIso() }));
  if (audit.length > MAX_AUDIT_RING) {
    audit.splice(0, audit.length - MAX_AUDIT_RING);
  }
  return seq;
}

export function nowIso(): string {
  return timestampSchema.parse(new Date().toISOString());
}

export function parsePolicyId(value: string): PolicyId {
  const parsed = policyIdSchema.safeParse(value);
  if (!parsed.success) throw invalidConfiguration(`Policy id '${value}' is invalid.`);
  return parsed.data;
}

export function parseGrantId(value: string): string {
  const parsed = grantIdSchema.safeParse(value);
  if (!parsed.success) throw invalidConfiguration(`Grant id '${value}' is invalid.`);
  return parsed.data;
}

function mapStateError(error: unknown): Error {
  if (error instanceof CodedCliError) return error;
  if (!(error instanceof AuthorizationStateFileError)) {
    if (error instanceof Error && error.message.includes('Authentication failed')) {
      return securityIntegrityFailure(error.message);
    }
    return error instanceof Error
      ? error
      : datastoreFailure('Kavrix operation failed.');
  }
  switch (error.code) {
    case 'INTEGRITY_FAILURE':
    case 'SCOPE_MISMATCH':
    case 'INVALID_FORMAT':
    case 'KEY_INVALID':
      return securityIntegrityFailure(error.message);
    case 'OPERATION_FAILED':
      return datastoreFailure(error.message);
  }
}
