import { randomUUID } from 'node:crypto';
import { realpathSync } from 'node:fs';
import { isAbsolute, resolve } from 'node:path';

import {
  authorizationDecisionSchema,
  grantIdSchema,
  grantRecordSchema,
  parseDurationToMs,
  permissionEntrySchema,
  timestampSchema,
  type GrantRecord,
  type PermissionEntry,
} from '@kavrix/schemas';

import { nowIso, parseGrantId, parsePolicyId } from './authorization-state.js';
import { CodedCliError, invalidConfiguration } from './exit-codes.js';
import type { DatabaseFlatCommandOptions } from '../database-flat-commands.js';
import {
  withAuthorizationSnapshot,
  withAuthorizationState,
} from './authorization-session.js';
import { canonicalizeDirectory, type EvaluationContext } from './engine.js';
import { resolveExecutable } from './executable.js';
import {
  diffPolicyDefinition,
  explainPolicyEvaluation,
  grantInspection,
  lintAuthorizationState,
  suggestPolicyTightenings,
  type PolicyExplanation,
} from './policy-analysis.js';

export interface PolicyCreateOptions extends DatabaseFlatCommandOptions {
  readonly id: string;
  readonly secret?: string | undefined;
  readonly commands?: readonly string[] | undefined;
  readonly hashes?: readonly string[] | undefined;
  readonly env?: string | undefined;
  readonly reveal?: boolean | undefined;
  readonly ttl?: string | undefined;
  readonly maxUses?: number | undefined;
  readonly requireConfirmation?: boolean | readonly string[] | undefined;
  readonly workdir?: string | undefined;
  readonly deny?: boolean | undefined;
}

/** Creates or replaces one stored permission entry in sealed state. */
export async function executePolicyCreate(
  options: PolicyCreateOptions,
): Promise<unknown> {
  // Canonicalize at creation so the sealed policy binds to the real
  // directory, immune to later symlink or spelling changes.
  const workdir = resolveWorkdir(options.workdir);
  const entry = assembleEntry({ ...options, workdir });
  return await withAuthorizationState(options, async (state) => {
    const record = await state.putPolicy(options.id, entry);
    return {
      saved: true,
      id: options.id,
      secret: entry.secret ?? null,
      commands: entry.commands ?? [],
      reveal: entry.reveal === true,
      ...(entry.ttl === undefined ? {} : { ttl: entry.ttl }),
      ...(entry.maxUses === undefined ? {} : { maxUses: entry.maxUses }),
      deny: entry.deny === true,
      createdAt: record.createdAt,
    };
  });
}

export async function executePolicyList(
  options: DatabaseFlatCommandOptions,
): Promise<unknown> {
  return await withAuthorizationSnapshot(options, (snapshot) => {
    const policies = Object.entries(snapshot.policies)
      .map(([id, record]) => summarizeEntry(id, record.definition, record.createdAt))
      .sort((left, right) => String(left['id']).localeCompare(String(right['id'])));
    return { policies };
  });
}

export async function executePolicyShow(
  options: DatabaseFlatCommandOptions & Readonly<{ policyId: string }>,
): Promise<unknown> {
  return await withAuthorizationSnapshot(options, (snapshot) => {
    const record = snapshot.policies[options.policyId];
    if (record === undefined) {
      throw new CodedCliError(
        'GRANT_INVALID',
        `Policy '${options.policyId}' was not found.`,
      );
    }
    return summarizeEntry(options.policyId, record.definition, record.createdAt);
  });
}

export interface PolicySimulationOptions extends DatabaseFlatCommandOptions {
  readonly policyId: string;
  readonly executableAndArgs: readonly string[];
}

export type PolicyCheckResult = Readonly<{
  policyId: string;
  secret: string | null;
  command: string;
  credentialRead: false;
  outcome: 'allow' | 'deny' | 'confirm';
  reason: string;
  requiresConfirmation: boolean;
  executionWindowMs: number | null;
  matchedPolicyId?: string;
}>;

/** Simulates one stored policy and returns only its final machine decision. */
export async function executePolicyCheck(
  options: PolicySimulationOptions,
): Promise<PolicyCheckResult> {
  const explained = await policyExplanation(options);
  return {
    policyId: explained.policyId,
    secret: explained.secret,
    command: explained.command,
    credentialRead: false,
    outcome: explained.decision.outcome,
    reason: explained.decision.reason,
    requiresConfirmation: explained.decision.outcome === 'confirm',
    executionWindowMs: explained.executionWindowMs,
    ...(explained.decision.policyId === undefined
      ? {}
      : { matchedPolicyId: explained.decision.policyId }),
  };
}

/** Simulates one stored policy and returns the complete ordered rule trace. */
export async function executePolicyExplain(
  options: PolicySimulationOptions,
): Promise<PolicyExplanation> {
  return await policyExplanation(options);
}

/** Lints authenticated stored policies and grants without changing the sidecar. */
export async function executePolicyLint(
  options: DatabaseFlatCommandOptions,
): Promise<ReturnType<typeof lintAuthorizationState>> {
  const atMs = Date.now();
  return await withAuthorizationSnapshot(options, (snapshot) =>
    lintAuthorizationState(snapshot, atMs),
  );
}

/** Diffs the exact canonical definition that `policy create` would persist. */
export async function executePolicyDiff(
  options: PolicyCreateOptions,
): Promise<unknown> {
  const policyId = parsePolicyId(options.id);
  const workdir = resolveWorkdir(options.workdir);
  const proposed = assembleEntry({ ...options, workdir });
  return await withAuthorizationSnapshot(options, (snapshot) =>
    diffPolicyDefinition(policyId, snapshot.policies[policyId]?.definition, proposed),
  );
}

export interface PolicySuggestOptions extends DatabaseFlatCommandOptions {
  readonly limit?: number | undefined;
}

/** Builds review-only tightening candidates from positive sanitized audit events. */
export async function executePolicySuggest(
  options: PolicySuggestOptions,
): Promise<unknown> {
  return await withAuthorizationSnapshot(options, (snapshot) => {
    const limit = options.limit ?? 100;
    const audit = snapshot.audit.slice(Math.max(0, snapshot.audit.length - limit));
    return suggestPolicyTightenings(snapshot.policies, audit);
  });
}

export async function executePolicyRemove(
  options: DatabaseFlatCommandOptions & Readonly<{ policyId: string }>,
): Promise<unknown> {
  return await withAuthorizationState(options, async (state) => {
    await state.removePolicy(options.policyId);
    return { removed: true, id: options.policyId };
  });
}

// ---- grants ----------------------------------------------------------------

export interface GrantCreateOptions extends DatabaseFlatCommandOptions {
  readonly secret: string;
  readonly commands: readonly string[];
  readonly hashes?: readonly string[] | undefined;
  readonly env?: string | undefined;
  readonly ttl?: string | undefined;
  readonly maxUses?: number | undefined;
}

/** Issues one temporary consumable authorization. */
export async function executeGrantCreate(
  options: GrantCreateOptions,
): Promise<unknown> {
  const grantId = grantIdSchema.parse(`grant_${randomUUID()}`);
  let expiresAt: string | undefined;
  if (options.ttl !== undefined) {
    const ttlMs = parseDurationToMs(options.ttl);
    if (ttlMs === undefined)
      throw invalidConfiguration('--ttl is invalid or too large.');
    expiresAt = timestampSchema.parse(new Date(Date.now() + ttlMs).toISOString());
  }
  const assembled: Record<string, unknown> = {
    grantId,
    secret: options.secret,
    commands: [...options.commands],
    createdAt: nowIso(),
    usedCount: 0,
    actor: 'user',
  };
  if (options.hashes !== undefined && options.hashes.length > 0) {
    assembled['hashes'] = parseHashPins(options.hashes);
  }
  if (options.env !== undefined) assembled['env'] = options.env;
  if (expiresAt !== undefined) assembled['expiresAt'] = expiresAt;
  if (options.maxUses !== undefined) assembled['maxUses'] = options.maxUses;

  const record = validateGrant(assembled);
  return await withAuthorizationState(options, async (state) => {
    await state.putGrant(record);
    return {
      granted: true,
      grantId: record.grantId,
      secret: record.secret,
      commands: [...record.commands],
      ...(record.expiresAt === undefined ? {} : { expiresAt: record.expiresAt }),
      ...(record.maxUses === undefined ? {} : { maxUses: record.maxUses }),
    };
  });
}

export async function executeGrantList(
  options: DatabaseFlatCommandOptions,
): Promise<unknown> {
  const atMs = Date.now();
  return await withAuthorizationSnapshot(options, (snapshot) => {
    const grants = Object.values(snapshot.grants)
      .map((grant) => ({ ...grant, status: grantStatus(grant, atMs) }))
      .sort((left, right) => left.createdAt.localeCompare(right.createdAt));
    return { grants: grants.map((grant) => presentGrant(grant, atMs)) };
  });
}

export async function executeGrantShow(
  options: DatabaseFlatCommandOptions & Readonly<{ grantId: string }>,
): Promise<unknown> {
  const atMs = Date.now();
  return await withAuthorizationSnapshot(options, (snapshot) => {
    const grantId = parseGrantId(options.grantId);
    const grant = snapshot.grants[grantId];
    if (grant === undefined) {
      throw new CodedCliError('GRANT_INVALID', `Grant '${grantId}' was not found.`);
    }
    return presentGrant({ ...grant, status: grantStatus(grant, atMs) }, atMs);
  });
}

export async function executeGrantRevoke(
  options: DatabaseFlatCommandOptions & Readonly<{ grantId: string }>,
): Promise<unknown> {
  return await withAuthorizationState(options, async (state) => {
    const revoked = await state.revokeGrant(options.grantId);
    return { revoked: true, grantId: revoked.grantId };
  });
}

// ---- shared helpers --------------------------------------------------------

function summarizeEntry(
  id: string,
  entry: PermissionEntry,
  createdAt: string,
): Record<string, unknown> {
  return {
    id,
    secret: entry.secret ?? null,
    commands: entry.commands ?? [],
    ...(entry.hashes === undefined ? {} : { hashes: entry.hashes }),
    ...(entry.env === undefined ? {} : { env: entry.env }),
    ...(entry.workingDirectory === undefined
      ? {}
      : { workdir: entry.workingDirectory }),
    reveal: entry.reveal === true,
    ...(entry.ttl === undefined ? {} : { ttl: entry.ttl }),
    ...(entry.maxUses === undefined ? {} : { maxUses: entry.maxUses }),
    ...(entry.requireConfirmation === undefined
      ? {}
      : { requireConfirmation: entry.requireConfirmation }),
    deny: entry.deny === true,
    createdAt,
  };
}

export type GrantStatus =
  'active' | 'expired' | 'exhausted' | 'revoked' | 'clock-invalid';

export function grantStatus(grant: GrantRecord, atMs: number): GrantStatus {
  if (atMs < Date.parse(grant.createdAt)) return 'clock-invalid';
  if (grant.revokedAt !== undefined) return 'revoked';
  if (grant.expiresAt !== undefined && atMs > Date.parse(grant.expiresAt))
    return 'expired';
  if (grant.maxUses !== undefined && grant.usedCount >= grant.maxUses)
    return 'exhausted';
  return 'active';
}

export function presentGrant(
  grant: GrantRecord & { status: GrantStatus },
  atMs = Date.now(),
): Readonly<Record<string, unknown>> {
  return grantInspection(grant, atMs, grant.status);
}

export function assembleEntry(options: PolicyCreateOptions): PermissionEntry {
  const raw: Record<string, unknown> = {};
  if (options.deny === true) {
    raw['deny'] = true;
    if (options.secret !== undefined) raw['secret'] = options.secret;
  } else {
    if (options.secret !== undefined) raw['secret'] = options.secret;
    raw['commands'] = [...(options.commands ?? [])];
    if (options.reveal !== undefined) raw['reveal'] = options.reveal;
    if (options.ttl !== undefined) {
      if (parseDurationToMs(options.ttl) === undefined) {
        throw invalidConfiguration('--ttl is invalid or too large.');
      }
      raw['ttl'] = options.ttl;
    }
    if (options.workdir !== undefined) raw['workingDirectory'] = options.workdir;
    if (options.maxUses !== undefined) raw['maxUses'] = options.maxUses;
    if (options.requireConfirmation !== undefined) {
      raw['requireConfirmation'] =
        typeof options.requireConfirmation === 'boolean'
          ? options.requireConfirmation
          : options.requireConfirmation.filter((token) => token.length > 0);
    }
  }
  if (options.env !== undefined) raw['env'] = options.env;
  if (options.hashes !== undefined && options.hashes.length > 0) {
    raw['hashes'] = parseHashPins(options.hashes);
  }
  const parsed = permissionEntrySchema.safeParse(raw);
  if (!parsed.success) {
    throw invalidConfiguration('The policy definition is incomplete or invalid.');
  }
  return parsed.data;
}

async function policyExplanation(
  options: PolicySimulationOptions,
): Promise<PolicyExplanation> {
  const target = options.executableAndArgs[0];
  if (target === undefined || target.length === 0) {
    throw invalidConfiguration('A command is required after `--`.');
  }
  const policyId = parsePolicyId(options.policyId);
  return await withAuthorizationSnapshot(options, async (snapshot) => {
    const record = snapshot.policies[policyId];
    if (record === undefined) {
      throw new CodedCliError('GRANT_INVALID', `Policy '${policyId}' was not found.`);
    }
    const resolution = await resolveExecutable(target);
    if (resolution.status !== 'resolved') {
      const reason =
        resolution.status === 'refused'
          ? ('executable-refused' as const)
          : ('executable-unresolved' as const);
      return {
        policyId,
        secret: record.definition.secret ?? null,
        command: target,
        credentialRead: false,
        decision: authorizationDecisionSchema.parse({
          outcome: 'deny',
          reason,
          policyId,
          ...(record.definition.secret === undefined
            ? {}
            : { secret: record.definition.secret }),
        }),
        executionWindowMs: null,
        checks: [
          {
            order: 1,
            kind: 'command',
            status: 'not-evaluated',
            effect: 'deny',
            policyId,
            actual: target,
            note:
              resolution.status === 'refused'
                ? 'The executable type is refused before policy evaluation.'
                : 'The executable could not be resolved before policy evaluation.',
          },
        ],
      };
    }
    const context: EvaluationContext = {
      platform: process.platform,
      facts: {
        displayName: resolution.displayName,
        sha256: resolution.sha256,
        firstArgument: options.executableAndArgs[1],
      },
      nowIso: nowIso(),
      cwdRealPath: canonicalizeDirectory(process.cwd()),
    };
    return explainPolicyEvaluation(
      policyId,
      record.definition,
      snapshot.policies,
      context,
    );
  });
}

export function parseHashPins(values: readonly string[]): Record<string, string> {
  const pins: Record<string, string> = {};
  for (const value of values) {
    const separator = value.indexOf('=');
    if (separator <= 0 || separator === value.length - 1) {
      throw invalidConfiguration('--hash expects COMMAND=SHA256HEX.');
    }
    pins[value.slice(0, separator)] = value.slice(separator + 1).toLowerCase();
  }
  return pins;
}

function validateGrant(raw: Record<string, unknown>): GrantRecord {
  const parsed = grantRecordSchema.safeParse(raw);
  if (!parsed.success) {
    throw invalidConfiguration('The grant definition is incomplete or invalid.');
  }
  return parsed.data;
}

function resolveWorkdir(value: string | undefined): string | undefined {
  if (value === undefined) return undefined;
  const absolute = isAbsolute(value) ? value : resolve(value);
  try {
    return realpathSync(absolute);
  } catch {
    throw invalidConfiguration(`--workdir path could not be resolved: ${value}`);
  }
}
