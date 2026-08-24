import { randomUUID } from 'node:crypto';
import { realpathSync } from 'node:fs';
import { isAbsolute, resolve } from 'node:path';

import {
  grantIdSchema,
  grantRecordSchema,
  parseDurationToMs,
  permissionEntrySchema,
  timestampSchema,
  type GrantRecord,
  type PermissionEntry,
} from '@kavrix/schemas';

import { nowIso } from './authorization-state.js';
import { CodedCliError, invalidConfiguration } from './exit-codes.js';
import type { DatabaseFlatCommandOptions } from '../database-flat-commands.js';
import { withAuthorizationState } from './authorization-session.js';

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
  return await withAuthorizationState(options, async (state) => {
    const snapshot = await state.read();
    const policies = Object.entries(snapshot.policies)
      .map(([id, record]) => summarizeEntry(id, record.definition, record.createdAt))
      .sort((left, right) => String(left['id']).localeCompare(String(right['id'])));
    return { policies };
  });
}

export async function executePolicyShow(
  options: DatabaseFlatCommandOptions & Readonly<{ policyId: string }>,
): Promise<unknown> {
  return await withAuthorizationState(options, async (state) => {
    const snapshot = await state.read();
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
  return await withAuthorizationState(options, async (state) => {
    const snapshot = await state.read();
    const grants = Object.values(snapshot.grants)
      .map((grant) => ({ ...grant, status: grantStatus(grant, atMs) }))
      .sort((left, right) => left.createdAt.localeCompare(right.createdAt));
    return { grants: grants.map(presentGrant) };
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

export function grantStatus(
  grant: GrantRecord,
  atMs: number,
): 'active' | 'expired' | 'exhausted' | 'revoked' {
  if (grant.revokedAt !== undefined) return 'revoked';
  if (grant.expiresAt !== undefined && atMs > Date.parse(grant.expiresAt))
    return 'expired';
  if (grant.maxUses !== undefined && grant.usedCount >= grant.maxUses)
    return 'exhausted';
  return 'active';
}

export function presentGrant(
  grant: GrantRecord & { status: string },
): Record<string, unknown> {
  return {
    grantId: grant.grantId,
    secret: grant.secret,
    commands: [...grant.commands],
    status: grant.status,
    usedCount: grant.usedCount,
    ...(grant.maxUses === undefined ? {} : { maxUses: grant.maxUses }),
    ...(grant.expiresAt === undefined ? {} : { expiresAt: grant.expiresAt }),
    ...(grant.lastUsedAt === undefined ? {} : { lastUsedAt: grant.lastUsedAt }),
    createdAt: grant.createdAt,
  };
}

function assembleEntry(options: PolicyCreateOptions): PermissionEntry {
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
