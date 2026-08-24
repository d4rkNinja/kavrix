import { realpathSync } from 'node:fs';

import {
  authorizationDecisionSchema,
  parseDurationToMs,
  type AuthorizationDecision,
  type GrantRecord,
  type PermissionEntry,
} from '@kavrix/schemas';

export type PolicyLike = Readonly<{ id: string; entry: PermissionEntry }>;

export type ExecutableFacts = Readonly<{
  displayName: string;
  sha256: string | undefined;
  firstArgument: string | undefined;
}>;

export type EvaluationContext = Readonly<{
  platform: NodeJS.Platform;
  facts: ExecutableFacts;
  nowIso: string;
  /** Real path of the invocation working directory, when the caller resolved it. */
  cwdRealPath?: string | undefined;
}>;

/**
 * Working-directory restriction: a policy may bind use to invocations launched
 * inside one directory subtree. Comparison is exact-prefix on canonical real
 * paths (case-insensitive on Windows), so symlinked spellings of the same
 * directory always match and sibling directories never do.
 */
export function matchesWorkingDirectory(
  restrictedTo: string,
  cwdRealPath: string,
  platform: NodeJS.Platform,
): boolean {
  const normalize = (value: string): string => {
    let normalized = value.replace(/[\\/]+$/u, '');
    if (platform === 'win32') {
      normalized = normalized.replaceAll('/', '\\').toLowerCase();
    }
    return normalized;
  };
  const base = normalize(restrictedTo);
  const actual = normalize(cwdRealPath);
  if (actual === base) return true;
  return (
    (actual.startsWith(`${base}\\`) && platform === 'win32') ||
    (actual.startsWith(`${base}/`) && platform !== 'win32')
  );
}

/**
 * Canonicalizes a directory path through realpath, falling back to the input
 * when the path cannot be resolved (the caller fails closed downstream).
 */
export function canonicalizeDirectory(path: string): string {
  try {
    return realpathSync(path);
  } catch {
    return path;
  }
}

/**
 * Evaluates one explicitly attached permission entry against a resolved
 * executable. This is the single decision procedure for `run --policy`,
 * project policies, and agent firewall permissions; deny entries are checked
 * by the caller before this function runs.
 */
export function evaluatePermission(
  entry: PermissionEntry,
  context: EvaluationContext,
): AuthorizationDecision {
  if (entry.deny === true) {
    return deny('policy-denied', entry.secret);
  }
  const commands = entry.commands ?? [];
  const commandMatches = commands.some((command) =>
    sameCommand(command, context.facts.displayName, context.platform),
  );
  if (!commandMatches) {
    return deny('command-not-allowed', entry.secret);
  }
  const pin = entry.hashes?.[context.facts.displayName];
  if (pin !== undefined && pin !== context.facts.sha256) {
    return deny('hash-mismatch', entry.secret);
  }
  if (entry.workingDirectory !== undefined) {
    // Fail closed when no canonical cwd could be established.
    const inside =
      context.cwdRealPath !== undefined &&
      matchesWorkingDirectory(
        entry.workingDirectory,
        context.cwdRealPath,
        context.platform,
      );
    if (!inside) {
      return deny('working-directory-mismatch', entry.secret);
    }
  }
  if (requiresConfirmation(entry, context.facts.firstArgument)) {
    return authorizationDecisionSchema.parse({
      outcome: 'confirm',
      reason: 'confirmation-required',
      ...(entry.secret === undefined ? {} : { secret: entry.secret }),
    });
  }
  return allow('policy-allowed', entry.secret);
}

/** Whether one executable name matches a policy command for this platform. */
export function sameCommand(
  policyCommand: string,
  resolvedName: string,
  platform: NodeJS.Platform,
): boolean {
  return platform === 'win32'
    ? policyCommand.toLowerCase() === resolvedName.toLowerCase()
    : policyCommand === resolvedName;
}

export function requiresConfirmation(
  entry: PermissionEntry,
  firstArgument: string | undefined,
): boolean {
  const requirement = entry.requireConfirmation;
  if (requirement === undefined || requirement === false) return false;
  if (requirement === true) return true;
  return (
    firstArgument !== undefined && requirement.some((token) => token === firstArgument)
  );
}

/** Execution-window cap from an entry TTL; invalid durations fail closed. */
export function executionWindowMs(
  entry: PermissionEntry,
): number | 'invalid' | undefined {
  if (entry.ttl === undefined) return undefined;
  const parsed = parseDurationToMs(entry.ttl);
  return parsed ?? 'invalid';
}

/**
 * Reveal is a distinct permission from use: any stored policy covering the
 * credential that does not explicitly grant reveal blocks every reveal path.
 */
export function evaluateReveal(
  entries: readonly PermissionEntry[],
): AuthorizationDecision {
  const covering = entries.filter((entry) => entry.secret !== undefined);
  if (covering.length === 0) {
    return authorizationDecisionSchema.parse({
      outcome: 'allow',
      reason: 'no-applicable-policy',
    });
  }
  const denied = covering.some((entry) => entry.reveal !== true);
  if (denied) {
    return authorizationDecisionSchema.parse({
      outcome: 'deny',
      reason: 'reveal-forbidden-by-policy',
    });
  }
  return authorizationDecisionSchema.parse({
    outcome: 'allow',
    reason: 'policy-allowed',
  });
}

export type GrantEvaluation =
  | Readonly<{ status: 'allowed'; grant: GrantRecord }>
  | Readonly<{
      status: 'denied';
      reason:
        | 'clock-invalid'
        | 'revoked'
        | 'expired'
        | 'exhausted'
        | 'command-not-allowed'
        | 'hash-mismatch';
    }>;

/**
 * Validates one temporary grant against wall-clock time and the resolved
 * executable. Consumption itself happens under the sealed-state lock so two
 * concurrent invocations can never both claim the final use.
 */
export function evaluateGrantUse(
  grant: GrantRecord,
  context: EvaluationContext,
): GrantEvaluation {
  const createdAtMs = Date.parse(grant.createdAt);
  const nowMs = Date.parse(context.nowIso);
  if (!Number.isFinite(createdAtMs) || !Number.isFinite(nowMs)) {
    return { status: 'denied', reason: 'clock-invalid' };
  }
  if (nowMs < createdAtMs - CLOCK_SKEW_MS) {
    return { status: 'denied', reason: 'clock-invalid' };
  }
  if (grant.revokedAt !== undefined) return { status: 'denied', reason: 'revoked' };
  if (
    grant.expiresAt !== undefined &&
    nowMs > Date.parse(grant.expiresAt) + CLOCK_SKEW_MS
  ) {
    return { status: 'denied', reason: 'expired' };
  }
  if (grant.maxUses !== undefined && grant.usedCount >= grant.maxUses) {
    return { status: 'denied', reason: 'exhausted' };
  }
  const matchesCommand = grant.commands.some((command) =>
    sameCommand(command, context.facts.displayName, context.platform),
  );
  if (!matchesCommand) return { status: 'denied', reason: 'command-not-allowed' };
  const pin = grant.hashes?.[context.facts.displayName];
  if (pin !== undefined && pin !== context.facts.sha256) {
    return { status: 'denied', reason: 'hash-mismatch' };
  }
  return { status: 'allowed', grant };
}

const CLOCK_SKEW_MS = 0;

function allow(
  reason: 'no-applicable-policy' | 'policy-allowed' | 'grant-allowed',
  secret?: string,
): AuthorizationDecision {
  return authorizationDecisionSchema.parse({
    outcome: 'allow',
    reason,
    ...(secret === undefined ? {} : { secret }),
  });
}

type DenyReason = Extract<AuthorizationDecision, { outcome: 'deny' }>['reason'];

function deny(reason: DenyReason, secret?: string): AuthorizationDecision {
  return authorizationDecisionSchema.parse({
    outcome: 'deny',
    reason,
    ...(secret === undefined ? {} : { secret }),
  });
}
