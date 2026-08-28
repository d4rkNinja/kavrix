import { statSync } from 'node:fs';

import {
  authorizationDecisionSchema,
  parseDurationToMs,
  type AuthorizationDecision,
  type GrantRecord,
  type PermissionEntry,
  type RuntimeAuditEvent,
  type StoredPolicyRecord,
} from '@kavrix/schemas';

import type { AuthorizationStateSnapshot } from './authorization-state.js';
import {
  executionWindowMs,
  matchesWorkingDirectory,
  requiresConfirmation,
  sameCommand,
  type EvaluationContext,
} from './engine.js';
import { invalidConfiguration } from './exit-codes.js';

export type PolicyRuleKind =
  'deny' | 'command' | 'hash' | 'directory' | 'ttl' | 'confirmation';

export type PolicyRuleStatus =
  'matched' | 'not-matched' | 'applied' | 'not-configured' | 'not-evaluated';

export type PolicyRuleTrace = Readonly<{
  order: number;
  kind: PolicyRuleKind;
  status: PolicyRuleStatus;
  effect: 'allow' | 'deny' | 'limit' | 'confirm' | 'none';
  policyId: string;
  expected?: unknown;
  actual?: unknown;
  relatedPolicyId?: string;
  note: string;
}>;

export type PolicyExplanation = Readonly<{
  policyId: string;
  secret: string | null;
  command: string;
  credentialRead: false;
  decision: AuthorizationDecision;
  executionWindowMs: number | null;
  checks: readonly PolicyRuleTrace[];
}>;

/**
 * Produces the ordered rule trace for one stored policy. The order mirrors the
 * real execution firewall and never reads a credential or mutates audit state.
 */
export function explainPolicyEvaluation(
  policyId: string,
  entry: PermissionEntry,
  storedPolicies: Readonly<Record<string, StoredPolicyRecord>>,
  context: EvaluationContext,
): PolicyExplanation {
  const checks: PolicyRuleTrace[] = [];
  let order = 1;
  const push = (trace: Omit<PolicyRuleTrace, 'order'>): void => {
    checks.push({ order, ...trace });
    order += 1;
  };
  const secret = entry.secret ?? null;
  const coveringDeny =
    entry.secret === undefined
      ? undefined
      : Object.entries(storedPolicies).find(
          ([, record]) =>
            record.definition.deny === true &&
            record.definition.secret === entry.secret,
        );

  push({
    kind: 'deny',
    status: coveringDeny === undefined ? 'not-matched' : 'matched',
    effect: coveringDeny === undefined ? 'none' : 'deny',
    policyId,
    ...(coveringDeny === undefined ? {} : { relatedPolicyId: coveringDeny[0] }),
    note:
      coveringDeny === undefined
        ? 'No stored deny covers this credential.'
        : 'A stored deny covering this credential takes precedence.',
  });
  if (coveringDeny !== undefined) {
    return explanation(
      policyId,
      secret,
      context.facts.displayName,
      authorizationDecisionSchema.parse({
        outcome: 'deny',
        reason: 'policy-denied',
        policyId: coveringDeny[0],
        ...(entry.secret === undefined ? {} : { secret: entry.secret }),
      }),
      null,
      withSkippedChecks(checks, order, policyId),
    );
  }

  if (entry.deny === true) {
    push({
      kind: 'deny',
      status: 'matched',
      effect: 'deny',
      policyId,
      note: 'The selected policy is an unconditional deny.',
    });
    return explanation(
      policyId,
      secret,
      context.facts.displayName,
      authorizationDecisionSchema.parse({
        outcome: 'deny',
        reason: 'policy-denied',
        policyId,
        ...(entry.secret === undefined ? {} : { secret: entry.secret }),
      }),
      null,
      withSkippedChecks(checks, order, policyId),
    );
  }

  const commands = entry.commands ?? [];
  const commandMatched = commands.some((command) =>
    sameCommand(command, context.facts.displayName, context.platform),
  );
  push({
    kind: 'command',
    status: commandMatched ? 'matched' : 'not-matched',
    effect: commandMatched ? 'allow' : 'deny',
    policyId,
    expected: [...commands],
    actual: context.facts.displayName,
    note: commandMatched
      ? 'The resolved executable is in the command allowlist.'
      : 'The resolved executable is not in the command allowlist.',
  });
  if (!commandMatched) {
    return terminalExplanation(
      policyId,
      entry,
      context,
      checks,
      order,
      'command-not-allowed',
    );
  }

  const pin = entry.hashes?.[context.facts.displayName];
  if (pin === undefined) {
    push({
      kind: 'hash',
      status: 'not-configured',
      effect: 'none',
      policyId,
      expected: entry.hashes === undefined ? [] : Object.keys(entry.hashes),
      actual: context.facts.sha256 ?? null,
      note:
        entry.hashes === undefined
          ? 'No executable hash pin is configured.'
          : 'No hash pin is keyed by the resolved executable name.',
    });
  } else {
    const hashMatched = pin === context.facts.sha256;
    push({
      kind: 'hash',
      status: hashMatched ? 'matched' : 'not-matched',
      effect: hashMatched ? 'allow' : 'deny',
      policyId,
      expected: pin,
      actual: context.facts.sha256 ?? null,
      note: hashMatched
        ? 'The executable SHA-256 digest matches the configured pin.'
        : 'The executable SHA-256 digest does not match the configured pin.',
    });
    if (!hashMatched) {
      return terminalExplanation(
        policyId,
        entry,
        context,
        checks,
        order,
        'hash-mismatch',
      );
    }
  }

  if (entry.workingDirectory === undefined) {
    push({
      kind: 'directory',
      status: 'not-configured',
      effect: 'none',
      policyId,
      actual: context.cwdRealPath ?? null,
      note: 'No working-directory restriction is configured.',
    });
  } else {
    const directoryMatched =
      context.cwdRealPath !== undefined &&
      matchesWorkingDirectory(
        entry.workingDirectory,
        context.cwdRealPath,
        context.platform,
      );
    push({
      kind: 'directory',
      status: directoryMatched ? 'matched' : 'not-matched',
      effect: directoryMatched ? 'allow' : 'deny',
      policyId,
      expected: entry.workingDirectory,
      actual: context.cwdRealPath ?? null,
      note: directoryMatched
        ? 'The invocation directory is inside the allowed subtree.'
        : 'The invocation directory is outside the allowed subtree.',
    });
    if (!directoryMatched) {
      return terminalExplanation(
        policyId,
        entry,
        context,
        checks,
        order,
        'working-directory-mismatch',
      );
    }
  }

  const executionWindow = executionWindowMs(entry);
  if (executionWindow === 'invalid') {
    throw invalidConfiguration(
      `Policy '${policyId}' declares a TTL above the supported maximum.`,
    );
  }
  push({
    kind: 'ttl',
    status: executionWindow === undefined ? 'not-configured' : 'applied',
    effect: executionWindow === undefined ? 'none' : 'limit',
    policyId,
    ...(entry.ttl === undefined ? {} : { expected: entry.ttl }),
    ...(executionWindow === undefined ? {} : { actual: executionWindow }),
    note:
      executionWindow === undefined
        ? 'No execution-window cap is configured.'
        : 'The TTL caps each child execution; it is not a policy expiry.',
  });

  const confirmationMatched = requiresConfirmation(entry, context.facts.firstArgument);
  push({
    kind: 'confirmation',
    status:
      entry.requireConfirmation === undefined || entry.requireConfirmation === false
        ? 'not-configured'
        : confirmationMatched
          ? 'matched'
          : 'not-matched',
    effect: confirmationMatched ? 'confirm' : 'none',
    policyId,
    ...(entry.requireConfirmation === undefined
      ? {}
      : { expected: entry.requireConfirmation }),
    actual: context.facts.firstArgument ?? null,
    note: confirmationMatched
      ? 'This invocation requires operator confirmation.'
      : 'This invocation does not match a confirmation requirement.',
  });

  const decision = authorizationDecisionSchema.parse({
    outcome: confirmationMatched ? 'confirm' : 'allow',
    reason: confirmationMatched ? 'confirmation-required' : 'policy-allowed',
    policyId,
    ...(entry.secret === undefined ? {} : { secret: entry.secret }),
  });
  return explanation(
    policyId,
    secret,
    context.facts.displayName,
    decision,
    executionWindow ?? null,
    checks,
  );
}

function terminalExplanation(
  policyId: string,
  entry: PermissionEntry,
  context: EvaluationContext,
  checks: readonly PolicyRuleTrace[],
  nextOrder: number,
  reason: 'command-not-allowed' | 'hash-mismatch' | 'working-directory-mismatch',
): PolicyExplanation {
  return explanation(
    policyId,
    entry.secret ?? null,
    context.facts.displayName,
    authorizationDecisionSchema.parse({
      outcome: 'deny',
      reason,
      policyId,
      ...(entry.secret === undefined ? {} : { secret: entry.secret }),
    }),
    null,
    withSkippedChecks(checks, nextOrder, policyId),
  );
}

function explanation(
  policyId: string,
  secret: string | null,
  command: string,
  decision: AuthorizationDecision,
  executionWindowMs: number | null,
  checks: readonly PolicyRuleTrace[],
): PolicyExplanation {
  return {
    policyId,
    secret,
    command,
    credentialRead: false,
    decision,
    executionWindowMs,
    checks,
  };
}

function withSkippedChecks(
  current: readonly PolicyRuleTrace[],
  firstOrder: number,
  policyId: string,
): readonly PolicyRuleTrace[] {
  const present = new Set(current.map((check) => check.kind));
  let order = firstOrder;
  const skipped: PolicyRuleTrace[] = [];
  for (const kind of ['command', 'hash', 'directory', 'ttl', 'confirmation'] as const) {
    if (present.has(kind)) continue;
    skipped.push({
      order,
      kind,
      status: 'not-evaluated',
      effect: 'none',
      policyId,
      note: 'An earlier terminal rule stopped evaluation.',
    });
    order += 1;
  }
  return [...current, ...skipped];
}

export type PolicyLintFinding = Readonly<{
  severity: 'error' | 'warning';
  category: 'shadowed' | 'impossible' | 'overly-broad' | 'expired';
  code: string;
  targetType: 'policy' | 'grant';
  targetId: string;
  relatedIds?: readonly string[];
  details?: readonly string[];
  message: string;
}>;

export type PolicyLintResult = Readonly<{
  checkedPolicies: number;
  checkedGrants: number;
  errors: number;
  warnings: number;
  findings: readonly PolicyLintFinding[];
}>;

/** Deterministic semantic lint over authenticated authorization metadata. */
export function lintAuthorizationState(
  snapshot: AuthorizationStateSnapshot,
  atMs: number,
  platform: NodeJS.Platform = process.platform,
  directoryExists: (path: string) => boolean = isDirectory,
): PolicyLintResult {
  const findings: PolicyLintFinding[] = [];
  const policies = Object.entries(snapshot.policies).sort(([left], [right]) =>
    left.localeCompare(right),
  );
  const denies = policies.filter(([, record]) => record.definition.deny === true);

  for (const [policyId, record] of policies) {
    const entry = record.definition;
    if (entry.deny === true) {
      if (entry.secret === undefined) {
        findings.push({
          severity: 'warning',
          category: 'impossible',
          code: 'deny-without-credential-scope',
          targetType: 'policy',
          targetId: policyId,
          message:
            'An unscoped deny has no automatic firewall effect; it only denies when selected explicitly.',
        });
      }
      continue;
    }

    const shadowingDenies = denies
      .filter(([, deny]) => deny.definition.secret === entry.secret)
      .map(([denyId]) => denyId);
    if (shadowingDenies.length > 0) {
      findings.push({
        severity: 'error',
        category: 'shadowed',
        code: 'credential-covered-by-deny',
        targetType: 'policy',
        targetId: policyId,
        relatedIds: shadowingDenies,
        message: 'A stored deny covering this credential prevents this allow policy.',
      });
    }

    const duplicateCommands = duplicates(entry.commands ?? [], platform);
    if (duplicateCommands.length > 0) {
      findings.push({
        severity: 'warning',
        category: 'shadowed',
        code: 'duplicate-command-rules',
        targetType: 'policy',
        targetId: policyId,
        details: duplicateCommands,
        message: 'Duplicate command entries add no effective restriction.',
      });
    }

    if (entry.maxUses !== undefined) {
      findings.push({
        severity: 'warning',
        category: 'impossible',
        code: 'max-uses-not-enforced-for-direct-policy',
        targetType: 'policy',
        targetId: policyId,
        message:
          'maxUses does not limit direct policy execution; use a consumable grant for use-count enforcement.',
      });
    }

    if (entry.ttl !== undefined && parseDurationToMs(entry.ttl) === undefined) {
      findings.push({
        severity: 'error',
        category: 'impossible',
        code: 'invalid-execution-window',
        targetType: 'policy',
        targetId: policyId,
        message: 'The execution-window TTL is not representable by this client.',
      });
    }

    if (
      entry.workingDirectory !== undefined &&
      !directoryExists(entry.workingDirectory)
    ) {
      findings.push({
        severity: 'error',
        category: 'impossible',
        code: 'working-directory-unavailable',
        targetType: 'policy',
        targetId: policyId,
        message: 'The configured working directory is unavailable on this host.',
      });
    }

    if (
      platform === 'win32' &&
      Object.keys(entry.hashes ?? {}).some(
        (command) => command !== command.toLowerCase(),
      )
    ) {
      findings.push({
        severity: 'error',
        category: 'impossible',
        code: 'windows-hash-pin-case-mismatch',
        targetType: 'policy',
        targetId: policyId,
        message:
          'Windows resolves policy command names to lowercase, so a mixed-case hash key cannot bind.',
      });
    }

    const missingRestrictions = [
      entry.hashes === undefined ? 'hash-pin' : undefined,
      entry.workingDirectory === undefined ? 'working-directory' : undefined,
      entry.ttl === undefined ? 'execution-window' : undefined,
      entry.requireConfirmation === undefined || entry.requireConfirmation === false
        ? 'confirmation'
        : undefined,
    ].filter((value): value is string => value !== undefined);
    if (missingRestrictions.length >= 3 || entry.reveal === true) {
      findings.push({
        severity: 'warning',
        category: 'overly-broad',
        code: 'few-narrowing-controls',
        targetType: 'policy',
        targetId: policyId,
        details: [
          ...missingRestrictions,
          ...(entry.reveal === true ? ['plaintext-reveal'] : []),
        ],
        message:
          'This policy has few narrowing controls and should receive an explicit least-privilege review.',
      });
    }
  }

  for (const grant of Object.values(snapshot.grants).sort((left, right) =>
    left.grantId.localeCompare(right.grantId),
  )) {
    if (grant.expiresAt !== undefined && atMs > Date.parse(grant.expiresAt)) {
      findings.push({
        severity: 'warning',
        category: 'expired',
        code: 'expired-grant-retained',
        targetType: 'grant',
        targetId: grant.grantId,
        message: 'This expired grant remains in the bounded authorization state.',
      });
    }
  }

  findings.sort(compareFindings);
  return {
    checkedPolicies: policies.length,
    checkedGrants: Object.keys(snapshot.grants).length,
    errors: findings.filter((finding) => finding.severity === 'error').length,
    warnings: findings.filter((finding) => finding.severity === 'warning').length,
    findings,
  };
}

function isDirectory(path: string): boolean {
  try {
    return statSync(path).isDirectory();
  } catch {
    return false;
  }
}

function duplicates(
  values: readonly string[],
  platform: NodeJS.Platform,
): readonly string[] {
  const seen = new Set<string>();
  const repeated = new Set<string>();
  for (const value of values) {
    const comparable = platform === 'win32' ? value.toLowerCase() : value;
    if (seen.has(comparable)) repeated.add(comparable);
    seen.add(comparable);
  }
  return [...repeated].sort();
}

function compareFindings(left: PolicyLintFinding, right: PolicyLintFinding): number {
  const severity =
    left.severity === right.severity ? 0 : left.severity === 'error' ? -1 : 1;
  return (
    severity ||
    left.targetType.localeCompare(right.targetType) ||
    left.targetId.localeCompare(right.targetId) ||
    left.code.localeCompare(right.code)
  );
}

const DIFF_FIELDS = [
  'secret',
  'commands',
  'hashes',
  'env',
  'reveal',
  'ttl',
  'maxUses',
  'requireConfirmation',
  'workingDirectory',
  'deny',
] as const;

export type PolicyDiffChange = Readonly<{
  field: (typeof DIFF_FIELDS)[number];
  before: unknown;
  after: unknown;
  impact: 'tightens' | 'widens' | 'changes';
}>;

export type PolicyDiffResult = Readonly<{
  id: string;
  operation: 'add' | 'replace' | 'unchanged';
  changed: boolean;
  before: Readonly<Record<string, unknown>> | null;
  after: Readonly<Record<string, unknown>>;
  changes: readonly PolicyDiffChange[];
}>;

/** Semantic diff for the exact policy definition that `policy create` would store. */
export function diffPolicyDefinition(
  id: string,
  current: PermissionEntry | undefined,
  proposed: PermissionEntry,
  platform: NodeJS.Platform = process.platform,
): PolicyDiffResult {
  const before = current === undefined ? null : canonicalEntry(current, platform);
  const after = canonicalEntry(proposed, platform);
  const changes: PolicyDiffChange[] = [];
  for (const field of DIFF_FIELDS) {
    const prior = before?.[field] ?? null;
    const next = after[field] ?? null;
    if (JSON.stringify(prior) === JSON.stringify(next)) continue;
    changes.push({
      field,
      before: prior,
      after: next,
      impact: diffImpact(field, prior, next),
    });
  }
  return {
    id,
    operation:
      current === undefined ? 'add' : changes.length === 0 ? 'unchanged' : 'replace',
    changed: changes.length > 0,
    before,
    after,
    changes,
  };
}

function canonicalEntry(
  entry: PermissionEntry,
  platform: NodeJS.Platform,
): Readonly<Record<string, unknown>> {
  const hashes =
    entry.hashes === undefined
      ? null
      : Object.fromEntries(
          Object.entries(entry.hashes).sort(([left], [right]) =>
            left.localeCompare(right),
          ),
        );
  return {
    secret: entry.secret ?? null,
    commands: uniqueSorted(
      (entry.commands ?? []).map((command) =>
        platform === 'win32' ? command.toLowerCase() : command,
      ),
    ),
    hashes,
    env: entry.env ?? null,
    reveal: entry.reveal === true,
    ttl: entry.ttl === undefined ? null : (parseDurationToMs(entry.ttl) ?? entry.ttl),
    maxUses: entry.maxUses ?? null,
    requireConfirmation: Array.isArray(entry.requireConfirmation)
      ? uniqueSorted(entry.requireConfirmation)
      : entry.requireConfirmation === true,
    workingDirectory: entry.workingDirectory ?? null,
    deny: entry.deny === true,
  };
}

function uniqueSorted(values: readonly string[]): readonly string[] {
  return [...new Set(values)].sort();
}

function diffImpact(
  field: PolicyDiffChange['field'],
  before: unknown,
  after: unknown,
): PolicyDiffChange['impact'] {
  if (field === 'deny' || field === 'reveal') {
    if (before === true && after === false)
      return field === 'deny' ? 'widens' : 'tightens';
    if (before === false && after === true)
      return field === 'deny' ? 'tightens' : 'widens';
  }
  if (field === 'commands' && Array.isArray(before) && Array.isArray(after)) {
    const removed = before.filter((value) => !after.includes(value));
    const added = after.filter((value) => !before.includes(value));
    if (removed.length > 0 && added.length === 0) return 'tightens';
    if (added.length > 0 && removed.length === 0) return 'widens';
    return 'changes';
  }
  if (field === 'hashes' || field === 'workingDirectory') {
    if (before !== null && after === null) return 'widens';
    if (before === null && after !== null) return 'tightens';
  }
  if (field === 'ttl' || field === 'maxUses') {
    if (before === null && typeof after === 'number') return 'tightens';
    if (typeof before === 'number' && after === null) return 'widens';
    if (typeof before === 'number' && typeof after === 'number') {
      return after < before ? 'tightens' : 'widens';
    }
  }
  if (field === 'requireConfirmation') {
    if (before === false && after !== false) return 'tightens';
    if (before !== false && after === false) return 'widens';
  }
  return 'changes';
}

export type PolicySuggestion = Readonly<{
  suggestionId: string;
  kind: 'narrow-command-allowlist';
  policyId: string;
  secret: string;
  reviewRequired: true;
  confidence: 'low';
  observedUses: number;
  evidenceSeq: readonly number[];
  currentCommands: readonly string[];
  observedCommands: readonly string[];
  proposedCommands: readonly string[];
  proposedDefinition: PermissionEntry;
}>;

export type PolicySuggestionResult = Readonly<{
  retainedAuditEvents: number;
  firstRetainedSeq: number | null;
  lastRetainedSeq: number | null;
  positiveAuthorizationEvents: number;
  reviewOnly: true;
  coverage: 'incomplete-bounded-audit-ring';
  limitations: readonly string[];
  suggestions: readonly PolicySuggestion[];
}>;

/**
 * Produces only monotonic tightening candidates. Absence in the bounded audit
 * ring is never treated as proof and no suggestion is applied automatically.
 */
export function suggestPolicyTightenings(
  policies: Readonly<Record<string, StoredPolicyRecord>>,
  audit: readonly RuntimeAuditEvent[],
  platform: NodeJS.Platform = process.platform,
): PolicySuggestionResult {
  const positive = audit.filter(
    (event) =>
      event.action === 'authorization-allowed' &&
      event.policyId !== undefined &&
      event.secret !== undefined &&
      event.command !== undefined,
  );
  const suggestions: PolicySuggestion[] = [];
  for (const [policyId, record] of Object.entries(policies).sort(([left], [right]) =>
    left.localeCompare(right),
  )) {
    const entry = record.definition;
    if (entry.deny === true || entry.secret === undefined) continue;
    const evidence = positive.filter(
      (event) => event.policyId === policyId && event.secret === entry.secret,
    );
    if (evidence.length === 0) continue;
    const observedCommands = [...new Set(evidence.map((event) => event.command))]
      .filter((command): command is string => command !== undefined)
      .sort();
    const proposedCommands = (entry.commands ?? []).filter((command) =>
      observedCommands.some((observed) => sameCommand(command, observed, platform)),
    );
    if (
      proposedCommands.length === 0 ||
      proposedCommands.length === (entry.commands ?? []).length
    ) {
      continue;
    }
    const hashes =
      entry.hashes === undefined
        ? undefined
        : Object.fromEntries(
            Object.entries(entry.hashes).filter(([command]) =>
              proposedCommands.includes(command),
            ),
          );
    const entryWithoutHashes = { ...entry };
    delete entryWithoutHashes.hashes;
    const proposedDefinition: PermissionEntry = {
      ...entryWithoutHashes,
      commands: proposedCommands,
      ...(hashes === undefined || Object.keys(hashes).length === 0 ? {} : { hashes }),
    };
    suggestions.push({
      suggestionId: `narrow-${policyId}`,
      kind: 'narrow-command-allowlist',
      policyId,
      secret: entry.secret,
      reviewRequired: true,
      confidence: 'low',
      observedUses: evidence.length,
      evidenceSeq: evidence.map((event) => event.seq),
      currentCommands: [...(entry.commands ?? [])],
      observedCommands,
      proposedCommands,
      proposedDefinition,
    });
  }
  return {
    retainedAuditEvents: audit.length,
    firstRetainedSeq: audit.at(0)?.seq ?? null,
    lastRetainedSeq: audit.at(-1)?.seq ?? null,
    positiveAuthorizationEvents: positive.length,
    reviewOnly: true,
    coverage: 'incomplete-bounded-audit-ring',
    limitations: [
      'No suggestion is applied automatically.',
      'Missing audit evidence does not prove a command is unused.',
      'Audit events do not contain executable hashes, working directories, or safe TTL evidence.',
      'Denied and failed events never create or widen an allow recommendation.',
    ],
    suggestions,
  };
}

export function grantInspection(
  grant: GrantRecord,
  atMs: number,
  status: 'active' | 'expired' | 'exhausted' | 'revoked' | 'clock-invalid',
): Readonly<Record<string, unknown>> {
  const remainingUses =
    grant.maxUses === undefined ? null : Math.max(0, grant.maxUses - grant.usedCount);
  const expiresInMs =
    grant.expiresAt === undefined
      ? null
      : Math.max(0, Date.parse(grant.expiresAt) - atMs);
  return {
    grantId: grant.grantId,
    secret: grant.secret,
    status,
    usedCount: grant.usedCount,
    ...(grant.maxUses === undefined ? {} : { maxUses: grant.maxUses }),
    remainingUses,
    ...(grant.expiresAt === undefined ? {} : { expiresAt: grant.expiresAt }),
    expiresInMs,
    ...(grant.lastUsedAt === undefined ? {} : { lastUsedAt: grant.lastUsedAt }),
    ...(grant.revokedAt === undefined ? {} : { revokedAt: grant.revokedAt }),
    createdAt: grant.createdAt,
    restrictions: {
      actor: grant.actor,
      commands: [...grant.commands],
      hashes: grant.hashes ?? {},
      remainingUses,
      expiresAt: grant.expiresAt ?? null,
      revoked: grant.revokedAt !== undefined,
    },
    injection: { environmentVariable: grant.env ?? null },
    provenance: {
      createdByPolicyId: grant.createdByPolicyId ?? null,
      agentPermissionKey: grant.agentPermissionKey ?? null,
    },
    commands: [...grant.commands],
    ...(grant.hashes === undefined ? {} : { hashes: grant.hashes }),
    ...(grant.env === undefined ? {} : { env: grant.env }),
    actor: grant.actor,
  };
}
