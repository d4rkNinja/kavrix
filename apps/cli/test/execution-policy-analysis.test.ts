import {
  permissionEntrySchema,
  runtimeAuditEventSchema,
  storedPolicyRecordSchema,
  type GrantRecord,
  type StoredPolicyRecord,
} from '@kavrix/schemas';
import { describe, expect, it } from 'vitest';

import type { AuthorizationStateSnapshot } from '../src/execution/authorization-state.js';
import { evaluatePermission, type EvaluationContext } from '../src/execution/engine.js';
import {
  diffPolicyDefinition,
  explainPolicyEvaluation,
  grantInspection,
  lintAuthorizationState,
  suggestPolicyTightenings,
} from '../src/execution/policy-analysis.js';

const CREATED_AT = '2026-08-27T09:00:00.000Z';
const SHA_A = 'a'.repeat(64);
const SHA_B = 'b'.repeat(64);

function stored(definition: unknown): StoredPolicyRecord {
  return storedPolicyRecordSchema.parse({ definition, createdAt: CREATED_AT });
}

function context(
  overrides: Partial<EvaluationContext['facts']> = {},
): EvaluationContext {
  return {
    platform: 'win32',
    facts: {
      displayName: 'node',
      sha256: SHA_A,
      firstArgument: 'deploy',
      ...overrides,
    },
    nowIso: CREATED_AT,
    cwdRealPath: 'C:\\repo\\child',
  };
}

describe('policy explanation', () => {
  it('traces the firewall order and agrees with the execution engine', () => {
    const definition = permissionEntrySchema.parse({
      secret: 'service/token',
      commands: ['node'],
      hashes: { node: SHA_A },
      workingDirectory: 'C:\\repo',
      ttl: '30s',
      requireConfirmation: ['deploy'],
    });
    const policies = { selected: stored(definition) };
    const explained = explainPolicyEvaluation(
      'selected',
      definition,
      policies,
      context(),
    );

    expect(explained.credentialRead).toBe(false);
    expect(explained.decision).toEqual({
      outcome: 'confirm',
      reason: 'confirmation-required',
      policyId: 'selected',
      secret: 'service/token',
    });
    expect(explained.decision).toMatchObject(evaluatePermission(definition, context()));
    expect(explained.executionWindowMs).toBe(30_000);
    expect(explained.checks.map((check) => check.kind)).toEqual([
      'deny',
      'command',
      'hash',
      'directory',
      'ttl',
      'confirmation',
    ]);
    expect(explained.checks.map((check) => check.order)).toEqual([1, 2, 3, 4, 5, 6]);
    expect(explained.checks.find((check) => check.kind === 'ttl')?.note).toContain(
      'not a policy expiry',
    );
  });

  it('shows a covering deny and marks later checks as unevaluated', () => {
    const allowed = permissionEntrySchema.parse({
      secret: 'service/token',
      commands: ['node'],
    });
    const policies = {
      allowed: stored(allowed),
      blocked: stored({ secret: 'service/token', deny: true }),
    };
    const explained = explainPolicyEvaluation('allowed', allowed, policies, context());

    expect(explained.decision).toMatchObject({
      outcome: 'deny',
      reason: 'policy-denied',
      policyId: 'blocked',
    });
    expect(explained.checks[0]).toMatchObject({
      kind: 'deny',
      status: 'matched',
      relatedPolicyId: 'blocked',
    });
    expect(
      explained.checks.slice(1).every((check) => check.status === 'not-evaluated'),
    ).toBe(true);
  });

  it('fails closed on a TTL that real execution cannot represent', () => {
    const definition = permissionEntrySchema.parse({
      secret: 'service/token',
      commands: ['node'],
      ttl: '31d',
    });
    expect(() =>
      explainPolicyEvaluation(
        'selected',
        definition,
        { selected: stored(definition) },
        context(),
      ),
    ).toThrow(/TTL above the supported maximum/u);
  });

  it('covers each terminal rule and unconfigured rule variant', () => {
    const selectedDeny = permissionEntrySchema.parse({ deny: true });
    const denied = explainPolicyEvaluation(
      'deny-all',
      selectedDeny,
      { 'deny-all': stored(selectedDeny) },
      context(),
    );
    expect(denied.secret).toBeNull();
    expect(denied.decision).toEqual({
      outcome: 'deny',
      reason: 'policy-denied',
      policyId: 'deny-all',
    });
    const scopedDeny = permissionEntrySchema.parse({
      secret: 'service/token',
      deny: true,
    });
    expect(
      explainPolicyEvaluation(
        'scoped-deny',
        scopedDeny,
        { 'scoped-deny': stored(scopedDeny) },
        context(),
      ).decision,
    ).toMatchObject({ secret: 'service/token' });

    const commandDenied = permissionEntrySchema.parse({
      secret: 'service/token',
      commands: ['git'],
    });
    expect(
      explainPolicyEvaluation(
        'command',
        commandDenied,
        { command: stored(commandDenied) },
        context(),
      ).decision,
    ).toMatchObject({ outcome: 'deny', reason: 'command-not-allowed' });

    const hashDenied = permissionEntrySchema.parse({
      secret: 'service/token',
      commands: ['node'],
      hashes: { node: SHA_B },
    });
    expect(
      explainPolicyEvaluation(
        'hash',
        hashDenied,
        { hash: stored(hashDenied) },
        context({ sha256: undefined }),
      ).decision,
    ).toMatchObject({ outcome: 'deny', reason: 'hash-mismatch' });

    const directoryDenied = permissionEntrySchema.parse({
      secret: 'service/token',
      commands: ['node'],
      workingDirectory: 'C:\\elsewhere',
    });
    expect(
      explainPolicyEvaluation(
        'directory',
        directoryDenied,
        { directory: stored(directoryDenied) },
        { ...context(), cwdRealPath: undefined },
      ).decision,
    ).toMatchObject({ outcome: 'deny', reason: 'working-directory-mismatch' });

    const unconfigured = permissionEntrySchema.parse({
      secret: 'service/token',
      commands: ['node', 'git'],
      hashes: { git: SHA_A },
    });
    const allowed = explainPolicyEvaluation(
      'plain',
      unconfigured,
      { plain: stored(unconfigured) },
      {
        ...context({ firstArgument: undefined, sha256: undefined }),
        cwdRealPath: undefined,
      },
    );
    expect(allowed.decision).toMatchObject({ outcome: 'allow' });
    expect(allowed.executionWindowMs).toBeNull();
    expect(allowed.checks.map(({ kind, status }) => [kind, status])).toEqual([
      ['deny', 'not-matched'],
      ['command', 'matched'],
      ['hash', 'not-configured'],
      ['directory', 'not-configured'],
      ['ttl', 'not-configured'],
      ['confirmation', 'not-configured'],
    ]);
  });

  it('explains matching optional restrictions without confirmation', () => {
    const definition = permissionEntrySchema.parse({
      secret: 'service/token',
      commands: ['node'],
      hashes: { node: SHA_A },
      workingDirectory: 'C:\\repo',
      ttl: '1m',
      requireConfirmation: ['publish'],
    });
    const result = explainPolicyEvaluation(
      'restricted',
      definition,
      { restricted: stored(definition) },
      context({ firstArgument: 'status' }),
    );
    expect(result.decision).toMatchObject({ outcome: 'allow' });
    expect(result.checks.find(({ kind }) => kind === 'hash')).toMatchObject({
      status: 'matched',
    });
    expect(result.checks.find(({ kind }) => kind === 'directory')).toMatchObject({
      status: 'matched',
    });
    expect(result.checks.find(({ kind }) => kind === 'confirmation')).toMatchObject({
      status: 'not-matched',
    });
  });
});

describe('policy lint and diff', () => {
  it('finds shadowed, impossible, broad, and expired authorization records', () => {
    const snapshot: AuthorizationStateSnapshot = {
      policies: {
        allowed: stored({
          secret: 'service/token',
          commands: ['Node', 'Node'],
          hashes: { Node: SHA_A },
          maxUses: 2,
          reveal: true,
          workingDirectory: 'Z:\\definitely-missing',
        }),
        blocked: stored({ secret: 'service/token', deny: true }),
        unscoped: stored({ deny: true }),
      },
      grants: {
        grant_old: {
          grantId: 'grant_old',
          secret: 'service/token',
          actor: 'user',
          commands: ['node'],
          createdAt: '2026-08-26T09:00:00.000Z',
          expiresAt: '2026-08-26T10:00:00.000Z',
          usedCount: 0,
        },
      },
      audit: [],
    };

    const result = lintAuthorizationState(
      snapshot,
      Date.parse(CREATED_AT),
      'win32',
      () => false,
    );
    const codes = result.findings.map((finding) => finding.code);

    expect(codes).toEqual(
      expect.arrayContaining([
        'credential-covered-by-deny',
        'duplicate-command-rules',
        'max-uses-not-enforced-for-direct-policy',
        'working-directory-unavailable',
        'windows-hash-pin-case-mismatch',
        'few-narrowing-controls',
        'deny-without-credential-scope',
        'expired-grant-retained',
      ]),
    );
    expect(result.errors).toBeGreaterThan(0);
    expect(result.warnings).toBeGreaterThan(0);
  });

  it('classifies narrowing and widening changes without mutating either definition', () => {
    const current = permissionEntrySchema.parse({
      secret: 'service/token',
      commands: ['git', 'node'],
      ttl: '1h',
    });
    const proposed = permissionEntrySchema.parse({
      secret: 'service/token',
      commands: ['node'],
      ttl: '30m',
      requireConfirmation: true,
    });
    const currentBefore = structuredClone(current);
    const proposedBefore = structuredClone(proposed);
    const result = diffPolicyDefinition('selected', current, proposed);

    expect(result.operation).toBe('replace');
    expect(result.changed).toBe(true);
    expect(result.changes).toEqual(
      expect.arrayContaining([
        expect.objectContaining({ field: 'commands', impact: 'tightens' }),
        expect.objectContaining({ field: 'ttl', impact: 'tightens' }),
        expect.objectContaining({
          field: 'requireConfirmation',
          impact: 'tightens',
        }),
      ]),
    );
    expect(current).toEqual(currentBefore);
    expect(proposed).toEqual(proposedBefore);
  });

  it('classifies mixed command replacement and normalizes Windows command identity', () => {
    const current = permissionEntrySchema.parse({
      secret: 'service/token',
      commands: ['Node', 'git'],
    });
    const mixed = permissionEntrySchema.parse({
      secret: 'service/token',
      commands: ['node', 'python'],
    });
    const caseOnly = permissionEntrySchema.parse({
      secret: 'service/token',
      commands: ['node', 'git'],
    });

    expect(
      diffPolicyDefinition('selected', current, mixed, 'win32').changes.find(
        (change) => change.field === 'commands',
      ),
    ).toMatchObject({ impact: 'changes' });
    expect(diffPolicyDefinition('selected', current, caseOnly, 'win32').changed).toBe(
      false,
    );
  });

  it('covers clean lint inputs and platform-specific duplicate identity', () => {
    const clean = stored({
      secret: 'service/token',
      commands: ['Node', 'node'],
      hashes: { node: SHA_A },
      workingDirectory: '/repo',
      ttl: '1m',
      requireConfirmation: true,
    });
    const snapshot: AuthorizationStateSnapshot = {
      policies: { clean },
      grants: {
        live: {
          grantId: 'live',
          secret: 'service/token',
          actor: 'user',
          commands: [],
          createdAt: CREATED_AT,
          usedCount: 0,
        },
      },
      audit: [],
    };
    const linux = lintAuthorizationState(
      snapshot,
      Date.parse(CREATED_AT),
      'linux',
      () => true,
    );
    expect(linux.errors).toBe(0);
    expect(linux.findings.map(({ code }) => code)).not.toContain(
      'duplicate-command-rules',
    );

    const windows = lintAuthorizationState(
      snapshot,
      Date.parse(CREATED_AT),
      'win32',
      () => true,
    );
    expect(windows.findings.map(({ code }) => code)).toContain(
      'duplicate-command-rules',
    );
  });

  it('checks working directories with the default filesystem probe', () => {
    const snapshot: AuthorizationStateSnapshot = {
      policies: {
        available: stored({
          secret: 'service/available',
          commands: ['node'],
          hashes: { node: SHA_A },
          workingDirectory: process.cwd(),
          ttl: '1m',
          requireConfirmation: true,
        }),
        missing: stored({
          secret: 'service/missing',
          commands: ['node'],
          hashes: { node: SHA_A },
          workingDirectory: `${process.cwd()}\\definitely-not-present-kavrix`,
          ttl: '1m',
          requireConfirmation: true,
        }),
      },
      grants: {},
      audit: [],
    };
    const result = lintAuthorizationState(snapshot, Date.parse(CREATED_AT), 'linux');
    expect(result.findings).toEqual([
      expect.objectContaining({
        targetId: 'missing',
        code: 'working-directory-unavailable',
      }),
    ]);
  });

  it('classifies add, removal, booleans, limits, and restriction transitions', () => {
    const added = permissionEntrySchema.parse({
      secret: 'service/token',
      commands: ['Node', 'node'],
      hashes: { node: SHA_A },
      workingDirectory: 'C:\\repo',
      ttl: '1m',
      maxUses: 2,
      requireConfirmation: true,
    });
    expect(diffPolicyDefinition('new', undefined, added, 'win32')).toMatchObject({
      operation: 'add',
      changed: true,
      before: null,
    });

    const broad = permissionEntrySchema.parse({
      secret: 'service/token',
      commands: ['node', 'git'],
      reveal: true,
    });
    const narrow = permissionEntrySchema.parse({
      secret: 'service/token',
      commands: ['node'],
      hashes: { node: SHA_A },
      workingDirectory: 'C:\\repo',
      ttl: '1m',
      maxUses: 1,
      requireConfirmation: true,
    });
    const tightened = diffPolicyDefinition('limits', broad, narrow, 'win32');
    expect(tightened.changes).toEqual(
      expect.arrayContaining([
        expect.objectContaining({ field: 'commands', impact: 'tightens' }),
        expect.objectContaining({ field: 'hashes', impact: 'tightens' }),
        expect.objectContaining({ field: 'workingDirectory', impact: 'tightens' }),
        expect.objectContaining({ field: 'ttl', impact: 'tightens' }),
        expect.objectContaining({ field: 'maxUses', impact: 'tightens' }),
        expect.objectContaining({ field: 'reveal', impact: 'tightens' }),
      ]),
    );

    const widened = diffPolicyDefinition('limits', narrow, broad, 'win32');
    expect(widened.changes).toEqual(
      expect.arrayContaining([
        expect.objectContaining({ field: 'commands', impact: 'widens' }),
        expect.objectContaining({ field: 'hashes', impact: 'widens' }),
        expect.objectContaining({ field: 'workingDirectory', impact: 'widens' }),
        expect.objectContaining({ field: 'ttl', impact: 'widens' }),
        expect.objectContaining({ field: 'maxUses', impact: 'widens' }),
        expect.objectContaining({ field: 'requireConfirmation', impact: 'widens' }),
        expect.objectContaining({ field: 'reveal', impact: 'widens' }),
      ]),
    );

    const deny = permissionEntrySchema.parse({ secret: 'service/token', deny: true });
    const allow = permissionEntrySchema.parse({
      secret: 'service/token',
      commands: ['node'],
    });
    expect(
      diffPolicyDefinition('deny', allow, deny).changes.find(
        ({ field }) => field === 'deny',
      ),
    ).toMatchObject({ impact: 'tightens' });
    expect(
      diffPolicyDefinition('deny', deny, allow).changes.find(
        ({ field }) => field === 'deny',
      ),
    ).toMatchObject({ impact: 'widens' });

    const longer = permissionEntrySchema.parse({
      secret: 'service/token',
      commands: ['node'],
      ttl: '2m',
      maxUses: 3,
    });
    const shorter = permissionEntrySchema.parse({
      secret: 'service/token',
      commands: ['node'],
      ttl: '1m',
      maxUses: 2,
    });
    expect(diffPolicyDefinition('numeric', shorter, longer).changes).toEqual(
      expect.arrayContaining([
        expect.objectContaining({ field: 'ttl', impact: 'widens' }),
        expect.objectContaining({ field: 'maxUses', impact: 'widens' }),
      ]),
    );

    const arrayConfirmation = permissionEntrySchema.parse({
      secret: 'service/token',
      commands: ['Node'],
      requireConfirmation: ['publish', 'deploy', 'publish'],
    });
    expect(
      diffPolicyDefinition('linux-array', undefined, arrayConfirmation, 'linux').after,
    ).toMatchObject({
      commands: ['Node'],
      requireConfirmation: ['deploy', 'publish'],
    });
  });
});

describe('least-privilege suggestions and grant inspection', () => {
  it('uses only positive sanitized events to propose monotonic command narrowing', () => {
    const policies = {
      selected: stored({
        secret: 'service/token',
        commands: ['node', 'git'],
        hashes: { node: SHA_A, git: SHA_B },
      }),
    };
    const audit = [
      runtimeAuditEventSchema.parse({
        seq: 1,
        occurredAt: CREATED_AT,
        actor: 'user',
        action: 'authorization-allowed',
        policyId: 'selected',
        secret: 'service/token',
        command: 'node',
        reason: 'policy-allowed',
      }),
      runtimeAuditEventSchema.parse({
        seq: 2,
        occurredAt: CREATED_AT,
        actor: 'user',
        action: 'authorization-denied',
        policyId: 'selected',
        secret: 'service/token',
        command: 'git',
        reason: 'command-not-allowed',
      }),
    ];

    const result = suggestPolicyTightenings(policies, audit, 'win32');

    expect(result.reviewOnly).toBe(true);
    expect(result.coverage).toBe('incomplete-bounded-audit-ring');
    expect(result.suggestions).toHaveLength(1);
    expect(result.suggestions[0]).toMatchObject({
      policyId: 'selected',
      currentCommands: ['node', 'git'],
      proposedCommands: ['node'],
      observedUses: 1,
      reviewRequired: true,
      confidence: 'low',
    });
    expect(result.suggestions[0]?.proposedDefinition.hashes).toEqual({
      node: SHA_A,
    });
  });

  it('reports live remaining uses, expiry, and effective restrictions', () => {
    const grant: GrantRecord = {
      grantId: 'grant_demo',
      secret: 'service/token',
      actor: 'agent',
      commands: ['node'],
      hashes: { node: SHA_A },
      env: 'SERVICE_TOKEN',
      createdByPolicyId: 'selected',
      createdAt: CREATED_AT,
      expiresAt: '2026-08-27T10:00:00.000Z',
      maxUses: 3,
      usedCount: 1,
    };
    const inspection = grantInspection(
      grant,
      Date.parse('2026-08-27T09:30:00.000Z'),
      'active',
    );

    expect(inspection['remainingUses']).toBe(2);
    expect(inspection['expiresInMs']).toBe(1_800_000);
    expect(inspection['restrictions']).toEqual({
      actor: 'agent',
      commands: ['node'],
      hashes: { node: SHA_A },
      remainingUses: 2,
      expiresAt: '2026-08-27T10:00:00.000Z',
      revoked: false,
    });
  });

  it('omits absent grant limits and clamps exhausted optional fields', () => {
    const unlimited: GrantRecord = {
      grantId: 'grant_unlimited',
      secret: 'service/token',
      actor: 'user',
      commands: [],
      createdAt: CREATED_AT,
      usedCount: 5,
    };
    expect(grantInspection(unlimited, Date.parse(CREATED_AT), 'active')).toMatchObject({
      remainingUses: null,
      expiresInMs: null,
      injection: { environmentVariable: null },
      provenance: { createdByPolicyId: null, agentPermissionKey: null },
    });

    const revoked: GrantRecord = {
      ...unlimited,
      grantId: 'grant_revoked',
      hashes: { node: SHA_A },
      env: 'TOKEN',
      maxUses: 1,
      expiresAt: '2026-08-27T08:00:00.000Z',
      lastUsedAt: '2026-08-27T08:30:00.000Z',
      revokedAt: '2026-08-27T08:45:00.000Z',
      createdByPolicyId: 'selected',
      agentPermissionKey: 'agent-key',
    };
    const inspected = grantInspection(revoked, Date.parse(CREATED_AT), 'revoked');
    expect(inspected).toMatchObject({
      remainingUses: 0,
      expiresInMs: 0,
      lastUsedAt: revoked.lastUsedAt,
      revokedAt: revoked.revokedAt,
      env: 'TOKEN',
      hashes: { node: SHA_A },
    });
    expect(inspected['restrictions']).toMatchObject({ revoked: true });
  });

  it('skips unsafe or unsupported suggestion candidates', () => {
    const policies = {
      denied: stored({ secret: 'service/token', deny: true }),
      unseen: stored({ secret: 'service/unseen', commands: ['node', 'git'] }),
      noOverlap: stored({ secret: 'service/token', commands: ['git'] }),
      alreadyTight: stored({ secret: 'service/token', commands: ['node'] }),
      noHashes: stored({ secret: 'service/token', commands: ['node', 'git'] }),
      irrelevantHashes: stored({
        secret: 'service/token',
        commands: ['node', 'git'],
        hashes: { git: SHA_B },
      }),
    };
    const allowed = runtimeAuditEventSchema.parse({
      seq: 9,
      occurredAt: CREATED_AT,
      actor: 'user',
      action: 'authorization-allowed',
      policyId: 'noHashes',
      secret: 'service/token',
      command: 'node',
      reason: 'policy-allowed',
    });
    const audit = [
      allowed,
      runtimeAuditEventSchema.parse({ ...allowed, seq: 10, policyId: 'noOverlap' }),
      runtimeAuditEventSchema.parse({ ...allowed, seq: 11, policyId: 'alreadyTight' }),
      runtimeAuditEventSchema.parse({
        ...allowed,
        seq: 12,
        policyId: 'irrelevantHashes',
      }),
      runtimeAuditEventSchema.parse({ ...allowed, seq: 13, policyId: undefined }),
      runtimeAuditEventSchema.parse({ ...allowed, seq: 14, secret: undefined }),
      runtimeAuditEventSchema.parse({ ...allowed, seq: 15, command: undefined }),
    ];
    const result = suggestPolicyTightenings(policies, audit, 'win32');
    expect(result.firstRetainedSeq).toBe(9);
    expect(result.lastRetainedSeq).toBe(15);
    expect(result.suggestions.map(({ policyId }) => policyId)).toEqual([
      'irrelevantHashes',
      'noHashes',
    ]);
    expect(
      result.suggestions.every(
        ({ proposedDefinition }) => proposedDefinition.hashes === undefined,
      ),
    ).toBe(true);

    expect(suggestPolicyTightenings({}, [])).toMatchObject({
      firstRetainedSeq: null,
      lastRetainedSeq: null,
      positiveAuthorizationEvents: 0,
      suggestions: [],
    });
  });
});
