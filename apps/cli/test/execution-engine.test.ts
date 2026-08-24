import { createHash } from 'node:crypto';

import { permissionEntrySchema, type PermissionEntry } from '@kavrix/schemas';
import { describe, expect, it } from 'vitest';

import {
  canonicalizeDirectory,
  evaluateGrantUse,
  evaluatePermission,
  evaluateReveal,
  executionWindowMs,
  matchesWorkingDirectory,
  requiresConfirmation,
  sameCommand,
  type EvaluationContext,
} from '../src/execution/engine.js';

const DIGEST = createHash('sha256').update('executable-bytes').digest('hex');

function entry(raw: Record<string, unknown>): PermissionEntry {
  return permissionEntrySchema.parse(raw);
}

function context(overrides: Partial<EvaluationContext> = {}): EvaluationContext {
  return {
    platform: 'linux',
    facts: {
      displayName: 'node',
      sha256: DIGEST,
      firstArgument: undefined,
    },
    nowIso: '2026-08-22T12:00:00.000Z',
    cwdRealPath: '/repos/app',
    ...overrides,
  };
}

describe('evaluatePermission', () => {
  it('allows a listed command and records the policy secret', () => {
    const decision = evaluatePermission(
      entry({ secret: 'github/token', commands: ['gh', 'git'] }),
      context({
        facts: { displayName: 'gh', sha256: DIGEST, firstArgument: undefined },
      }),
    );
    expect(decision).toMatchObject({ outcome: 'allow', reason: 'policy-allowed' });
    if (decision.outcome === 'allow') expect(decision.secret).toBe('github/token');
  });

  it('denies unlisted commands with a closed reason', () => {
    const decision = evaluatePermission(
      entry({ secret: 's', commands: ['gh'] }),
      context(),
    );
    expect(decision).toMatchObject({
      outcome: 'deny',
      reason: 'command-not-allowed',
      secret: 's',
    });
  });

  it('matches commands case-insensitively only on Windows', () => {
    const allowEntry = entry({ secret: 's', commands: ['GH'] });
    expect(
      evaluatePermission(
        allowEntry,
        context({
          platform: 'win32',
          facts: { displayName: 'gh', sha256: DIGEST, firstArgument: undefined },
        }),
      ).outcome,
    ).toBe('allow');
    expect(evaluatePermission(allowEntry, context()).outcome).toBe('deny');
  });

  it('verifies executable hash pins exactly', () => {
    const pinned = entry({
      secret: 's',
      commands: ['node'],
      hashes: { node: DIGEST },
    });
    expect(evaluatePermission(pinned, context()).outcome).toBe('allow');
    expect(
      evaluatePermission(
        pinned,
        context({
          facts: {
            displayName: 'node',
            sha256: 'f'.repeat(64),
            firstArgument: undefined,
          },
        }),
      ),
    ).toMatchObject({ outcome: 'deny', reason: 'hash-mismatch' });
    expect(
      evaluatePermission(
        pinned,
        context({
          facts: { displayName: 'node', sha256: undefined, firstArgument: undefined },
        }),
      ),
    ).toMatchObject({ outcome: 'deny', reason: 'hash-mismatch' });
  });

  it('requires confirmation when the requirement is unconditional', () => {
    const decision = evaluatePermission(
      entry({ secret: 'npm/token', commands: ['npm'], requireConfirmation: true }),
      context({
        facts: { displayName: 'npm', sha256: DIGEST, firstArgument: undefined },
      }),
    );
    expect(decision).toEqual({
      outcome: 'confirm',
      reason: 'confirmation-required',
      secret: 'npm/token',
    });
  });

  it('matches confirmation tokens against the first argument only', () => {
    const scoped = entry({
      secret: 's',
      commands: ['node', 'npm'],
      requireConfirmation: ['publish'],
    });
    expect(requiresConfirmation(scoped, 'publish')).toBe(true);
    expect(requiresConfirmation(scoped, 'install')).toBe(false);
    expect(requiresConfirmation(scoped, undefined)).toBe(false);
    expect(
      requiresConfirmation(entry({ secret: 's', commands: ['npm'] }), 'publish'),
    ).toBe(false);
  });

  it('denies deny entries regardless of the requested command', () => {
    expect(evaluatePermission(entry({ deny: true }), context())).toMatchObject({
      outcome: 'deny',
      reason: 'policy-denied',
    });
  });

  it('caps execution windows from ttl and fails closed on overflow', () => {
    expect(executionWindowMs(entry({ secret: 's', commands: ['c'], ttl: '30m' }))).toBe(
      1_800_000,
    );
    expect(executionWindowMs(entry({ secret: 's', commands: ['c'] }))).toBeUndefined();
    expect(executionWindowMs(entry({ secret: 's', commands: ['c'], ttl: '31d' }))).toBe(
      'invalid',
    );
  });

  it('enforces working-directory restrictions before confirmation', () => {
    const restricted = entry({
      secret: 's',
      commands: ['node'],
      workingDirectory: 'D:\\projects\\app',
    });
    const inside = context({
      platform: 'win32',
      cwdRealPath: 'D:\\projects\\app\\subdir',
    });
    expect(evaluatePermission(restricted, inside).outcome).toBe('allow');

    const outside = context({
      platform: 'win32',
      cwdRealPath: 'D:\\other\\place',
    });
    expect(evaluatePermission(restricted, outside)).toMatchObject({
      outcome: 'deny',
      reason: 'working-directory-mismatch',
    });

    // No cwd supplied (caller could not resolve it): fail closed.
    expect(
      evaluatePermission(restricted, { ...context(), cwdRealPath: undefined }),
    ).toMatchObject({ outcome: 'deny', reason: 'working-directory-mismatch' });
  });
});

describe('matchesWorkingDirectory', () => {
  it('accepts the exact directory and any subtree member', () => {
    expect(matchesWorkingDirectory('/repos/app', '/repos/app', 'linux')).toBe(true);
    expect(
      matchesWorkingDirectory('/repos/app', '/repos/app/packages/x', 'linux'),
    ).toBe(true);
  });

  it('rejects sibling prefixes that merely share characters', () => {
    expect(matchesWorkingDirectory('/repos/app', '/repos/application', 'linux')).toBe(
      false,
    );
  });

  it('normalizes trailing separators, case, and slash direction on Windows', () => {
    expect(
      matchesWorkingDirectory('D:/Projects/App/', 'd:\\projects\\app', 'win32'),
    ).toBe(true);
    expect(
      matchesWorkingDirectory('D:/Projects/App', 'D:\\Projects\\App\\x', 'win32'),
    ).toBe(true);
  });

  it('canonicalizes through realpath with a safe fallback', () => {
    expect(canonicalizeDirectory(process.cwd())).toBeTruthy();
    expect(
      canonicalizeDirectory(process.cwd().replace(/[\\/]+$/u, '') + '\\nonexistent'),
    ).toContain('nonexistent');
  });
});

describe('sameCommand', () => {
  it('is case-sensitive on POSIX and insensitive on Windows', () => {
    expect(sameCommand('NPM', 'npm', 'linux')).toBe(false);
    expect(sameCommand('NPM', 'npm', 'win32')).toBe(true);
    expect(sameCommand('npm', 'npm', 'linux')).toBe(true);
  });
});

describe('evaluateReveal', () => {
  it('allows reveal when no stored policy covers the credential', () => {
    expect(evaluateReveal([])).toEqual({
      outcome: 'allow',
      reason: 'no-applicable-policy',
    });
  });

  it('denies reveal unless a covering policy explicitly grants it', () => {
    const covering = [
      entry({ secret: 'a/b', commands: ['x'], reveal: false }),
      entry({ secret: 'a/b', commands: ['y'] }),
    ];
    expect(evaluateReveal(covering)).toMatchObject({
      outcome: 'deny',
      reason: 'reveal-forbidden-by-policy',
    });
    expect(
      evaluateReveal([entry({ secret: 'a/b', commands: ['x'], reveal: true })]),
    ).toMatchObject({ outcome: 'allow', reason: 'policy-allowed' });
  });
});

interface GrantFixture {
  grantId: string;
  secret: string;
  actor: 'user';
  commands: string[];
  createdAt: string;
  expiresAt?: string;
  maxUses?: number;
  usedCount: number;
  revokedAt?: string;
  hashes?: Record<string, string>;
}

function grantFixture(overrides: Partial<GrantFixture> = {}): GrantFixture {
  return {
    grantId: 'grant_11111111-1111-4111-8111-111111111111',
    secret: 'production/database',
    actor: 'user',
    commands: ['psql'],
    createdAt: '2026-08-22T11:00:00.000Z',
    expiresAt: '2026-08-22T12:30:00.000Z',
    usedCount: 0,
    ...overrides,
  };
}

describe('evaluateGrantUse', () => {
  it('allows a live grant for a listed command', () => {
    expect(
      evaluateGrantUse(
        grantFixture(),
        context({
          facts: { displayName: 'psql', sha256: undefined, firstArgument: undefined },
        }),
      ),
    ).toMatchObject({ status: 'allowed' });
  });

  it('rejects unparseable timestamps as clock failures', () => {
    expect(
      evaluateGrantUse(grantFixture({ createdAt: 'not-a-timestamp' }), context()),
    ).toMatchObject({ status: 'denied', reason: 'clock-invalid' });
  });
  it('rejects clock regression before creation time', () => {
    expect(
      evaluateGrantUse(grantFixture(), context({ nowIso: '2026-08-22T10:00:00.000Z' })),
    ).toMatchObject({ status: 'denied', reason: 'clock-invalid' });
  });

  it('rejects revoked, expired, and exhausted grants', () => {
    expect(
      evaluateGrantUse(
        grantFixture({ revokedAt: '2026-08-22T11:30:00.000Z' }),
        context(),
      ),
    ).toMatchObject({ status: 'denied', reason: 'revoked' });
    expect(
      evaluateGrantUse(grantFixture(), context({ nowIso: '2026-08-22T12:31:00.000Z' })),
    ).toMatchObject({ status: 'denied', reason: 'expired' });
    expect(
      evaluateGrantUse(grantFixture({ maxUses: 2, usedCount: 2 }), context()),
    ).toMatchObject({ status: 'denied', reason: 'exhausted' });
  });

  it('enforces command allowlists and hash pins on grants too', () => {
    expect(
      evaluateGrantUse(
        grantFixture(),
        context({
          facts: { displayName: 'curl', sha256: undefined, firstArgument: undefined },
        }),
      ),
    ).toMatchObject({ status: 'denied', reason: 'command-not-allowed' });
    expect(
      evaluateGrantUse(
        grantFixture({ hashes: { psql: 'a'.repeat(64) } }),
        context({
          facts: {
            displayName: 'psql',
            sha256: 'b'.repeat(64),
            firstArgument: undefined,
          },
        }),
      ),
    ).toMatchObject({ status: 'denied', reason: 'hash-mismatch' });
  });
});
