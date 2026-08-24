import type { Command } from 'commander';

import { describe, expect, it } from 'vitest';

import {
  flattenRecords,
  formatRecordLine,
  isRecord,
  named,
  renderRecordLines,
  text,
} from '../src/execution/register.js';
import {
  addPlannedInjection,
  asAuditReason,
  denyMessage,
  describeError,
  grantDenyMessage,
} from '../src/execution/run-command.js';
import { grantStatus, parseHashPins } from '../src/execution/policy-command.js';
import { CodedCliError } from '../src/execution/exit-codes.js';
import { extractMergedOptions } from '../src/execution/cli-options.js';

describe('register render helpers', () => {
  it('flattens arrays, known containers, and single records', () => {
    const arrayCase = [{ id: 'a' }];
    expect(flattenRecords(arrayCase)).toEqual(arrayCase);
    expect(flattenRecords({ policies: [{ id: 'p' }] })).toEqual([{ id: 'p' }]);
    expect(flattenRecords({ grants: [] })).toEqual([]);
    expect(flattenRecords('scalar')).toEqual([]);
    expect(flattenRecords({ unrelated: true })).toEqual([{ unrelated: true }]);
    const removed = { removed: true, id: 'x' };
    expect(flattenRecords(removed)).toEqual([removed]);
  });

  it('filters non-records out of arrays', () => {
    expect(isRecord({})).toBe(true);
    expect(isRecord('x')).toBe(false);
    expect(flattenRecords([{ id: 'a' }, 'skip', 5] as unknown[])).toEqual([
      { id: 'a' },
    ]);
  });

  it('formats audit lines with every optional field', () => {
    expect(
      formatRecordLine({
        occurredAt: '2026-01-01T00:00:00.000Z',
        actor: 'agent',
        action: 'authorization-denied',
        policyId: 'pol',
        permissionKey: 'perm',
        secret: 'sec/ret',
        command: 'gh',
        reason: 'policy-denied',
        exitCode: 3,
      }),
    ).toBe(
      '2026-01-01T00:00:00.000Z actor=agent action=authorization-denied policy=pol permission=perm credential=sec/ret command=gh reason=policy-denied exit=3',
    );
    // Missing actor/action fall back to '?'.
    expect(
      formatRecordLine({
        occurredAt: '2026-01-01T00:00:00.000Z',
        action: 'unlock',
      }),
    ).toContain('actor=?');
  });

  it('formats record lines with status, reveal, deny, ttl, and expiry fields', () => {
    expect(
      formatRecordLine({
        grantId: 'grant_x',
        secret: 'a/b',
        commands: ['node', 'gh'],
        status: 'active',
        reveal: true,
        ttl: '15m',
        maxUses: 3,
        expiresAt: 'soon',
      }),
    ).toBe(
      'grant_x  a/b  node,gh  status=active  reveal=true  ttl=15m  maxUses=3  expires=soon',
    );
    expect(formatRecordLine({ id: 'pol', deny: true })).toBe('pol  DENY');
  });

  it('coerces primitives and renders name=value pairs', () => {
    expect(text('s')).toBe('s');
    expect(text(4)).toBe('4');
    expect(text(true)).toBe('true');
    expect(text(undefined)).toBe('');
    expect(text({})).toBe('');
    expect(named('k', 'v')).toBe('k=v');
    expect(named('k', undefined)).toBe('');
  });
});

describe('run message and injection guards', () => {
  it('renders each denial message arm', () => {
    expect(denyMessage('command-not-allowed', 'p')).toContain('does not allow');
    expect(denyMessage('hash-mismatch', 'p')).toContain('hash does not match');
    expect(denyMessage('expired', 'p')).toContain('Denied by policy');
    expect(grantDenyMessage('expired')).toContain('expired');
    expect(grantDenyMessage('exhausted')).toContain('no remaining uses');
    expect(grantDenyMessage('revoked')).toContain('revoked');
    expect(grantDenyMessage('clock-invalid')).toContain('clock');
    expect(grantDenyMessage('command-not-allowed')).toContain('does not allow');
    expect(grantDenyMessage('hash-mismatch')).toContain('pin');
    expect(grantDenyMessage('unknown-reason')).toBe('Denied (unknown-reason).');
    expect(denyMessage('unknown-reason', 'p')).toBe(
      "Denied by policy 'p' (unknown-reason).",
    );
    expect(asAuditReason('policy-allowed')).toBe('policy-allowed');
    expect(asAuditReason('not-a-reason')).toBeUndefined();
    expect(describeError(new Error('e'))).toBe('e');
    expect(describeError(42)).toBe('42');
  });

  it('rejects invalid destinations and conflicting grant injections', () => {
    const planned = new Map([['VAR', 'one/secret']]);
    expect(() => addPlannedInjection(planned, 'BAD DEST', 'two/secret')).toThrow(
      /invalid/u,
    );
    expect(() => addPlannedInjection(planned, 'VAR', 'two/secret')).toThrow(
      /conflicting credentials/u,
    );
    addPlannedInjection(planned, 'VAR', 'one/secret');
    addPlannedInjection(planned, 'OTHER', 'three/secret');
    expect(planned.get('OTHER')).toBe('three/secret');
  });
});

describe('policy presentation helpers', () => {
  const base = {
    grantId: 'grant_1',
    secret: 'a/b',
    actor: 'user' as const,
    commands: ['psql'],
    createdAt: '2026-08-22T11:00:00.000Z',
    usedCount: 0,
  };

  it('computes every live grant status', () => {
    const at = Date.parse('2026-08-22T12:00:00.000Z');
    expect(grantStatus(base as never, at)).toBe('active');
    expect(
      grantStatus({ ...base, revokedAt: '2026-08-22T11:30:00.000Z' } as never, at),
    ).toBe('revoked');
    expect(
      grantStatus({ ...base, expiresAt: '2026-08-22T11:30:00.000Z' } as never, at),
    ).toBe('expired');
    expect(grantStatus({ ...base, maxUses: 1, usedCount: 1 } as never, at)).toBe(
      'exhausted',
    );
  });

  it('parses hash pins strictly', () => {
    expect(parseHashPins(['node=' + 'a'.repeat(64)])).toEqual({
      node: 'a'.repeat(64),
    });
    expect(() => parseHashPins(['noparse'])).toThrow(/--hash expects/u);
  });
});

describe('coded error identity', () => {
  it('keeps coded errors distinct from plain errors', () => {
    const error = new CodedCliError('CREDENTIAL_MISSING', 'x');
    expect(error.exitCode).toBe(11);
    expect(error.message).toBe('x');
  });
});

describe('option merge precedence', () => {
  function node(opts: Record<string, unknown>, parent: Command | null): Command {
    return {
      opts: () => opts,
      getOptionValueSource: (key: string) =>
        key === 'inherited-default' ? 'default' : 'explicit',
      parent,
    } as unknown as Command;
  }

  it('keeps an explicit child value over a default that collides with a parent key', () => {
    const leaf = node({ shared: 'leaf-value' }, null);
    const root = node({ shared: 'root-value', inheritedDefault: 'root-default' }, null);
    leaf.parent = root;
    const merged = extractMergedOptions(leaf);
    // Child explicit wins; parent default for a key the child also declares
    // as default would be skipped by the hasOwn guard.
    expect(merged['shared']).toBe('leaf-value');
    expect(merged['inheritedDefault']).toBe('root-default');
  });
});
