import { describe, expect, it } from 'vitest';

import {
  auditArgvPreview,
  mergeMappings,
  parseSecretMappings,
} from '../src/execution/run-options.js';
import {
  evaluateGrantUse,
  evaluateReveal,
  sameCommand,
} from '../src/execution/engine.js';
import { permissionEntrySchema } from '@kavrix/schemas';

describe('parseSecretMappings', () => {
  it('accepts well-formed mappings', () => {
    expect(parseSecretMappings(['DATABASE_URL=production/database'])).toEqual([
      { destination: 'DATABASE_URL', secret: 'production/database' },
    ]);
  });

  it('rejects invalid destination names', () => {
    expect(() => parseSecretMappings(['1BAD=x'])).toThrow(/--secret expects/u);
    expect(() => parseSecretMappings(['HAS SPACE=x'])).toThrow(/--secret expects/u);
  });

  it('rejects control characters in credential references', () => {
    expect(() => parseSecretMappings(['GOOD=name\u0007bad'])).toThrow(
      /--secret expects/u,
    );
  });

  it('rejects values without a separator or with empty sides', () => {
    expect(() => parseSecretMappings(['NO_SEPARATOR'])).toThrow();
    expect(() => parseSecretMappings(['=name'])).toThrow();
    expect(() => parseSecretMappings(['DEST='])).toThrow();
  });
});

describe('mergeMappings', () => {
  it('deduplicates identical destinations and rejects conflicts', () => {
    const merged = mergeMappings(
      [{ destination: 'A', secret: 'one' }],
      [
        { destination: 'A', secret: 'one' },
        { destination: 'B', secret: 'two' },
      ],
    );
    expect(merged).toEqual([
      { destination: 'A', secret: 'one' },
      { destination: 'B', secret: 'two' },
    ]);
    expect(() =>
      mergeMappings(
        [{ destination: 'A', secret: 'one' }],
        [{ destination: 'A', secret: 'other' }],
      ),
    ).toThrow(/conflicting credentials/u);
  });
});

describe('auditArgvPreview', () => {
  it('bounds entries, strips controls, and truncates long values', () => {
    const preview = auditArgvPreview([
      `${'a'.repeat(80)}`,
      `ctrl${String.fromCharCode(3)}char`,
      ...Array.from({ length: 9 }, (_, index) => `arg${String(index)}`),
    ]);
    expect(preview?.length).toBe(8);
    expect(preview?.[0]).toBe(`${'a'.repeat(61)}...`);
    expect(preview?.[1]).toBe('ctrl?char');
    expect(auditArgvPreview([])).toBeUndefined();
  });
});

describe('engine extras', () => {
  const context = {
    platform: 'linux' as NodeJS.Platform,
    facts: { displayName: 'psql', sha256: 'a'.repeat(64), firstArgument: undefined },
    nowIso: '2026-08-22T12:00:00.000Z',
  };
  const grant = {
    grantId: 'grant_11111111-1111-4111-8111-111111111111',
    secret: 'production/database',
    actor: 'user' as const,
    commands: ['psql'],
    createdAt: '2026-08-22T11:00:00.000Z',
    expiresAt: '2026-08-22T13:00:00.000Z',
    usedCount: 0,
    hashes: { psql: 'a'.repeat(64) },
  };

  it('allows grants whose pin matches the resolved executable', () => {
    expect(evaluateGrantUse(grant, context)).toMatchObject({
      status: 'allowed',
    });
  });

  it('denies reveal lists that contain any non-revealing entry', () => {
    const entries = [
      permissionEntrySchema.parse({ secret: 'x', commands: ['c'], reveal: true }),
      permissionEntrySchema.parse({ secret: 'x', commands: ['d'] }),
    ];
    expect(evaluateReveal(entries)).toMatchObject({
      outcome: 'deny',
      reason: 'reveal-forbidden-by-policy',
    });
  });

  it('compares POSIX command names exactly', () => {
    expect(sameCommand('psql', 'PSQL', 'linux')).toBe(false);
    expect(sameCommand('psql', 'psql', 'linux')).toBe(true);
  });
});
