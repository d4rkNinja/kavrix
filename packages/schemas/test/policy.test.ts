import { describe, expect, it } from 'vitest';

import {
  ALLOW_DECISION_REASONS,
  CONFIRM_DECISION_REASONS,
  DENY_DECISION_REASONS,
  authorizationDecisionSchema,
  authorizationEnvelopeContextSchema,
  authorizationReasonSchema,
  authorizationStateDocumentSchema,
  authorizationStateDomainSchema,
  authorizationStateEnvelopeSchema,
  cliErrorCodeSchema,
  commandNameSchema,
  credentialReferenceSchema,
  durationSchema,
  environmentVariableNameSchema,
  exitCodeForCliError,
  grantRecordSchema,
  normalizePermissionEntryAliases,
  normalizeProjectConfigAliases,
  parseDurationToMs,
  permissionEntrySchema,
  projectConfigDocumentSchema,
  runtimeAuditEventSchema,
  sha256HexDigestSchema,
} from '../src/index.js';

const HEX_DIGEST = 'a'.repeat(64);

describe('credential references', () => {
  it('accepts slash-separated and single-segment references', () => {
    expect(credentialReferenceSchema.parse('production/database')).toBe(
      'production/database',
    );
    expect(credentialReferenceSchema.parse('token')).toBe('token');
  });

  it.each([
    ['control characters', 'bad\u0007name'],
    ['NUL bytes', 'bad\u0000name'],
    ['surrounding whitespace', ' token '],
    ['reserved prototype names', '__proto__'],
    ['reserved constructor names', 'constructor'],
    ['empty values', ''],
    ['oversized values', 'x'.repeat(257)],
  ])('rejects %s', (_label, value) => {
    expect(credentialReferenceSchema.safeParse(value).success).toBe(false);
  });
});

describe('command names and pins', () => {
  it('accepts bare executable names including dotted and hyphenated forms', () => {
    expect(commandNameSchema.parse('npm')).toBe('npm');
    expect(commandNameSchema.parse('gh-cli')).toBe('gh-cli');
    expect(commandNameSchema.parse('psql12.app')).toBe('psql12.app');
  });

  it.each([
    ['path traversal', '../node'],
    ['absolute paths', '/bin/sh'],
    ['shell separators', 'a;b'],
    ['whitespace', 'two words'],
    ['empty', ''],
    ['leading punctuation', '.hidden'],
  ])('rejects %s as a command name', (_label, value) => {
    expect(commandNameSchema.safeParse(value).success).toBe(false);
  });

  it('requires exactly 64 lowercase hex characters for pins', () => {
    expect(sha256HexDigestSchema.safeParse(HEX_DIGEST).success).toBe(true);
    expect(sha256HexDigestSchema.safeParse(HEX_DIGEST.toUpperCase()).success).toBe(
      false,
    );
    expect(sha256HexDigestSchema.safeParse(`g${'a'.repeat(63)}`).success).toBe(false);
    expect(sha256HexDigestSchema.safeParse('a'.repeat(63)).success).toBe(false);
  });
});

describe('environment variable destinations', () => {
  it('accepts portable variable names', () => {
    expect(environmentVariableNameSchema.parse('DATABASE_URL')).toBe('DATABASE_URL');
    expect(environmentVariableNameSchema.parse('_PRIVATE')).toBe('_PRIVATE');
  });

  it.each([
    ['leading digits', '1BAD'],
    ['hyphens', 'BAD-NAME'],
    ['shell expansion syntax', 'BAD$NAME'],
  ])('rejects %s', (_label, value) => {
    expect(environmentVariableNameSchema.safeParse(value).success).toBe(false);
  });
});

describe('durations', () => {
  it('parses every unit into milliseconds', () => {
    expect(parseDurationToMs('30s')).toBe(30_000);
    expect(parseDurationToMs('15m')).toBe(900_000);
    expect(parseDurationToMs('12h')).toBe(43_200_000);
    expect(parseDurationToMs('7d')).toBe(604_800_000);
    expect(durationSchema.safeParse('15m').success).toBe(true);
  });

  it('rejects malformed or oversized durations', () => {
    expect(parseDurationToMs('0m')).toBeUndefined();
    expect(parseDurationToMs('-5m')).toBeUndefined();
    expect(parseDurationToMs('15x')).toBeUndefined();
    expect(parseDurationToMs('')).toBeUndefined();
    expect(parseDurationToMs('31d')).toBeUndefined();
    expect(parseDurationToMs('10000000s')).toBeUndefined();
  });
});

describe('permission entries', () => {
  const validEntry = {
    secret: 'github/token',
    commands: ['git', 'gh'],
    reveal: false,
    ttl: '30m',
  };

  it('accepts a bounded allowlist entry', () => {
    expect(permissionEntrySchema.parse(validEntry)).toMatchObject({
      secret: 'github/token',
      commands: ['git', 'gh'],
      reveal: false,
    });
  });

  it('requires a secret and at least one command unless the entry denies', () => {
    expect(permissionEntrySchema.safeParse({ commands: ['git'] }).success).toBe(false);
    expect(permissionEntrySchema.safeParse({ secret: 'a/b' }).success).toBe(false);
    const deny = { deny: true };
    const parsed = permissionEntrySchema.parse(deny);
    expect(parsed.deny).toBe(true);
  });

  it('forbids allowlist fields on deny entries', () => {
    expect(
      permissionEntrySchema.safeParse({ deny: true, commands: ['git'] }).success,
    ).toBe(false);
    expect(
      permissionEntrySchema.safeParse({
        deny: true,
        maxUses: 1,
        requireConfirmation: true,
      }).success,
    ).toBe(false);
  });

  it('rejects executable pins that do not reference listed commands', () => {
    expect(
      permissionEntrySchema.safeParse({
        ...validEntry,
        hashes: { npm: HEX_DIGEST },
      }).success,
    ).toBe(false);
    expect(
      permissionEntrySchema.parse({ ...validEntry, hashes: { gh: HEX_DIGEST } }),
    ).toMatchObject({ hashes: { gh: HEX_DIGEST } });
  });

  it('rejects unknown fields so plaintext secrets cannot hide inside entries', () => {
    expect(
      permissionEntrySchema.safeParse({
        secret: 'github/token',
        commands: ['git'],
        tokenValue: 'ghp_cannot_hide_here',
      }).success,
    ).toBe(false);
  });

  it('normalizes documented snake_case aliases', () => {
    const normalized = normalizePermissionEntryAliases({
      secret: 'npm/publish-token',
      commands: ['npm'],
      require_confirmation: ['publish'],
      max_uses: 1,
    }) as Record<string, unknown>;
    expect(normalized['requireConfirmation']).toEqual(['publish']);
    expect(normalized['maxUses']).toBe(1);
    expect('require_confirmation' in normalized).toBe(false);
    expect('max_uses' in normalized).toBe(false);
  });

  it('leaves already-canonical entries untouched by alias normalization', () => {
    const entry = { secret: 'a/b', commands: ['c'], requireConfirmation: true };
    expect(normalizePermissionEntryAliases(entry)).toBe(entry);
  });
});

describe('project configuration documents', () => {
  it('accepts the documented kavrix.yaml shape', () => {
    const document = projectConfigDocumentSchema.parse({
      version: 1,
      project: 'backend-api',
      environments: {
        development: {
          secrets: {
            DATABASE_URL: 'database/development',
            REDIS_URL: 'redis/development',
          },
        },
      },
      policies: {
        'github-development': {
          secret: 'github/development-token',
          commands: ['git', 'gh'],
          reveal: false,
          ttl: '30m',
        },
        'npm-publish': {
          secret: 'npm/publish-token',
          commands: ['npm'],
          reveal: false,
          requireConfirmation: ['publish'],
          maxUses: 1,
        },
      },
      agents: {
        'coding-agent': {
          permissions: {
            github: {
              secret: 'github/development',
              commands: ['git', 'gh'],
              env: 'GITHUB_TOKEN',
            },
            'production-database': { deny: true },
          },
        },
      },
    });
    expect(document.version).toBe(1);
    const codingAgent = document.agents?.['coding-agent'];
    expect(codingAgent?.permissions['github']?.env).toBe('GITHUB_TOKEN');
  });

  it('fails closed on unknown keys anywhere in the document', () => {
    expect(
      projectConfigDocumentSchema.safeParse({ version: 1, extra: true }).success,
    ).toBe(false);
    expect(
      projectConfigDocumentSchema.safeParse({
        version: 1,
        environments: { dev: { plaintext: 'sk-live-value' } },
      }).success,
    ).toBe(false);
    expect(projectConfigDocumentSchema.safeParse({ version: 2 }).success).toBe(false);
  });

  it('applies alias normalization across policies, agents, and environments', () => {
    const input = {
      version: 1,
      policies: {
        one: { secret: 'a/b', commands: ['c'], max_uses: 3 },
      },
      agents: {
        bot: { permissions: { key: { secret: 'a/b', commands: ['c'], max_uses: 2 } } },
      },
      environments: {
        dev: { policies: { two: { secret: 'a/b', commands: ['c'], max_uses: 1 } } },
      },
    };
    const normalized = normalizeProjectConfigAliases(input) as {
      policies: Record<string, Record<string, unknown>>;
      agents: Record<string, { permissions: Record<string, Record<string, unknown>> }>;
      environments: Record<
        string,
        { policies: Record<string, Record<string, unknown>> }
      >;
    };
    expect(normalized.policies['one']?.['maxUses']).toBe(3);
    expect(normalized.agents['bot']?.permissions['key']?.['maxUses']).toBe(2);
    expect(normalized.environments['dev']?.policies['two']?.['maxUses']).toBe(1);
    expect(() => projectConfigDocumentSchema.parse(normalized)).not.toThrow();
  });
});

describe('grant records', () => {
  const baseGrant = {
    grantId: 'grant_11111111-1111-4111-8111-111111111111',
    secret: 'production/database',
    actor: 'user' as const,
    commands: ['psql'],
    createdAt: '2026-08-22T00:00:00.000Z',
    expiresAt: '2026-08-22T00:15:00.000Z',
    usedCount: 0,
  };

  it('accepts a bounded temporary grant', () => {
    expect(grantRecordSchema.parse(baseGrant)).toMatchObject({ usedCount: 0 });
  });

  it('rejects uses beyond the recorded maximum', () => {
    expect(
      grantRecordSchema.safeParse({ ...baseGrant, maxUses: 2, usedCount: 3 }).success,
    ).toBe(false);
    expect(
      grantRecordSchema.safeParse({ ...baseGrant, maxUses: 2, usedCount: 2 }).success,
    ).toBe(true);
  });

  it('rejects expiry before creation and revocation before creation', () => {
    expect(
      grantRecordSchema.safeParse({
        ...baseGrant,
        expiresAt: '2026-08-21T00:00:00.000Z',
      }).success,
    ).toBe(false);
    expect(
      grantRecordSchema.safeParse({
        ...baseGrant,
        revokedAt: '2026-08-21T00:00:00.000Z',
      }).success,
    ).toBe(false);
  });

  it('rejects pins outside the granted command list', () => {
    expect(
      grantRecordSchema.safeParse({ ...baseGrant, hashes: { curl: HEX_DIGEST } })
        .success,
    ).toBe(false);
  });
});

describe('runtime audit events', () => {
  it('records bounded sanitized metadata only', () => {
    const event = runtimeAuditEventSchema.parse({
      seq: 1,
      occurredAt: '2026-08-22T02:31:17.000Z',
      actor: 'agent',
      action: 'authorization-denied',
      policyId: 'github-development',
      secret: 'github/development-token',
      command: 'gh',
      argvPreview: ['issue', 'create'],
      reason: 'command-not-allowed',
    });
    expect(event.seq).toBe(1);
  });

  it('rejects unbounded preview text and unknown actions or reasons', () => {
    expect(
      runtimeAuditEventSchema.safeParse({
        seq: 1,
        occurredAt: '2026-08-22T02:31:17.000Z',
        actor: 'user',
        action: 'authorization-denied',
        argvPreview: ['x'.repeat(65)],
      }).success,
    ).toBe(false);
    expect(
      runtimeAuditEventSchema.safeParse({
        seq: 1,
        occurredAt: '2026-08-22T02:31:17.000Z',
        actor: 'user',
        action: 'exfiltrate',
      }).success,
    ).toBe(false);
    expect(
      runtimeAuditEventSchema.safeParse({
        seq: 1,
        occurredAt: '2026-08-22T02:31:17.000Z',
        actor: 'user',
        action: 'authorization-denied',
        reason: 'because-i-said-so',
      }).success,
    ).toBe(false);
    expect(
      runtimeAuditEventSchema.safeParse({
        seq: 1,
        occurredAt: '2026-08-22T02:31:17.000Z',
        actor: 'user',
        action: 'authorization-denied',
        argvPreview: ['bad\u001b[31mcolor'],
      }).success,
    ).toBe(false);
  });
});

describe('authorization decisions', () => {
  it('keeps each outcome coupled to its closed reason family', () => {
    expect(
      authorizationDecisionSchema.safeParse({ outcome: 'allow', reason: 'expired' })
        .success,
    ).toBe(false);
    expect(
      authorizationDecisionSchema.parse({ outcome: 'allow', reason: 'policy-allowed' })
        .outcome,
    ).toBe('allow');
    expect(
      authorizationDecisionSchema.parse({
        outcome: 'confirm',
        reason: 'confirmation-required',
        policyId: 'npm-publish',
      }).outcome,
    ).toBe('confirm');
    expect(
      authorizationDecisionSchema.parse({
        outcome: 'deny',
        reason: 'reveal-forbidden-by-policy',
      }).reason,
    ).toBe('reveal-forbidden-by-policy');
  });

  it('partitions every reason into exactly one outcome family', () => {
    const all = new Set([
      ...ALLOW_DECISION_REASONS,
      ...CONFIRM_DECISION_REASONS,
      ...DENY_DECISION_REASONS,
    ]);
    expect(all.size).toBe(authorizationReasonSchema.options.length);
  });
});

describe('sealed authorization state envelope', () => {
  it('validates the exact authenticated context shape', () => {
    expect(
      authorizationEnvelopeContextSchema.parse({
        domain: authorizationStateDomainSchema.value,
        scopeKind: 'database',
        scopeId: 'db_local',
        sequence: 3,
      }),
    ).toMatchObject({ sequence: 3 });
    expect(
      authorizationEnvelopeContextSchema.safeParse({
        domain: 'kavrix/other/v9',
        scopeKind: 'database',
        scopeId: 'db_local',
        sequence: 3,
      }).success,
    ).toBe(false);
  });

  it('enforces canonical nonce and tag encodings on the wire format', () => {
    const nonce = Buffer.alloc(24, 7).toString('base64url');
    const tag = Buffer.alloc(16, 9).toString('base64url');
    const valid = {
      format: 'kavrix-authorization-state',
      version: 1,
      scopeKind: 'database',
      scopeId: 'db_local',
      sequence: 0,
      createdAt: '2026-08-22T00:00:00.000Z',
      updatedAt: '2026-08-22T00:00:00.000Z',
      nonce,
      ciphertext: Buffer.from('cipher-bytes', 'utf8').toString('base64url'),
      authenticationTag: tag,
    };
    expect(authorizationStateEnvelopeSchema.parse(valid)).toBeDefined();
    expect(
      authorizationStateEnvelopeSchema.safeParse({ ...valid, nonce: `${nonce}AAAA` })
        .success,
    ).toBe(false);
    expect(
      authorizationStateEnvelopeSchema.safeParse({
        ...valid,
        authenticationTag: `${tag}AAA`,
      }).success,
    ).toBe(false);
    expect(
      authorizationStateEnvelopeSchema.safeParse({ ...valid, version: 2 }).success,
    ).toBe(false);
  });
});

describe('authorization state documents', () => {
  it('accepts an empty initial state', () => {
    expect(
      authorizationStateDocumentSchema.parse({
        version: 1,
        policies: {},
        grants: {},
        audit: [],
      }),
    ).toBeDefined();
  });

  it('bounds the audit ring and rejects unknown state keys', () => {
    const event = (seq: number): unknown => ({
      seq,
      occurredAt: '2026-08-22T02:31:17.000Z',
      actor: 'user',
      action: 'unlock',
    });
    expect(
      authorizationStateDocumentSchema.safeParse({
        version: 1,
        policies: {},
        grants: {},
        audit: Array.from({ length: 512 }, (_, index) => event(index + 1)),
      }).success,
    ).toBe(true);
    expect(
      authorizationStateDocumentSchema.safeParse({
        version: 1,
        policies: {},
        grants: {},
        audit: Array.from({ length: 513 }, (_, index) => event(index + 1)),
      }).success,
    ).toBe(false);
    expect(
      authorizationStateDocumentSchema.safeParse({
        version: 1,
        policies: {},
        grants: {},
        audit: [],
        plaintext: 'nope',
      }).success,
    ).toBe(false);
  });
});

describe('CLI contract', () => {
  it('maps every error code to a distinct nonzero-or-zero exit code', () => {
    const codes = cliErrorCodeSchema.options;
    const mapped = codes.map((code) => exitCodeForCliError(code));
    expect(new Set(mapped).size).toBe(codes.length);
    expect(exitCodeForCliError('OK')).toBe(0);
    expect(exitCodeForCliError('AUTHORIZATION_DENIED')).toBe(12);
    expect(exitCodeForCliError('SECURITY_INTEGRITY_FAILURE')).toBe(16);
    expect(exitCodeForCliError('CONFIRMATION_REQUIRED')).toBe(17);
  });
});
