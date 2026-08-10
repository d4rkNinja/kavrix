import { describe, expect, it } from 'vitest';

import { groupPayloadSchema, type GroupPayload } from '@kavrix/schemas';

import { AmbiguousNameError, NotFoundError, resolveNamedEntity } from '../src/index.js';

const timestamp = '2026-08-10T00:00:00.000Z';

function group(
  id: string,
  name: string,
  slug: string,
  aliases: readonly string[],
): GroupPayload {
  return groupPayloadSchema.parse({
    id,
    vaultId: 'vault.1',
    name,
    slug,
    aliases,
    tags: [],
    notes: [],
    template: {
      id: `template.${id}`,
      name: `${name} template`,
      version: 1,
      fields: [],
      createdAt: timestamp,
      updatedAt: timestamp,
    },
    sortOrder: 0,
    revision: 0,
    createdAt: timestamp,
    updatedAt: timestamp,
  });
}

const groups = [
  group('group.1', 'Email Accounts', 'mail', ['Personal Mail']),
  group('group.2', 'Production', 'prod', ['Primary']),
];

describe('name resolution', () => {
  it('prioritizes exact IDs, aliases/slugs, names, then case-insensitive matches', () => {
    expect(resolveNamedEntity('group.1', groups).id).toBe('group.1');
    expect(resolveNamedEntity('ＰＲＯＤ', groups).id).toBe('group.2');

    const exactAliasOverName = [
      ...groups,
      group('group.3', 'Primary', 'primary-name', []),
    ];
    expect(resolveNamedEntity('Primary', exactAliasOverName).id).toBe('group.2');

    const exactNameOverCaseInsensitiveAlias = [
      ...groups,
      group('group.3', 'primary', 'primary-name', []),
    ];
    expect(resolveNamedEntity('primary', exactNameOverCaseInsensitiveAlias).id).toBe(
      'group.3',
    );
  });

  it('uses a unique prefix only after every exact lookup phase', () => {
    expect(resolveNamedEntity('pers', groups).id).toBe('group.1');
    expect(resolveNamedEntity('group.2', groups).id).toBe('group.2');

    const ambiguousPrefix = [...groups, group('group.3', 'Project', 'project', [])];
    expect(() => resolveNamedEntity('pro', ambiguousPrefix)).toThrow(
      AmbiguousNameError,
    );
  });

  it('prefers an exact-case name and never chooses duplicate exact names', () => {
    const caseVariant = [
      ...groups,
      group('group.3', 'email accounts', 'other-mail', []),
    ];
    expect(resolveNamedEntity('Email Accounts', caseVariant).id).toBe('group.1');

    const exactDuplicates = [
      ...groups,
      group('group.3', 'Email Accounts', 'other-mail', []),
    ];
    expect(() => resolveNamedEntity('Email Accounts', exactDuplicates)).toThrow(
      AmbiguousNameError,
    );
  });

  it('returns safe errors that do not echo an unknown query', () => {
    const canary = 'secret-query-canary';
    try {
      resolveNamedEntity(canary, groups);
      expect.unreachable();
    } catch (error) {
      expect(error).toBeInstanceOf(NotFoundError);
      expect(String(error)).not.toContain(canary);
    }
  });
});
