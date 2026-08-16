import {
  fieldDefinitionSchema,
  groupPayloadSchema,
  itemPayloadSchema,
  noteSchema,
  type FieldDefinition,
  type GroupPayload,
  type ItemPayload,
  type Note,
} from '@kavrix/schemas';
import { describe, expect, it } from 'vitest';

import { ValidationError } from '../src/errors.js';
import {
  DEFAULT_VAULT_SEARCH_RESULT_LIMIT,
  MAX_VAULT_SEARCH_MATCHES_PER_HIT,
  MAX_VAULT_SEARCH_RESULTS,
  MAX_VAULT_SEARCH_TERM_LENGTH,
  isFieldValueSearchable,
  normalizeVaultSearchTerm,
  searchVault,
  type VaultSearchHit,
  type VaultSearchOptions,
  type VaultSearchScope,
} from '../src/policies/vault-search.js';

const TIMESTAMP = '2026-08-16T00:00:00.000Z';

/**
 * The value that must never appear in a search result.
 *
 * Every redaction assertion checks for this exact string, so a policy that ever
 * returned matched text would fail loudly instead of subtly.
 */
const CANARY = 'canary-secret-value';

const METADATA_ONLY: VaultSearchOptions = {
  includeSecretValues: false,
  includeArchived: false,
};
const SECRETS_ENABLED: VaultSearchOptions = {
  includeSecretValues: true,
  includeArchived: false,
};
const ARCHIVED_INCLUDED: VaultSearchOptions = {
  includeSecretValues: false,
  includeArchived: true,
};
const EVERYTHING: VaultSearchOptions = {
  includeSecretValues: true,
  includeArchived: true,
};

interface FieldOverrides {
  readonly label?: string;
  readonly sensitive?: boolean;
  readonly searchableLocally?: boolean;
  readonly revealPolicy?: 'never' | 'timed' | 'confirm';
  readonly repeatable?: boolean;
  readonly type?: FieldDefinition['type'];
  /** A template rejects duplicate sort orders, so multi-field groups must vary it. */
  readonly sortOrder?: number;
}

function field(key: string, overrides: FieldOverrides = {}): FieldDefinition {
  const sensitive = overrides.sensitive ?? false;
  return fieldDefinitionSchema.parse({
    id: `field.${key}`,
    stableKey: key,
    label: overrides.label ?? key,
    type: overrides.type ?? (sensitive ? 'secret' : 'text'),
    required: false,
    sensitive,
    repeatable: overrides.repeatable ?? false,
    copyable: true,
    searchableLocally: overrides.searchableLocally ?? !sensitive,
    showInPreview: false,
    copyPolicy: 'allowed',
    revealPolicy: sensitive ? (overrides.revealPolicy ?? 'timed') : 'never',
    reauthenticationPolicy: sensitive ? 'after-lock' : 'never',
    exportPolicy: 'guarded',
    sortOrder: overrides.sortOrder ?? 0,
    createdAt: TIMESTAMP,
    updatedAt: TIMESTAMP,
  });
}

function storedValue(definition: FieldDefinition, value: string): unknown {
  return {
    fieldId: definition.id,
    stableKey: definition.stableKey,
    value: {
      version: 1,
      state: 'present',
      content: {
        cardinality: 'single',
        value: definition.sensitive
          ? { kind: 'secret', value }
          : { kind: 'text', value },
      },
    },
    updatedAt: TIMESTAMP,
  };
}

/** A single `environment-map` entry, whose value carries its own classification. */
function environmentValue(
  definition: FieldDefinition,
  key: string,
  classification: 'text' | 'secret',
  value: string,
): unknown {
  return {
    fieldId: definition.id,
    stableKey: definition.stableKey,
    value: {
      version: 1,
      state: 'present',
      content: {
        cardinality: 'single',
        value: { kind: 'environment-entry', key, value: { classification, value } },
      },
    },
    updatedAt: TIMESTAMP,
  };
}

interface NoteOverrides {
  readonly title?: string;
  readonly content?: string;
  readonly isSensitive?: boolean;
  readonly archivedAt?: string;
}

function note(id: string, overrides: NoteOverrides = {}): Note {
  return noteSchema.parse({
    id: `note.${id}`,
    title: overrides.title ?? 'Runbook',
    content: overrides.content ?? 'nothing interesting',
    isSensitive: overrides.isSensitive ?? false,
    isPinned: false,
    tags: [],
    sortOrder: 0,
    createdAt: TIMESTAMP,
    updatedAt: TIMESTAMP,
    ...(overrides.archivedAt === undefined ? {} : { archivedAt: overrides.archivedAt }),
  });
}

interface GroupOverrides {
  readonly name?: string;
  readonly aliases?: readonly string[];
  readonly tags?: readonly string[];
  readonly description?: string;
  readonly fields?: readonly FieldDefinition[];
  readonly notes?: readonly Note[];
  readonly archivedAt?: string;
  readonly deletedAt?: string;
}

function group(index: number, overrides: GroupOverrides = {}): GroupPayload {
  return groupPayloadSchema.parse({
    id: `group.${String(index)}`,
    vaultId: 'vault.1',
    name: overrides.name ?? `Group ${String(index)}`,
    slug: `group-${String(index)}`,
    aliases: overrides.aliases ?? [],
    ...(overrides.description === undefined
      ? {}
      : { description: overrides.description }),
    tags: overrides.tags ?? [],
    notes: overrides.notes ?? [],
    template: {
      id: `template.${String(index)}`,
      name: 'Custom',
      version: 1,
      fields: overrides.fields ?? [],
      createdAt: TIMESTAMP,
      updatedAt: TIMESTAMP,
    },
    sortOrder: index,
    revision: 1,
    createdAt: TIMESTAMP,
    updatedAt: TIMESTAMP,
    ...(overrides.archivedAt === undefined ? {} : { archivedAt: overrides.archivedAt }),
    ...(overrides.deletedAt === undefined ? {} : { deletedAt: overrides.deletedAt }),
  });
}

interface ItemOverrides {
  readonly title?: string;
  readonly aliases?: readonly string[];
  readonly subtitle?: string;
  readonly tags?: readonly string[];
  readonly environment?: string;
  readonly owner?: string;
  readonly purpose?: string;
  readonly notes?: readonly Note[];
  readonly templateValues?: readonly unknown[];
  readonly itemFields?: readonly FieldDefinition[];
  readonly itemValues?: readonly unknown[];
  readonly archivedAt?: string;
  readonly deletedAt?: string;
}

function item(
  owner: GroupPayload,
  index: number,
  overrides: ItemOverrides = {},
): ItemPayload {
  return itemPayloadSchema.parse({
    version: 1,
    id: `item.${String(index)}`,
    vaultId: owner.vaultId,
    groupId: owner.id,
    templateId: owner.template.id,
    title: overrides.title ?? `Credential ${String(index)}`,
    slug: `credential-${String(index)}`,
    aliases: overrides.aliases ?? [],
    ...(overrides.subtitle === undefined ? {} : { subtitle: overrides.subtitle }),
    templateVersion: owner.template.version,
    templateValues: overrides.templateValues ?? [],
    itemFields: overrides.itemFields ?? [],
    itemValues: overrides.itemValues ?? [],
    archivedFieldValues: [],
    notes: overrides.notes ?? [],
    tags: overrides.tags ?? [],
    favorite: false,
    ...(overrides.environment === undefined
      ? {}
      : { environment: overrides.environment }),
    ...(overrides.owner === undefined ? {} : { owner: overrides.owner }),
    ...(overrides.purpose === undefined ? {} : { purpose: overrides.purpose }),
    productionSensitive: false,
    relatedItemIds: [],
    attachmentIds: [],
    copySequences: [],
    revision: 1,
    createdAt: TIMESTAMP,
    updatedAt: TIMESTAMP,
    ...(overrides.archivedAt === undefined ? {} : { archivedAt: overrides.archivedAt }),
    ...(overrides.deletedAt === undefined ? {} : { deletedAt: overrides.deletedAt }),
  });
}

function scope(
  owner: GroupPayload,
  credentials: readonly ItemPayload[] = [],
): VaultSearchScope {
  return { group: owner, credentials };
}

function sources(hit: VaultSearchHit | undefined): readonly string[] {
  return (hit?.matches ?? []).map(({ source }) => source);
}

describe('normalizeVaultSearchTerm', () => {
  it('folds case, width, and surrounding whitespace into one comparable form', () => {
    expect(normalizeVaultSearchTerm('  ProdDB  ')).toBe('proddb');
    // NFKC maps the fullwidth forms onto their ASCII equivalents.
    expect(normalizeVaultSearchTerm('Ｐｒｏｄ')).toBe('prod');
  });

  it.each([
    ['an empty term', ''],
    ['a whitespace-only term', '   \t '],
  ])('rejects %s', (_description, term) => {
    expect(() => normalizeVaultSearchTerm(term)).toThrow(ValidationError);
  });

  it('rejects a term longer than the published bound', () => {
    expect(() =>
      normalizeVaultSearchTerm('a'.repeat(MAX_VAULT_SEARCH_TERM_LENGTH + 1)),
    ).toThrow(ValidationError);
    expect(
      normalizeVaultSearchTerm('a'.repeat(MAX_VAULT_SEARCH_TERM_LENGTH)),
    ).toHaveLength(MAX_VAULT_SEARCH_TERM_LENGTH);
  });
});

describe('isFieldValueSearchable', () => {
  it('admits a non-sensitive field the template marked locally searchable', () => {
    expect(isFieldValueSearchable(field('host'), METADATA_ONLY)).toBe(true);
  });

  it('refuses a field the template did not mark locally searchable', () => {
    expect(
      isFieldValueSearchable(
        field('host', { searchableLocally: false }),
        METADATA_ONLY,
      ),
    ).toBe(false);
  });

  it('refuses a sensitive field unless secret-value search is enabled', () => {
    const definition = field('token', { sensitive: true, searchableLocally: true });
    expect(isFieldValueSearchable(definition, METADATA_ONLY)).toBe(false);
    expect(isFieldValueSearchable(definition, SECRETS_ENABLED)).toBe(true);
  });

  it('refuses a sensitive field whose definition forbids reveal even when enabled', () => {
    const definition = field('token', {
      sensitive: true,
      searchableLocally: true,
      revealPolicy: 'never',
    });
    expect(isFieldValueSearchable(definition, SECRETS_ENABLED)).toBe(false);
  });

  it('refuses a sensitive field that was never marked locally searchable', () => {
    const definition = field('token', { sensitive: true, searchableLocally: false });
    expect(isFieldValueSearchable(definition, SECRETS_ENABLED)).toBe(false);
  });
});

describe('searchVault metadata surface', () => {
  it('matches every documented always-searchable credential property', () => {
    const owner = group(1);
    const credential = item(owner, 1, {
      title: 'Prod Database',
      aliases: ['proddb'],
      subtitle: 'Primary writer',
      tags: ['production'],
      environment: 'prod-eu',
      owner: 'platform-team',
      purpose: 'Serves the checkout path',
    });
    const target = scope(owner, [credential]);

    for (const [term, source] of [
      ['prod data', 'title'],
      ['proddb', 'alias'],
      ['credential-1', 'slug'],
      ['primary writer', 'subtitle'],
      ['production', 'tag'],
      ['prod-eu', 'environment'],
      ['platform-team', 'owner'],
      ['checkout', 'purpose'],
    ] as const) {
      const result = searchVault([target], term, METADATA_ONLY);
      expect(sources(result.hits[0]), `term ${term}`).toContain(source);
    }
  });

  it('matches group name, slug, alias, tag, and description', () => {
    const owner = group(1, {
      name: 'Engineering',
      aliases: ['eng'],
      tags: ['internal'],
      description: 'Shared platform credentials',
    });
    const target = scope(owner);

    for (const [term, source] of [
      ['engineering', 'group-name'],
      ['group-1', 'group-slug'],
      ['eng', 'group-alias'],
      ['internal', 'group-tag'],
      ['shared platform', 'group-description'],
    ] as const) {
      const result = searchVault([target], term, METADATA_ONLY);
      expect(sources(result.hits[0]), `term ${term}`).toContain(source);
    }
  });

  it('reports a credential hit under its own group', () => {
    const owner = group(1, { name: 'Engineering' });
    const credential = item(owner, 1, { title: 'Prod Database' });

    const result = searchVault([scope(owner, [credential])], 'prod', METADATA_ONLY);

    expect(result.hits).toHaveLength(1);
    const [hit] = result.hits;
    expect(hit?.kind).toBe('credential');
    expect(hit?.groupId).toBe(owner.id);
    expect(hit?.groupName).toBe('Engineering');
    expect(hit?.kind === 'credential' ? hit.credentialId : undefined).toBe(
      credential.id,
    );
    expect(hit?.kind === 'credential' ? hit.title : undefined).toBe('Prod Database');
  });

  it('reports the group and its credential separately when both match', () => {
    const owner = group(1, { name: 'Prod team' });
    const credential = item(owner, 1, { title: 'Prod Database' });

    const result = searchVault([scope(owner, [credential])], 'prod', METADATA_ONLY);

    expect(result.hits.map((hit) => hit.kind)).toEqual(['group', 'credential']);
  });

  it('is case, width, and accent-composition insensitive on both sides', () => {
    const owner = group(1);
    // A decomposed e-acute in the stored title must match a composed one.
    const credential = item(owner, 1, { title: 'Café POS' });

    const result = searchVault([scope(owner, [credential])], 'CAFÉ', METADATA_ONLY);

    expect(result.hits).toHaveLength(1);
  });

  it('finds nothing for a term that appears nowhere', () => {
    const owner = group(1);
    const result = searchVault(
      [scope(owner, [item(owner, 1)])],
      'no-such-thing',
      METADATA_ONLY,
    );

    expect(result.hits).toHaveLength(0);
    expect(result.truncated).toBe(false);
    expect(result.matchedCount).toBe(0);
  });

  it('reports how much of the vault was scanned', () => {
    const first = group(1);
    const second = group(2);
    const result = searchVault(
      [
        scope(first, [item(first, 1), item(first, 2)]),
        scope(second, [item(second, 3)]),
      ],
      'nothing',
      METADATA_ONLY,
    );

    expect(result.scannedGroups).toBe(2);
    expect(result.scannedCredentials).toBe(3);
  });
});

describe('searchVault note policy', () => {
  it('searches the content of a note that is not sensitive', () => {
    const owner = group(1);
    const credential = item(owner, 1, {
      notes: [note('1', { title: 'Runbook', content: `escalate to ${CANARY} first` })],
    });

    const result = searchVault([scope(owner, [credential])], CANARY, METADATA_ONLY);

    expect(sources(result.hits[0])).toEqual(['note-content']);
    // The locator names the note, never the matched text.
    expect(result.hits[0]?.matches[0]?.locator).toBe('Runbook');
    expect(JSON.stringify(result)).not.toContain(CANARY);
  });

  it('never searches the content of a sensitive note', () => {
    const owner = group(1);
    const credential = item(owner, 1, {
      notes: [note('1', { title: 'Break glass', content: CANARY, isSensitive: true })],
    });

    const result = searchVault([scope(owner, [credential])], CANARY, EVERYTHING);

    expect(result.hits).toHaveLength(0);
  });

  it('still matches the title of a sensitive note', () => {
    const owner = group(1);
    const credential = item(owner, 1, {
      notes: [note('1', { title: 'Break glass', content: CANARY, isSensitive: true })],
    });

    const result = searchVault(
      [scope(owner, [credential])],
      'break glass',
      METADATA_ONLY,
    );

    expect(sources(result.hits[0])).toEqual(['note-title']);
  });

  it('applies the same note policy to group notes', () => {
    const owner = group(1, {
      notes: [note('1', { title: 'Team runbook', content: CANARY, isSensitive: true })],
    });

    expect(searchVault([scope(owner)], CANARY, EVERYTHING).hits).toHaveLength(0);
    expect(
      sources(searchVault([scope(owner)], 'team runbook', METADATA_ONLY).hits[0]),
    ).toEqual(['group-note-title']);
  });

  it('skips an archived note unless archived entities are requested', () => {
    const owner = group(1);
    const credential = item(owner, 1, {
      notes: [note('1', { title: 'Retired runbook', archivedAt: TIMESTAMP })],
    });
    const target = scope(owner, [credential]);

    expect(searchVault([target], 'retired runbook', METADATA_ONLY).hits).toHaveLength(
      0,
    );
    expect(
      searchVault([target], 'retired runbook', ARCHIVED_INCLUDED).hits,
    ).toHaveLength(1);
  });
});

describe('searchVault field policy', () => {
  it('matches a field label without needing value search', () => {
    const host = field('host', { label: 'Database host' });
    const owner = group(1, { fields: [host] });
    const credential = item(owner, 1, {
      templateValues: [storedValue(host, 'db.internal')],
    });

    const result = searchVault(
      [scope(owner, [credential])],
      'database host',
      METADATA_ONLY,
    );

    expect(sources(result.hits[0])).toEqual(['field-label']);
    expect(result.hits[0]?.matches[0]?.locator).toBe('Database host');
  });

  it('matches a non-sensitive searchable value and reports only its label', () => {
    const host = field('host', { label: 'Database host' });
    const owner = group(1, { fields: [host] });
    const credential = item(owner, 1, {
      templateValues: [storedValue(host, `db-${CANARY}.internal`)],
    });

    const result = searchVault([scope(owner, [credential])], CANARY, METADATA_ONLY);

    expect(sources(result.hits[0])).toEqual(['field-value']);
    expect(result.hits[0]?.matches[0]?.locator).toBe('Database host');
    expect(JSON.stringify(result)).not.toContain(CANARY);
  });

  it('never matches a secret value unless secret-value search is enabled', () => {
    const token = field('token', {
      label: 'API token',
      sensitive: true,
      searchableLocally: true,
    });
    const owner = group(1, { fields: [token] });
    const credential = item(owner, 1, { templateValues: [storedValue(token, CANARY)] });
    const target = scope(owner, [credential]);

    expect(searchVault([target], CANARY, METADATA_ONLY).hits).toHaveLength(0);

    const enabled = searchVault([target], CANARY, SECRETS_ENABLED);
    expect(sources(enabled.hits[0])).toEqual(['field-value']);
    expect(enabled.hits[0]?.matches[0]?.locator).toBe('API token');
    expect(JSON.stringify(enabled)).not.toContain(CANARY);
  });

  it('never matches a secret value on a field that forbids reveal', () => {
    const token = field('token', {
      label: 'Recovery secret',
      sensitive: true,
      searchableLocally: true,
      revealPolicy: 'never',
    });
    const owner = group(1, { fields: [token] });
    const credential = item(owner, 1, { templateValues: [storedValue(token, CANARY)] });

    const result = searchVault([scope(owner, [credential])], CANARY, SECRETS_ENABLED);

    expect(result.hits).toHaveLength(0);
  });

  it('searches an item-only field through its inline definition', () => {
    const ticket = field('ticket', { label: 'Ticket' });
    const owner = group(1);
    const credential = item(owner, 1, {
      itemFields: [ticket],
      itemValues: [storedValue(ticket, `OPS-${CANARY}`)],
    });

    const result = searchVault([scope(owner, [credential])], CANARY, METADATA_ONLY);

    expect(sources(result.hits[0])).toEqual(['field-value']);
    expect(result.hits[0]?.matches[0]?.locator).toBe('Ticket');
  });

  it('refuses to search a stored value whose definition is unknown', () => {
    // The template no longer carries this field, so the definition that governs
    // the value is unavailable. An unknown definition means unknown sensitivity,
    // which must fail closed rather than assume the value is safe to scan.
    const host = field('host', { label: 'Database host' });
    const owner = group(1);
    const credential = item(owner, 1, { templateValues: [storedValue(host, CANARY)] });

    const result = searchVault([scope(owner, [credential])], CANARY, SECRETS_ENABLED);

    expect(result.hits).toHaveLength(0);
  });

  it('searches every element of a repeatable searchable field', () => {
    const alias = field('alias', { label: 'Alias', repeatable: true });
    const owner = group(1, { fields: [alias] });
    const credential = item(owner, 1, {
      templateValues: [
        {
          fieldId: alias.id,
          stableKey: alias.stableKey,
          value: {
            version: 1,
            state: 'present',
            content: {
              cardinality: 'multiple',
              elements: [
                {
                  id: 'element.1',
                  value: { kind: 'text', value: 'first' },
                  lifecycle: { version: 1, status: 'available' },
                },
                {
                  id: 'element.2',
                  value: { kind: 'text', value: CANARY },
                  lifecycle: { version: 1, status: 'available' },
                },
              ],
            },
          },
          updatedAt: TIMESTAMP,
        },
      ],
    });

    const result = searchVault([scope(owner, [credential])], CANARY, METADATA_ONLY);

    expect(sources(result.hits[0])).toEqual(['field-value']);
    expect(JSON.stringify(result)).not.toContain(CANARY);
  });

  /**
   * `environment-map` is not a sensitive field type, so the definition-level gate
   * alone would expose per-entry secrets. Classification has to be honoured.
   */
  it('searches an environment entry key even when its value is secret-classified', () => {
    const environment = field('env', { label: 'Environment', type: 'environment-map' });
    const owner = group(1, { fields: [environment] });
    const credential = item(owner, 1, {
      templateValues: [environmentValue(environment, 'DATABASE_URL', 'secret', CANARY)],
    });

    const result = searchVault(
      [scope(owner, [credential])],
      'database_url',
      METADATA_ONLY,
    );

    expect(sources(result.hits[0])).toEqual(['field-value']);
    expect(JSON.stringify(result)).not.toContain(CANARY);
  });

  it('never matches a secret-classified environment value unless secrets are enabled', () => {
    const environment = field('env', { label: 'Environment', type: 'environment-map' });
    const owner = group(1, { fields: [environment] });
    const credential = item(owner, 1, {
      templateValues: [environmentValue(environment, 'DATABASE_URL', 'secret', CANARY)],
    });
    const scopes = [scope(owner, [credential])];

    expect(searchVault(scopes, CANARY, METADATA_ONLY).hits).toHaveLength(0);
    expect(searchVault(scopes, CANARY, SECRETS_ENABLED).hits).toHaveLength(1);
  });

  it('matches a text-classified environment value without enabling secrets', () => {
    const environment = field('env', { label: 'Environment', type: 'environment-map' });
    const owner = group(1, { fields: [environment] });
    const credential = item(owner, 1, {
      templateValues: [environmentValue(environment, 'REGION', 'text', 'eu-west-1')],
    });

    const result = searchVault(
      [scope(owner, [credential])],
      'eu-west-1',
      METADATA_ONLY,
    );

    expect(sources(result.hits[0])).toEqual(['field-value']);
  });

  it('ignores a non-textual scalar', () => {
    const count = field('count', { label: 'Replica count', type: 'number' });
    const owner = group(1, { fields: [count] });
    const credential = item(owner, 1, {
      templateValues: [
        {
          fieldId: count.id,
          stableKey: count.stableKey,
          value: {
            version: 1,
            state: 'present',
            content: { cardinality: 'single', value: { kind: 'number', value: 42 } },
          },
          updatedAt: TIMESTAMP,
        },
      ],
    });

    const result = searchVault([scope(owner, [credential])], '42', METADATA_ONLY);

    expect(result.hits).toHaveLength(0);
  });
});

describe('searchVault lifecycle and bounds', () => {
  it('never returns a deleted credential even when archived entities are requested', () => {
    const owner = group(1);
    const credential = item(owner, 1, { title: 'Tombstoned', deletedAt: TIMESTAMP });

    const result = searchVault([scope(owner, [credential])], 'tombstoned', EVERYTHING);

    expect(result.hits).toHaveLength(0);
  });

  it('never returns anything from a deleted group', () => {
    const owner = group(1, { name: 'Tombstoned team', deletedAt: TIMESTAMP });
    const credential = item(owner, 1, { title: 'Tombstoned team key' });

    const result = searchVault([scope(owner, [credential])], 'tombstoned', EVERYTHING);

    expect(result.hits).toHaveLength(0);
  });

  it('skips an archived credential unless archived entities are requested', () => {
    const owner = group(1);
    const credential = item(owner, 1, { title: 'Retired', archivedAt: TIMESTAMP });
    const target = scope(owner, [credential]);

    expect(searchVault([target], 'retired', METADATA_ONLY).hits).toHaveLength(0);
    expect(searchVault([target], 'retired', ARCHIVED_INCLUDED).hits).toHaveLength(1);
  });

  it('skips every credential in an archived group unless requested', () => {
    const owner = group(1, { name: 'Retired team', archivedAt: TIMESTAMP });
    const credential = item(owner, 1, { title: 'Retired team key' });
    const target = scope(owner, [credential]);

    expect(searchVault([target], 'retired team', METADATA_ONLY).hits).toHaveLength(0);
    expect(
      searchVault([target], 'retired team', ARCHIVED_INCLUDED).hits.length,
    ).toBeGreaterThan(0);
  });

  it('caps the returned hits at the requested limit and reports truncation', () => {
    const owner = group(1);
    const credentials = Array.from({ length: 12 }, (_unused, index) =>
      item(owner, index + 1, { title: `Match ${String(index + 1)}` }),
    );

    const result = searchVault([scope(owner, credentials)], 'match', {
      ...METADATA_ONLY,
      limit: 5,
    });

    expect(result.hits).toHaveLength(5);
    expect(result.truncated).toBe(true);
    expect(result.matchedCount).toBe(12);
  });

  it('reports no truncation when every match fits', () => {
    const owner = group(1);
    const credentials = Array.from({ length: 3 }, (_unused, index) =>
      item(owner, index + 1, { title: `Match ${String(index + 1)}` }),
    );

    const result = searchVault([scope(owner, credentials)], 'match', METADATA_ONLY);

    expect(result.hits).toHaveLength(3);
    expect(result.truncated).toBe(false);
    expect(result.matchedCount).toBe(3);
  });

  it.each([
    ['zero', 0],
    ['a negative limit', -1],
    ['a fractional limit', 1.5],
    ['a limit above the published maximum', MAX_VAULT_SEARCH_RESULTS + 1],
  ])('rejects %s as a result limit', (_description, limit) => {
    const owner = group(1);
    expect(() =>
      searchVault([scope(owner, [item(owner, 1)])], 'match', {
        ...METADATA_ONLY,
        limit,
      }),
    ).toThrow(ValidationError);
  });

  it('defaults the limit to the published default', () => {
    const owner = group(1);
    const credentials = Array.from(
      { length: DEFAULT_VAULT_SEARCH_RESULT_LIMIT + 4 },
      (_unused, index) =>
        item(owner, index + 1, { title: `Match ${String(index + 1)}` }),
    );

    const result = searchVault([scope(owner, credentials)], 'match', METADATA_ONLY);

    expect(result.hits).toHaveLength(DEFAULT_VAULT_SEARCH_RESULT_LIMIT);
    expect(result.truncated).toBe(true);
  });

  it('bounds the matches reported for one hit', () => {
    const fields = Array.from(
      { length: MAX_VAULT_SEARCH_MATCHES_PER_HIT + 8 },
      (_unused, index) =>
        field(`match-${String(index)}`, {
          label: `Match label ${String(index)}`,
          sortOrder: index,
        }),
    );
    const owner = group(1, { fields });
    const credential = item(owner, 1);

    const result = searchVault(
      [scope(owner, [credential])],
      'match label',
      METADATA_ONLY,
    );

    expect(sources(result.hits[0])).toHaveLength(MAX_VAULT_SEARCH_MATCHES_PER_HIT);
    expect(result.hits[0]?.matchesTruncated).toBe(true);
  });

  it('reports each repeated match source at most once', () => {
    const owner = group(1);
    const credential = item(owner, 1, {
      title: 'match',
      tags: ['match-one', 'match-two', 'match-three'],
    });

    const result = searchVault([scope(owner, [credential])], 'match', METADATA_ONLY);

    expect(sources(result.hits[0]).filter((source) => source === 'tag')).toHaveLength(
      1,
    );
  });

  it('scans groups in the order supplied so results are deterministic', () => {
    const first = group(1, { name: 'Alpha match' });
    const second = group(2, { name: 'Beta match' });

    const result = searchVault([scope(first), scope(second)], 'match', METADATA_ONLY);

    expect(result.hits.map((hit) => hit.groupId)).toEqual([first.id, second.id]);
  });

  it('rejects an invalid term before scanning anything', () => {
    const owner = group(1);
    expect(() =>
      searchVault([scope(owner, [item(owner, 1)])], '   ', METADATA_ONLY),
    ).toThrow(ValidationError);
  });

  it('returns a frozen result so a caller cannot mutate it in place', () => {
    const owner = group(1);
    const result = searchVault(
      [scope(owner, [item(owner, 1, { title: 'match' })])],
      'match',
      METADATA_ONLY,
    );

    expect(Object.isFrozen(result)).toBe(true);
    expect(Object.isFrozen(result.hits)).toBe(true);
    expect(Object.isFrozen(result.hits[0])).toBe(true);
  });
});
