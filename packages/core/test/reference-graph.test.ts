import {
  fieldDefinitionSchema,
  groupPayloadSchema,
  itemPayloadSchema,
  type FieldDefinition,
  type GroupPayload,
  type ItemId,
  type ItemPayload,
} from '@kavrix/schemas';
import { describe, expect, it } from 'vitest';

import { ValidationError } from '../src/errors.js';
import {
  DEFAULT_REFERENCE_TRAVERSAL_DEPTH,
  MAX_REFERENCE_TRAVERSAL_DEPTH,
  MAX_REFERENCE_TRAVERSAL_NODES,
  findReferencePath,
  isItemReferenceField,
  resolveCredentialReferences,
  traverseReferenceGraph,
  type ReferenceScope,
} from '../src/policies/reference-graph.js';

const TIMESTAMP = '2026-08-16T00:00:00.000Z';

/**
 * The value that must never reach a reference report.
 *
 * A reference names a target and the field that binds it. If a stored secret ever
 * leaked into the graph output, every assertion below would fail on this exact
 * string rather than on something subtler.
 */
const CANARY = 'canary-secret-value';

function id(index: number): ItemId {
  return `item.${String(index)}` as ItemId;
}

interface FieldOverrides {
  readonly type?: FieldDefinition['type'];
  readonly label?: string;
  readonly repeatable?: boolean;
  readonly sensitive?: boolean;
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
    searchableLocally: false,
    showInPreview: false,
    copyPolicy: 'allowed',
    revealPolicy: sensitive ? 'timed' : 'never',
    reauthenticationPolicy: sensitive ? 'after-lock' : 'never',
    exportPolicy: 'guarded',
    sortOrder: overrides.sortOrder ?? 0,
    createdAt: TIMESTAMP,
    updatedAt: TIMESTAMP,
  });
}

const REFERENCE_FIELD = field('depends_on', {
  type: 'item-reference',
  label: 'Depends on',
});
const REPEATABLE_REFERENCE_FIELD = field('upstream', {
  type: 'item-reference',
  label: 'Upstream',
  repeatable: true,
  sortOrder: 1,
});
const SECRET_FIELD = field('token', { sensitive: true, sortOrder: 2 });

function referenceValue(definition: FieldDefinition, targetId: ItemId): unknown {
  return {
    fieldId: definition.id,
    stableKey: definition.stableKey,
    value: {
      version: 1,
      state: 'present',
      content: {
        cardinality: 'single',
        value: { kind: 'item-reference', itemId: targetId },
      },
    },
    updatedAt: TIMESTAMP,
  };
}

function referenceElements(
  definition: FieldDefinition,
  targets: readonly Readonly<{ elementId: string; targetId: ItemId }>[],
): unknown {
  return {
    fieldId: definition.id,
    stableKey: definition.stableKey,
    value: {
      version: 1,
      state: 'present',
      content: {
        cardinality: 'multiple',
        elements: targets.map(({ elementId, targetId }) => ({
          id: elementId,
          value: { kind: 'item-reference', itemId: targetId },
          lifecycle: { version: 1, status: 'available' },
        })),
      },
    },
    updatedAt: TIMESTAMP,
  };
}

function secretValue(definition: FieldDefinition, value: string): unknown {
  return {
    fieldId: definition.id,
    stableKey: definition.stableKey,
    value: {
      version: 1,
      state: 'present',
      content: {
        cardinality: 'single',
        value: { kind: 'secret', value },
      },
    },
    updatedAt: TIMESTAMP,
  };
}

function group(index: number, name?: string): GroupPayload {
  return groupPayloadSchema.parse({
    id: `group.${String(index)}`,
    vaultId: 'vault.1',
    name: name ?? `Group ${String(index)}`,
    slug: `group-${String(index)}`,
    aliases: [],
    tags: [],
    notes: [],
    template: {
      id: `template.${String(index)}`,
      name: 'Custom',
      version: 1,
      fields: [],
      createdAt: TIMESTAMP,
      updatedAt: TIMESTAMP,
    },
    sortOrder: index,
    revision: 1,
    createdAt: TIMESTAMP,
    updatedAt: TIMESTAMP,
  });
}

interface ItemOverrides {
  readonly title?: string;
  readonly relatedItemIds?: readonly ItemId[];
  readonly itemFields?: readonly FieldDefinition[];
  readonly itemValues?: readonly unknown[];
  readonly templateValues?: readonly unknown[];
  readonly archivedAt?: string;
}

function item(
  owner: GroupPayload,
  index: number,
  overrides: ItemOverrides = {},
): ItemPayload {
  return itemPayloadSchema.parse({
    version: 1,
    id: id(index),
    vaultId: owner.vaultId,
    groupId: owner.id,
    templateId: owner.template.id,
    title: overrides.title ?? `Credential ${String(index)}`,
    slug: `credential-${String(index)}`,
    aliases: [],
    templateVersion: owner.template.version,
    templateValues: overrides.templateValues ?? [],
    itemFields: overrides.itemFields ?? [],
    itemValues: overrides.itemValues ?? [],
    archivedFieldValues: [],
    notes: [],
    tags: [],
    favorite: false,
    productionSensitive: false,
    relatedItemIds: overrides.relatedItemIds ?? [],
    attachmentIds: [],
    copySequences: [],
    revision: 1,
    createdAt: TIMESTAMP,
    updatedAt: TIMESTAMP,
    ...(overrides.archivedAt === undefined ? {} : { archivedAt: overrides.archivedAt }),
  });
}

function scope(
  owner: GroupPayload,
  credentials: readonly ItemPayload[],
): ReferenceScope {
  return { group: owner, credentials };
}

/** A chain 1 -> 2 -> 3 -> ... -> length, each edge declared on the relation list. */
function chain(length: number): readonly ReferenceScope[] {
  const owner = group(1);
  const credentials = Array.from({ length }, (_value, index) =>
    item(owner, index + 1, {
      relatedItemIds: index + 2 <= length ? [id(index + 2)] : [],
    }),
  );
  return [scope(owner, credentials)];
}

/** One credential referencing `width` others, each of which references nothing. */
function fan(width: number): readonly ReferenceScope[] {
  const owner = group(1);
  const targets = Array.from({ length: width }, (_value, index) =>
    item(owner, index + 2),
  );
  const root = item(owner, 1, {
    relatedItemIds: targets.map(({ id: targetId }) => targetId),
  });
  return [scope(owner, [root, ...targets])];
}

describe('resolveCredentialReferences', () => {
  it('reports the field that binds each target without exposing any stored value', () => {
    const owner = group(1);
    const target = item(owner, 2, { title: 'Primary DB' });
    const source = item(owner, 1, {
      title: 'API Service',
      relatedItemIds: [id(2)],
      itemFields: [REFERENCE_FIELD, SECRET_FIELD],
      itemValues: [
        referenceValue(REFERENCE_FIELD, id(2)),
        secretValue(SECRET_FIELD, CANARY),
      ],
    });

    const references = resolveCredentialReferences(
      [scope(owner, [source, target])],
      id(1),
    );

    expect(references).toHaveLength(1);
    expect(references[0]).toEqual({
      targetId: id(2),
      state: 'active',
      groupId: 'group.1',
      groupName: 'Group 1',
      title: 'Primary DB',
      bindings: [
        {
          fieldKey: 'depends_on',
          fieldLabel: 'Depends on',
          scope: 'item',
        },
      ],
      reciprocal: false,
    });
    // The report is rendered and serialised, so a stored secret must not travel
    // in it even though the policy walked past one to build the bindings.
    expect(JSON.stringify(references)).not.toContain(CANARY);
  });

  it('carries the element ID of a repeatable reference so one of several can be named', () => {
    const owner = group(1);
    const first = item(owner, 2, { title: 'Primary DB' });
    const second = item(owner, 3, { title: 'Replica DB' });
    const source = item(owner, 1, {
      relatedItemIds: [id(2), id(3)],
      itemFields: [REPEATABLE_REFERENCE_FIELD],
      itemValues: [
        referenceElements(REPEATABLE_REFERENCE_FIELD, [
          { elementId: 'element.a', targetId: id(2) },
          { elementId: 'element.b', targetId: id(3) },
        ]),
      ],
    });

    const references = resolveCredentialReferences(
      [scope(owner, [source, first, second])],
      id(1),
    );

    expect(references.map(({ bindings }) => bindings)).toEqual([
      [
        {
          fieldKey: 'upstream',
          fieldLabel: 'Upstream',
          scope: 'item',
          elementId: 'element.a',
        },
      ],
      [
        {
          fieldKey: 'upstream',
          fieldLabel: 'Upstream',
          scope: 'item',
          elementId: 'element.b',
        },
      ],
    ]);
  });

  it('distinguishes an archived target, a deleted target, and a declared-only relation', () => {
    const owner = group(1);
    const archived = item(owner, 2, { title: 'Retired DB', archivedAt: TIMESTAMP });
    const active = item(owner, 3, { title: 'Replica DB' });
    // item.4 is absent from every scope, which is exactly how a deleted record
    // presents itself: tombstoned records are excluded from every read.
    const source = item(owner, 1, {
      relatedItemIds: [id(2), id(3), id(4)],
      itemFields: [REFERENCE_FIELD],
      itemValues: [referenceValue(REFERENCE_FIELD, id(2))],
    });

    const references = resolveCredentialReferences(
      [scope(owner, [source, archived, active])],
      id(1),
    );

    expect(references.map(({ targetId, state }) => [targetId, state])).toEqual([
      [id(2), 'archived'],
      [id(3), 'active'],
      [id(4), 'missing'],
    ]);
    // A relation with no field binding it is a valid canonical state and must be
    // reported, not filtered out as if it did not exist.
    expect(references[1]?.bindings).toEqual([]);
    // A missing target resolves to no group and no title, so nothing invented
    // stands in for the record that is gone. The keys are absent rather than
    // undefined, which is what keeps them out of the `--json` output.
    expect(references[2]?.bindings).toEqual([]);
    expect(references[2]).not.toHaveProperty('title');
    expect(references[2]).not.toHaveProperty('groupId');
    expect(references[2]).not.toHaveProperty('groupName');
  });

  it('reports a reciprocal relation from the target side, across groups', () => {
    const first = group(1);
    const second = group(2, 'Data');
    const source = item(first, 1, { relatedItemIds: [id(2)] });
    const target = item(second, 2, { title: 'Primary DB', relatedItemIds: [id(1)] });

    const scopes = [scope(first, [source]), scope(second, [target])];

    expect(resolveCredentialReferences(scopes, id(1))[0]).toMatchObject({
      groupId: 'group.2',
      groupName: 'Data',
      reciprocal: true,
    });
    expect(resolveCredentialReferences(scopes, id(2))[0]).toMatchObject({
      groupId: 'group.1',
      reciprocal: true,
    });
  });

  it('refuses a credential that is not in the unlocked vault', () => {
    expect(() => resolveCredentialReferences(chain(2), id(99))).toThrow(
      ValidationError,
    );
  });
});

describe('traverseReferenceGraph', () => {
  it('reports the credential itself and its direct references at the default depth', () => {
    const result = traverseReferenceGraph(chain(3), id(1));

    expect(DEFAULT_REFERENCE_TRAVERSAL_DEPTH).toBe(1);
    expect(
      result.nodes.map(({ depth, credentialId }) => [depth, credentialId]),
    ).toEqual([
      [0, id(1)],
      [1, id(2)],
    ]);
    expect(result.reachedDepth).toBe(1);
    expect(result.truncated).toBe(false);
  });

  it('walks outward to the requested depth', () => {
    const result = traverseReferenceGraph(chain(4), id(1), { maxDepth: 3 });

    expect(result.nodes.map(({ credentialId }) => credentialId)).toEqual([
      id(1),
      id(2),
      id(3),
      id(4),
    ]);
    expect(result.nodes.map(({ parentId }) => parentId)).toEqual([
      undefined,
      id(1),
      id(2),
      id(3),
    ]);
    expect(result.cycleCount).toBe(0);
  });

  it('terminates on a two-credential cycle and marks the closing edge', () => {
    const owner = group(1);
    const first = item(owner, 1, { relatedItemIds: [id(2)] });
    const second = item(owner, 2, { relatedItemIds: [id(1)] });

    const result = traverseReferenceGraph([scope(owner, [first, second])], id(1), {
      maxDepth: MAX_REFERENCE_TRAVERSAL_DEPTH,
    });

    // Without cycle handling this walk would never return; with silent pruning it
    // would return without ever saying the relation loops back.
    expect(
      result.nodes.map(({ credentialId, depth, cycle, revisit }) => ({
        credentialId,
        depth,
        cycle,
        revisit,
      })),
    ).toEqual([
      { credentialId: id(1), depth: 0, cycle: false, revisit: false },
      { credentialId: id(2), depth: 1, cycle: false, revisit: false },
      { credentialId: id(1), depth: 2, cycle: true, revisit: true },
    ]);
    expect(result.cycleCount).toBe(1);
  });

  it('terminates on a self-reference declared on the relation list', () => {
    // The item payload refuses a self-relation, so the only way one can exist is
    // as a relation to an ID that a later mutation gave to this credential. The
    // traversal must still terminate rather than trust the schema to prevent it.
    const owner = group(1);
    const selfish = {
      ...item(owner, 1),
      relatedItemIds: [id(1)],
    } as ItemPayload;

    const result = traverseReferenceGraph([scope(owner, [selfish])], id(1), {
      maxDepth: MAX_REFERENCE_TRAVERSAL_DEPTH,
    });

    expect(result.nodes).toHaveLength(2);
    expect(result.nodes[1]).toMatchObject({ credentialId: id(1), cycle: true });
    expect(result.cycleCount).toBe(1);
  });

  it('separates a shared target from a cycle', () => {
    const owner = group(1);
    // 1 -> 2, 1 -> 3, 2 -> 4, 3 -> 4: item.4 is shared, and nothing loops.
    const scopes = [
      scope(owner, [
        item(owner, 1, { relatedItemIds: [id(2), id(3)] }),
        item(owner, 2, { relatedItemIds: [id(4)] }),
        item(owner, 3, { relatedItemIds: [id(4)] }),
        item(owner, 4),
      ]),
    ];

    const result = traverseReferenceGraph(scopes, id(1), { maxDepth: 4 });

    const shared = result.nodes.filter(({ credentialId }) => credentialId === id(4));
    expect(shared).toHaveLength(2);
    expect(shared.map(({ revisit, cycle }) => ({ revisit, cycle }))).toEqual([
      { revisit: false, cycle: false },
      // The second arrival is a repeat, but it is not an ancestor of the node
      // that reached it, so calling it a cycle would be wrong.
      { revisit: true, cycle: false },
    ]);
    expect(result.cycleCount).toBe(0);
  });

  it('counts a missing target and does not try to expand it', () => {
    const owner = group(1);
    const scopes = [scope(owner, [item(owner, 1, { relatedItemIds: [id(9)] })])];

    const result = traverseReferenceGraph(scopes, id(1), { maxDepth: 4 });

    expect(result.missingCount).toBe(1);
    expect(result.nodes[1]).toMatchObject({ credentialId: id(9), state: 'missing' });
    expect(result.nodes).toHaveLength(2);
  });

  it('stops at the requested depth without reporting truncation', () => {
    const result = traverseReferenceGraph(
      chain(MAX_REFERENCE_TRAVERSAL_DEPTH + 8),
      id(1),
      {
        maxDepth: MAX_REFERENCE_TRAVERSAL_DEPTH,
      },
    );

    expect(result.nodes).toHaveLength(MAX_REFERENCE_TRAVERSAL_DEPTH + 1);
    expect(result.reachedDepth).toBe(MAX_REFERENCE_TRAVERSAL_DEPTH);
    // The chain continues past the last reported node, but the depth bound is a
    // deliberate stop and not a ceiling breach.
    expect(result.truncated).toBe(false);
  });

  it('reports truncation instead of exceeding the node ceiling', () => {
    // Depth alone cannot stop this walk: every target sits one edge from the root,
    // so only the node ceiling can bound it.
    const result = traverseReferenceGraph(
      fan(MAX_REFERENCE_TRAVERSAL_NODES + 100),
      id(1),
      {
        maxDepth: MAX_REFERENCE_TRAVERSAL_DEPTH,
      },
    );

    expect(result.nodes).toHaveLength(MAX_REFERENCE_TRAVERSAL_NODES);
    expect(result.truncated).toBe(true);
    expect(result.reachedDepth).toBe(1);
  });

  it.each([
    ['zero', 0],
    ['negative', -1],
    ['fractional', 1.5],
    ['beyond the ceiling', MAX_REFERENCE_TRAVERSAL_DEPTH + 1],
    ['not a number', Number.NaN],
  ])('refuses a %s depth', (_label, maxDepth) => {
    expect(() => traverseReferenceGraph(chain(2), id(1), { maxDepth })).toThrow(
      ValidationError,
    );
  });

  it('refuses a root that is not in the unlocked vault', () => {
    expect(() => traverseReferenceGraph(chain(2), id(99))).toThrow(ValidationError);
  });
});

describe('findReferencePath', () => {
  it('returns the shortest path when one credential already reaches another', () => {
    expect(findReferencePath(chain(4), id(1), id(4))).toEqual([
      id(1),
      id(2),
      id(3),
      id(4),
    ]);
  });

  it('returns undefined when no path exists', () => {
    expect(findReferencePath(chain(4), id(4), id(1))).toBeUndefined();
  });

  it('returns the single-node path when the endpoints are the same credential', () => {
    expect(findReferencePath(chain(2), id(1), id(1))).toEqual([id(1)]);
  });

  it('terminates on a cycle rather than revisiting a credential', () => {
    const owner = group(1);
    const scopes = [
      scope(owner, [
        item(owner, 1, { relatedItemIds: [id(2)] }),
        item(owner, 2, { relatedItemIds: [id(1)] }),
      ]),
    ];

    expect(findReferencePath(scopes, id(1), id(9))).toBeUndefined();
  });

  it('refuses an origin that is not in the unlocked vault', () => {
    expect(() => findReferencePath(chain(2), id(99), id(1))).toThrow(ValidationError);
  });
});

describe('isItemReferenceField', () => {
  it('accepts only the canonical reference field type', () => {
    expect(isItemReferenceField(REFERENCE_FIELD)).toBe(true);
    expect(isItemReferenceField(REPEATABLE_REFERENCE_FIELD)).toBe(true);
    expect(isItemReferenceField(SECRET_FIELD)).toBe(false);
    expect(isItemReferenceField(field('note_url', { type: 'url' }))).toBe(false);
    // An attachment reference is a different entity with a different lifetime, so
    // it must not be writable through a command that maintains item relations.
    expect(isItemReferenceField(field('proof', { type: 'attachment' }))).toBe(false);
  });
});
