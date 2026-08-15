import { describe, expect, expectTypeOf, it } from 'vitest';
import * as fc from 'fast-check';

import {
  fieldDefinitionSchema,
  fieldValueSchema,
  groupTemplateSchema,
  itemPayloadSchema,
  keySlotIdSchema,
  keySlotSchema,
  noteIdSchema,
  noteSchema,
  secretValueSchema,
  type AttachmentStreamFinalizeInput,
  type AttachmentStreamProgress,
  type AttachmentStreamStartInput,
  type FieldValue,
  type KeySlot,
  type OpaqueMutation,
  type PersistedAttachmentChunkRecord,
} from '@kavrix/schemas';

import {
  LastUnlockSlotError,
  NotFoundError,
  ValidationError,
  addNote,
  archiveNote,
  deleteNote,
  duplicateNote,
  restoreNote,
  reorderNotes,
  revokeKeySlot,
  updateNote,
  validateItemAgainstTemplate,
  validateFieldValue,
  assertSingleValueWriteTarget,
  type AttachmentStreamStagingSession,
  type VaultStoragePort,
} from '../src/index.js';

const timestamp = '2026-08-10T00:00:00.000Z';

describe('storage port attachment contracts', () => {
  it('uses canonical hidden staging sessions and ordered persisted chunks', () => {
    expectTypeOf<
      Parameters<VaultStoragePort['beginAttachmentStream']>[0]
    >().toEqualTypeOf<AttachmentStreamStartInput>();
    expectTypeOf<
      Awaited<ReturnType<VaultStoragePort['beginAttachmentStream']>>
    >().toEqualTypeOf<AttachmentStreamStagingSession>();
    expectTypeOf<
      Parameters<AttachmentStreamStagingSession['finalize']>[0]
    >().toEqualTypeOf<AttachmentStreamFinalizeInput>();
    expectTypeOf<
      Parameters<AttachmentStreamStagingSession['writeChunk']>[0]
    >().toEqualTypeOf<PersistedAttachmentChunkRecord>();
    expectTypeOf<
      AttachmentStreamStagingSession['progress']
    >().toEqualTypeOf<AttachmentStreamProgress>();
    expectTypeOf<
      Awaited<ReturnType<AttachmentStreamStagingSession['writeChunk']>>
    >().toEqualTypeOf<AttachmentStreamProgress>();
    expectTypeOf<
      Extract<OpaqueMutation, { entityType: 'attachment' }>
    >().toEqualTypeOf<never>();
    expectTypeOf<ReturnType<VaultStoragePort['listAttachmentChunks']>>().toEqualTypeOf<
      AsyncIterable<PersistedAttachmentChunkRecord>
    >();
  });
});

function numberValue(value: number): FieldValue {
  return fieldValueSchema.parse({
    version: 1,
    state: 'present',
    content: { cardinality: 'single', value: { kind: 'number', value } },
  });
}

function textValue(value: string): FieldValue {
  return fieldValueSchema.parse({
    version: 1,
    state: 'present',
    content: { cardinality: 'single', value: { kind: 'text', value } },
  });
}

function envelope(slotId: string): Record<string, unknown> {
  return {
    version: 1,
    algorithm: 'xchacha20-poly1305-ietf',
    nonce: 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA',
    ciphertext: 'AQID',
    authenticationTag: 'AAAAAAAAAAAAAAAAAAAAAA',
    aad: {
      version: 1,
      schemaVersion: 1,
      keyVersion: 1,
      vaultId: 'vault.1',
      entityType: 'wrapped-root-key',
      entityId: slotId,
      purpose: 'vrk-slot',
    },
    keyVersion: 1,
  };
}

function slot(id: string, keyVersion = 1): KeySlot {
  return keySlotSchema.parse({
    id,
    slotVersion: 1,
    type: 'portable-key',
    state: 'active',
    keyVersion,
    derivation: {
      algorithm: 'hkdf-sha256',
      version: 1,
      salt: 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA',
      context: 'credvault/v1/portable-key-wrap',
      outputLength: 32,
    },
    wrappedRootKey: {
      ...envelope(id),
      keyVersion,
      aad: { ...(envelope(id)['aad'] as object), keyVersion },
    },
    createdAt: timestamp,
  });
}

describe('key slot revocation', () => {
  it('prevents deletion of the final active unlock method', () => {
    expect(() =>
      revokeKeySlot([slot('slot.1')], keySlotIdSchema.parse('slot.1'), timestamp),
    ).toThrow(LastUnlockSlotError);
  });

  it('revokes one slot when another active method remains', () => {
    const result = revokeKeySlot(
      [slot('slot.1'), slot('slot.2')],
      keySlotIdSchema.parse('slot.1'),
      timestamp,
    );
    expect(result[0]?.state).toBe('revoked');
    expect(result[1]?.state).toBe('active');
  });

  it('does not count an active stale-key slot as protection for the current key', () => {
    expect(() =>
      revokeKeySlot(
        [slot('slot.current', 2), slot('slot.stale', 1)],
        keySlotIdSchema.parse('slot.current'),
        timestamp,
      ),
    ).toThrow(LastUnlockSlotError);
  });

  it('can revoke a superseded slot without retaining incompatible state metadata', () => {
    const superseded = keySlotSchema.parse({
      ...slot('slot.old'),
      state: 'superseded',
      supersededAt: timestamp,
    });
    const result = revokeKeySlot(
      [superseded, slot('slot.current')],
      keySlotIdSchema.parse('slot.old'),
      timestamp,
    );

    expect(result[0]?.state).toBe('revoked');
    expect(result[0]?.supersededAt).toBeUndefined();
  });

  it('is idempotent for revoked slots and fails safely for unknown IDs', () => {
    const revoked = keySlotSchema.parse({
      ...slot('slot.revoked'),
      state: 'revoked',
      revokedAt: timestamp,
    });
    const slots = [revoked, slot('slot.active')];
    expect(revokeKeySlot(slots, keySlotIdSchema.parse('slot.revoked'), timestamp)).toBe(
      slots,
    );
    expect(() =>
      revokeKeySlot(slots, keySlotIdSchema.parse('slot.missing'), timestamp),
    ).toThrow(NotFoundError);
  });
});

describe('contextual field validation', () => {
  it('validates dynamic select and port values without exposing invalid values', () => {
    const port = fieldDefinitionSchema.parse({
      id: 'field.port',
      stableKey: 'port',
      label: 'Port',
      type: 'port',
      required: true,
      sensitive: false,
      repeatable: false,
      copyable: true,
      searchableLocally: true,
      showInPreview: true,
      copyPolicy: 'allowed',
      revealPolicy: 'never',
      reauthenticationPolicy: 'never',
      exportPolicy: 'encrypted-only',
      sortOrder: 0,
      createdAt: timestamp,
      updatedAt: timestamp,
    });
    expect(() => {
      validateFieldValue(port, numberValue(5432));
    }).not.toThrow();
    expect(() => {
      validateFieldValue(port, numberValue(70_000));
    }).toThrow(ValidationError);
  });

  it('accepts arbitrary bounded values for repeatable secret fields', () => {
    const repeatableSecret = fieldDefinitionSchema.parse({
      id: 'field.recovery_answer',
      stableKey: 'recovery_answer',
      label: 'Recovery answers',
      type: 'secret',
      required: false,
      sensitive: true,
      repeatable: true,
      copyable: true,
      searchableLocally: false,
      showInPreview: false,
      copyPolicy: 'allowed',
      revealPolicy: 'timed',
      reauthenticationPolicy: 'after-lock',
      exportPolicy: 'guarded',
      sortOrder: 0,
      createdAt: timestamp,
      updatedAt: timestamp,
    });
    fc.assert(
      fc.property(
        fc.array(fc.string({ minLength: 1, maxLength: 1_024 }), {
          minLength: 1,
          maxLength: 100,
        }),
        (values) => {
          const repeated = fieldValueSchema.parse({
            version: 1,
            state: 'present',
            content: {
              cardinality: 'multiple',
              elements: values.map((value, index) => ({
                id: `element.${String(index)}`,
                value: { kind: 'secret', value: secretValueSchema.parse(value) },
                lifecycle: { version: 1, status: 'available' },
              })),
            },
          });
          expect(() => {
            validateFieldValue(repeatableSecret, repeated);
          }).not.toThrow();
        },
      ),
      { numRuns: 200 },
    );
  });

  it('refuses a single value write that would discard repeatable elements', () => {
    const repeatable = fieldDefinitionSchema.parse({
      id: 'field.recovery_codes',
      stableKey: 'recovery_codes',
      label: 'Recovery codes',
      type: 'secret',
      required: false,
      sensitive: true,
      repeatable: true,
      copyable: true,
      searchableLocally: false,
      showInPreview: false,
      copyPolicy: 'allowed',
      revealPolicy: 'timed',
      reauthenticationPolicy: 'after-lock',
      exportPolicy: 'guarded',
      sortOrder: 0,
      createdAt: timestamp,
      updatedAt: timestamp,
    });
    const single = fieldDefinitionSchema.parse({
      ...repeatable,
      id: 'field.token',
      stableKey: 'token',
      label: 'Token',
      repeatable: false,
    });
    const collection = fieldDefinitionSchema.parse({
      ...single,
      id: 'field.tags',
      stableKey: 'tags',
      label: 'Tags',
      type: 'tags',
      sensitive: false,
      revealPolicy: 'never',
      reauthenticationPolicy: 'never',
      exportPolicy: 'encrypted-only',
    });
    const stored = fieldValueSchema.parse({
      version: 1,
      state: 'present',
      content: {
        cardinality: 'multiple',
        elements: [
          {
            id: 'element.0',
            value: { kind: 'secret', value: secretValueSchema.parse('first') },
            lifecycle: { version: 1, status: 'available' },
          },
        ],
      },
    });

    // A repeatable definition or a collection type is refused on its own,
    // because either would lose every element the write does not name.
    expect(() => {
      assertSingleValueWriteTarget(repeatable, undefined);
    }).toThrow(ValidationError);
    expect(() => {
      assertSingleValueWriteTarget(collection, undefined);
    }).toThrow(ValidationError);

    // A single-value definition is refused only when the stored value already
    // holds elements, including one orphaned by a template change.
    expect(() => {
      assertSingleValueWriteTarget(single, undefined);
    }).not.toThrow();
    expect(() => {
      assertSingleValueWriteTarget(single, textValue('current'));
    }).not.toThrow();
    expect(() => {
      assertSingleValueWriteTarget(single, stored);
    }).toThrow(ValidationError);
    expect(() => {
      assertSingleValueWriteTarget(
        single,
        fieldValueSchema.parse({
          version: 1,
          state: 'orphaned',
          originalValue: stored,
        }),
      );
    }).toThrow(ValidationError);
  });

  it('binds item template identity, version, definitions, and required values', () => {
    const definition = fieldDefinitionSchema.parse({
      id: 'field.username',
      stableKey: 'username',
      label: 'Username',
      type: 'username',
      required: true,
      sensitive: false,
      repeatable: false,
      copyable: true,
      searchableLocally: true,
      showInPreview: true,
      copyPolicy: 'allowed',
      revealPolicy: 'never',
      reauthenticationPolicy: 'never',
      exportPolicy: 'encrypted-only',
      sortOrder: 0,
      createdAt: timestamp,
      updatedAt: timestamp,
    });
    const template = groupTemplateSchema.parse({
      id: 'template.1',
      name: 'Login',
      version: 1,
      fields: [definition],
      createdAt: timestamp,
      updatedAt: timestamp,
    });
    const item = itemPayloadSchema.parse({
      version: 1,
      id: 'item.1',
      vaultId: 'vault.1',
      groupId: 'group.1',
      templateId: 'template.1',
      title: 'Account',
      aliases: [],
      templateVersion: 1,
      templateValues: [
        {
          fieldId: definition.id,
          stableKey: definition.stableKey,
          value: textValue('user'),
          updatedAt: timestamp,
        },
      ],
      itemFields: [],
      itemValues: [],
      archivedFieldValues: [],
      notes: [],
      tags: [],
      favorite: false,
      productionSensitive: false,
      relatedItemIds: [],
      attachmentIds: [],
      copySequences: [],
      revision: 1,
      createdAt: timestamp,
      updatedAt: timestamp,
    });
    expect(() => {
      validateItemAgainstTemplate(item, template);
    }).not.toThrow();
    expect(() => {
      validateItemAgainstTemplate(
        itemPayloadSchema.parse({ ...item, templateId: 'template.other' }),
        template,
      );
    }).toThrow();
    expect(() => {
      validateItemAgainstTemplate(
        itemPayloadSchema.parse({ ...item, templateValues: [] }),
        template,
      );
    }).toThrow(ValidationError);
    expect(() => {
      validateItemAgainstTemplate(
        itemPayloadSchema.parse({
          ...item,
          templateValues: [
            ...item.templateValues,
            {
              fieldId: 'field.extra',
              stableKey: 'extra',
              value: textValue('extra'),
              updatedAt: timestamp,
            },
          ],
        }),
        template,
      );
    }).toThrow(ValidationError);
  });
});

describe('note lifecycle', () => {
  it('adds, edits, archives, restores, duplicates, and deletes notes', () => {
    const original = noteSchema.parse({
      id: 'note.1',
      title: 'Recovery',
      content: secretValueSchema.parse('fake recovery instructions'),
      isSensitive: true,
      isPinned: false,
      tags: [],
      sortOrder: 0,
      createdAt: timestamp,
      updatedAt: timestamp,
    });
    let notes = addNote([], original);
    notes = updateNote(
      notes,
      noteIdSchema.parse('note.1'),
      { isPinned: true },
      timestamp,
    );
    notes = archiveNote(notes, noteIdSchema.parse('note.1'), timestamp);
    expect(notes[0]?.archivedAt).toBe(timestamp);
    notes = restoreNote(notes, noteIdSchema.parse('note.1'), timestamp);
    notes = duplicateNote(
      notes,
      noteIdSchema.parse('note.1'),
      noteIdSchema.parse('note.2'),
      timestamp,
    );
    notes = deleteNote(notes, noteIdSchema.parse('note.1'));
    expect(notes).toHaveLength(1);
    expect(notes[0]?.id).toBe('note.2');
  });

  it('rejects duplicate and missing notes and validates complete reorderings', () => {
    const first = noteSchema.parse({
      id: 'note.1',
      title: 'First',
      content: secretValueSchema.parse('one'),
      isSensitive: false,
      isPinned: false,
      tags: [],
      sortOrder: 0,
      createdAt: timestamp,
      updatedAt: timestamp,
    });
    const second = noteSchema.parse({ ...first, id: 'note.2', title: 'Second' });
    expect(() => addNote([first], first)).toThrow(ValidationError);
    expect(() =>
      updateNote([first], noteIdSchema.parse('note.missing'), {}, timestamp),
    ).toThrow(NotFoundError);
    expect(() => deleteNote([first], noteIdSchema.parse('note.missing'))).toThrow(
      NotFoundError,
    );
    expect(() =>
      duplicateNote(
        [first],
        noteIdSchema.parse('note.missing'),
        noteIdSchema.parse('note.3'),
        timestamp,
      ),
    ).toThrow(NotFoundError);
    expect(() =>
      reorderNotes([first, second], [noteIdSchema.parse('note.1')], timestamp),
    ).toThrow(ValidationError);
    expect(() =>
      reorderNotes(
        [first, second],
        [noteIdSchema.parse('note.1'), noteIdSchema.parse('note.unknown')],
        timestamp,
      ),
    ).toThrow(ValidationError);

    const reordered = reorderNotes(
      [first, second],
      [noteIdSchema.parse('note.2'), noteIdSchema.parse('note.1')],
      timestamp,
    );
    expect(reordered.map(({ id, sortOrder }) => [id, sortOrder])).toEqual([
      ['note.2', 0],
      ['note.1', 1],
    ]);
  });
});
