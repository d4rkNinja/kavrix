import {
  attachmentIdSchema,
  fieldDefinitionSchema,
  itemIdSchema,
  itemPayloadSchema,
  secretValueSchema,
  type ActiveFieldValue,
  type FieldDefinition,
  type FieldScalarValue,
  type ItemPayload,
} from '@kavrix/schemas';
import { describe, expect, it } from 'vitest';

import { describeFieldEditor, scalarDisplayValue } from '../src/field-registry.js';
import { buildTuiScreenModel, renderTuiScreenText } from '../src/screen-model.js';
import {
  createInitialTuiState,
  keyboardTransition,
  selectedFields,
  transitionTui,
  type TuiState,
} from '../src/state.js';
import { sanitizeTerminalText } from '../src/terminal-text.js';
import { browserState, group, item, passwordField, tenantField } from './fixtures.js';

const timestamp = '2026-08-10T00:00:00.000Z';

function hydrate(): TuiState {
  let result = transitionTui(createInitialTuiState(), { type: 'start' });
  result = transitionTui(result.state, {
    type: 'groups-loaded',
    requestId: 1,
    groups: browserState().groups,
  });
  return transitionTui(result.state, {
    type: 'items-loaded',
    requestId: 2,
    groupId: group.id,
    items: browserState().items,
  }).state;
}

function details(state = hydrate()): TuiState {
  return { ...state, activePane: 'details' };
}

function definition(
  id: string,
  stableKey: string,
  type: FieldDefinition['type'],
  sortOrder: number,
  sensitive = false,
  repeatable = false,
): FieldDefinition {
  return fieldDefinitionSchema.parse({
    id,
    stableKey,
    label: stableKey,
    type,
    required: true,
    sensitive,
    repeatable,
    copyable: true,
    searchableLocally: !sensitive,
    showInPreview: !sensitive,
    copyPolicy: 'allowed',
    revealPolicy: sensitive ? 'timed' : 'never',
    reauthenticationPolicy: sensitive ? 'after-lock' : 'never',
    exportPolicy: sensitive ? 'guarded' : 'encrypted-only',
    sortOrder,
    createdAt: timestamp,
    updatedAt: timestamp,
  });
}

function present(value: FieldScalarValue): ActiveFieldValue {
  return {
    version: 1,
    state: 'present',
    content: { cardinality: 'single', value },
  };
}

const numberField = definition('field.number', 'count', 'number', 4);
const booleanField = definition('field.boolean', 'enabled', 'boolean', 5);
const itemReferenceField = definition(
  'field.reference',
  'related',
  'item-reference',
  6,
);
const attachmentField = definition(
  'field.attachment',
  'certificate_file',
  'attachment',
  7,
);
const environmentField = definition(
  'field.environment',
  'environment_values',
  'environment-map',
  8,
  true,
);

function dynamicItem(): ItemPayload {
  return itemPayloadSchema.parse({
    ...item,
    itemFields: [
      tenantField,
      numberField,
      booleanField,
      itemReferenceField,
      attachmentField,
      environmentField,
    ],
    itemValues: [
      ...item.itemValues,
      {
        fieldId: numberField.id,
        stableKey: numberField.stableKey,
        value: present({ kind: 'number', value: 2 }),
        updatedAt: timestamp,
      },
      {
        fieldId: booleanField.id,
        stableKey: booleanField.stableKey,
        value: present({ kind: 'boolean', value: true }),
        updatedAt: timestamp,
      },
      {
        fieldId: itemReferenceField.id,
        stableKey: itemReferenceField.stableKey,
        value: present({
          kind: 'item-reference',
          itemId: itemIdSchema.parse('item.related'),
        }),
        updatedAt: timestamp,
      },
      {
        fieldId: attachmentField.id,
        stableKey: attachmentField.stableKey,
        value: present({
          kind: 'attachment-reference',
          attachmentId: attachmentIdSchema.parse('attachment.certificate'),
        }),
        updatedAt: timestamp,
      },
      {
        fieldId: environmentField.id,
        stableKey: environmentField.stableKey,
        value: {
          version: 1,
          state: 'present',
          content: {
            cardinality: 'multiple',
            elements: [
              {
                id: 'environment.entry',
                value: {
                  kind: 'environment-entry',
                  key: 'TOKEN',
                  value: {
                    classification: 'secret',
                    value: secretValueSchema.parse('old'),
                  },
                },
                lifecycle: { version: 1, status: 'available' },
              },
            ],
          },
        },
        updatedAt: timestamp,
      },
    ],
    relatedItemIds: ['item.related'],
    attachmentIds: ['attachment.certificate'],
  });
}

function editField(state: TuiState, field: FieldDefinition, input: string): TuiState {
  let editing = keyboardTransition(
    {
      ...state,
      selectedField: selectedFields(state).findIndex(({ id }) => id === field.id),
    },
    { text: 'e' },
    0,
  ).state;
  if (editing.editor?.kind === 'repeatable') {
    while (
      editing.editor?.kind === 'repeatable' &&
      editing.editor.elements.length > 0
    ) {
      editing = keyboardTransition(editing, { ctrl: true, text: 'd' }, 0).state;
    }
    for (const value of input.split('\n')) {
      editing = keyboardTransition(editing, { ctrl: true, text: 'a' }, 0).state;
      for (const character of value) {
        editing = keyboardTransition(editing, { text: character }, 0).state;
      }
    }
  } else {
    editing = {
      ...editing,
      editor: { kind: 'single', fieldId: field.id, input },
    };
  }
  return keyboardTransition(editing, { name: 'return' }, 0).state;
}

describe('state edge behavior', () => {
  it('handles stale, empty, failed, completed, and locked operations deterministically', () => {
    const initial = createInitialTuiState();
    expect(keyboardTransition(initial, { text: 'l' }, 0).effects[0]?.kind).toBe('lock');

    let state = transitionTui(initial, { type: 'start' }).state;
    expect(
      transitionTui(state, { type: 'groups-loaded', requestId: 99, groups: [group] })
        .state,
    ).toBe(state);
    state = transitionTui(state, { type: 'operation-failed', requestId: 1 }).state;
    expect(state.screen).toBe('error');
    expect(state.message).not.toContain('PRIVATE');
    expect(keyboardTransition(state, { text: 'l' }, 0).effects[0]?.kind).toBe('lock');
    expect(
      keyboardTransition(state, { text: 'c', ctrl: true }, 0).effects[0]?.kind,
    ).toBe('lock');

    let empty = transitionTui(createInitialTuiState(), { type: 'start' }).state;
    empty = transitionTui(empty, {
      type: 'groups-loaded',
      requestId: 1,
      groups: [],
    }).state;
    expect(empty.screen).toBe('browser');
    expect(empty.message).toBe('No groups yet.');

    state = hydrate();
    const interrupted = keyboardTransition(state, { text: 'c', ctrl: true }, 0);
    expect(interrupted.effects[0]?.kind).toBe('lock');
    expect(interrupted.state.items).toEqual([]);
    expect(transitionTui(state, { type: 'copy-finished', requestId: 99 }).state).toBe(
      state,
    );
    const copying = keyboardTransition(
      { ...state, activePane: 'details' },
      { text: 'c' },
      0,
    );
    expect(
      transitionTui(copying.state, { type: 'operation-failed', requestId: 3 }).state
        .screen,
    ).toBe('browser');
    state = transitionTui(copying.state, {
      type: 'copy-finished',
      requestId: 3,
    }).state;
    expect(state.message).toContain('clipboard expiry');

    const locking = keyboardTransition(state, { text: 'l' }, 0);
    expect(
      transitionTui(locking.state, { type: 'lock-finished', requestId: 88 }).state,
    ).toBe(locking.state);
    const failedWithGroups = transitionTui(locking.state, {
      type: 'operation-failed',
      requestId: 4,
    }).state;
    expect(failedWithGroups.screen).toBe('error');
  });

  it('covers pane bounds, dirty navigation guards, and all dismissal keys', () => {
    let state = hydrate();
    expect(keyboardTransition(state, { name: 'up' }, 0).state.selectedGroup).toBe(0);
    state = keyboardTransition(state, { name: 'right' }, 0).state;
    expect(state.activePane).toBe('items');
    state = keyboardTransition(state, { text: 'j' }, 0).state;
    expect(state.selectedItem).toBe(1);
    state = keyboardTransition(state, { name: 'left' }, 0).state;
    expect(state.activePane).toBe('groups');

    const dirty = { ...state, dirty: true };
    expect(keyboardTransition(dirty, { name: 'down' }, 0).state.message).toContain(
      'Save',
    );
    expect(
      keyboardTransition({ ...dirty, activePane: 'items' }, { text: 'k' }, 0).state
        .message,
    ).toContain('Save');

    state = keyboardTransition(state, { text: '?' }, 0).state;
    expect(keyboardTransition(state, { name: 'return' }, 0).state.overlay).toBe('none');
    state = keyboardTransition(hydrate(), { ctrl: true, text: 'p' }, 0).state;
    expect(keyboardTransition(state, { text: '/' }, 0).state.overlay).toBe('search');
    expect(keyboardTransition(state, { text: 'z' }, 0).state).toBe(state);
    expect(keyboardTransition(state, { text: 'l' }, 0).effects[0]?.kind).toBe('lock');

    state = keyboardTransition(hydrate(), { text: '/' }, 0).state;
    state = keyboardTransition(state, { text: '\u{1F512}' }, 0).state;
    state = keyboardTransition(state, { name: 'backspace' }, 0).state;
    expect(state.query).toBe('');
    expect(keyboardTransition(state, { name: 'up' }, 0).state).toBe(state);
    expect(keyboardTransition(state, { name: 'escape' }, 0).state.query).toBe('');

    const confirmCopy = keyboardTransition(
      { ...details(), selectedField: 1 },
      { text: 'c' },
      0,
    ).state;
    expect(keyboardTransition(confirmCopy, { text: 'n' }, 0).state.overlay).toBe(
      'none',
    );
    expect(keyboardTransition(confirmCopy, { text: 'x' }, 0).state).toBe(confirmCopy);

    const confirmLock = { ...hydrate(), dirty: true, overlay: 'confirm-lock' as const };
    expect(keyboardTransition(confirmLock, { name: 'escape' }, 0).state.overlay).toBe(
      'none',
    );
    expect(keyboardTransition(confirmLock, { text: 'x' }, 0).state).toBe(confirmLock);

    const confirmRevealGroup = {
      ...group,
      template: {
        ...group.template,
        fields: group.template.fields.map((field) =>
          field.id === passwordField.id
            ? { ...field, revealPolicy: 'confirm' as const }
            : field,
        ),
      },
    };
    const revealState = {
      ...details(),
      groups: [confirmRevealGroup],
      selectedField: 1,
    };
    const confirmReveal = keyboardTransition(revealState, { text: 'r' }, 100).state;
    expect(confirmReveal.overlay).toBe('confirm-reveal');
    expect(keyboardTransition(confirmReveal, { text: 'n' }, 100).state.overlay).toBe(
      'none',
    );
    expect(
      keyboardTransition(confirmReveal, { text: 'y' }, 100).effects[0],
    ).toMatchObject({
      kind: 'authorize-reveal',
      expiresAt: 15_100,
    });
  });

  it('edits repeated and structured canonical values and rejects invalid values', () => {
    const dynamic = dynamicItem();
    let state: TuiState = {
      ...details(),
      items: [dynamic],
      draft: dynamic,
      selectedItem: 0,
    };

    state = editField(state, numberField, '42');
    state = editField(state, booleanField, 'no');
    state = editField(state, itemReferenceField, 'item.related');
    state = editField(state, attachmentField, 'attachment.certificate');
    state = editField(state, environmentField, 'TOKEN=new\nSECOND=two');
    expect(itemPayloadSchema.parse(state.draft).itemValues).toHaveLength(6);
    expect(state.nextElementId).toBeGreaterThan(2);

    const invalidNumber = editField(state, numberField, 'not-a-number');
    expect(invalidNumber.message).toContain('does not satisfy');
    const invalidBoolean = editField(state, booleanField, 'perhaps');
    expect(invalidBoolean.message).toContain('does not satisfy');
    const invalidReference = editField(state, itemReferenceField, 'bad id');
    expect(invalidReference.message).toContain('does not satisfy');
    const invalidEnvironment = editField(state, environmentField, 'missing-separator');
    expect(invalidEnvironment.message).toContain('does not satisfy');

    state = keyboardTransition(
      {
        ...state,
        overlay: 'editor',
        editor: { kind: 'single', fieldId: numberField.id, input: '4' },
      },
      { name: 'escape' },
      0,
    ).state;
    expect(state.editor).toBeNull();
    expect(state.message).toContain('cancelled');
  });

  it('supports local conflict retry and successful save reconciliation', () => {
    const local = itemPayloadSchema.parse({ ...item, title: 'Local title' });
    const remote = itemPayloadSchema.parse({
      ...item,
      title: 'Remote title',
      revision: 8,
    });
    let state: TuiState = {
      ...details(),
      overlay: 'conflict',
      conflict: { local, remote },
      dirty: true,
    };
    expect(keyboardTransition(state, { text: 'x' }, 0).state).toBe(state);
    const retry = keyboardTransition(state, { text: 'l' }, 0);
    expect(retry.effects[0]).toMatchObject({
      kind: 'save-item',
      expectedRevision: remote.revision,
    });
    state = transitionTui(retry.state, {
      type: 'save-finished',
      requestId: 3,
      result: { status: 'saved', item: local },
    }).state;
    expect(state.dirty).toBe(false);
    expect(state.message).toBe('Saved.');
  });
});

describe('formatting edge behavior', () => {
  it('formats every scalar kind and repeatable descriptor', () => {
    const repeatableText = definition(
      'field.repeatable',
      'aliases_extra',
      'text',
      9,
      false,
      true,
    );
    expect(describeFieldEditor(repeatableText).supportsMultiple).toBe(true);
    expect(scalarDisplayValue({ kind: 'number', value: 42 })).toBe('42');
    expect(scalarDisplayValue({ kind: 'boolean', value: true })).toBe('Yes');
    expect(scalarDisplayValue({ kind: 'boolean', value: false })).toBe('No');
    expect(
      scalarDisplayValue({
        kind: 'item-reference',
        itemId: itemIdSchema.parse('item.related'),
      }),
    ).toBe('item:item.related');
    expect(
      scalarDisplayValue({
        kind: 'attachment-reference',
        attachmentId: attachmentIdSchema.parse('attachment.certificate'),
      }),
    ).toBe('attachment:attachment.certificate');
    expect(
      scalarDisplayValue({
        kind: 'environment-entry',
        key: 'KEY',
        value: { classification: 'text', value: 'value' },
      }),
    ).toBe('KEY=value');
  });

  it('renders every overlay and terminal value-state marker without unsafe content', () => {
    const base = details();
    for (const overlay of [
      'help',
      'palette',
      'confirm-copy',
      'confirm-reveal',
      'confirm-lock',
    ] as const) {
      const output = renderTuiScreenText(buildTuiScreenModel({ ...base, overlay }, 0));
      expect(output.length).toBeGreaterThan(0);
    }

    const special = {
      ...item,
      templateValues: item.templateValues.map((stored, index) => ({
        ...stored,
        value:
          index === 0
            ? ({ version: 1, state: 'inapplicable', reason: 'test' } as const)
            : index === 1
              ? ({
                  version: 1,
                  state: 'unreadable',
                  reason: 'decryption-failed',
                } as const)
              : stored.value,
      })),
    };
    const state = { ...base, items: [special], draft: special };
    const output = renderTuiScreenText(buildTuiScreenModel(state, 0));
    expect(output).toContain('<not applicable>');
    expect(output).toContain('<unreadable>');

    expect(sanitizeTerminalText('\u001bPprivate\u001b\\after')).toBe('after');
    expect(sanitizeTerminalText('\u001b[31')).toBe('');
    expect(sanitizeTerminalText('\u009b2Jafter')).toBe('after');
    expect(sanitizeTerminalText('\u009dC1-OSC-PAYLOAD\u009cafter')).toBe('after');
    expect(sanitizeTerminalText('\u0090C1-DCS-PAYLOAD\u009cafter')).toBe('after');
    expect(sanitizeTerminalText('\u0098C1-SOS-PAYLOAD\u009cafter')).toBe('after');
    expect(sanitizeTerminalText('\u009eC1-PM-PAYLOAD\u009cafter')).toBe('after');
    expect(sanitizeTerminalText('\u009fC1-APC-PAYLOAD\u009cafter')).toBe('after');
    expect(sanitizeTerminalText('\u009dunterminated-C1-STRING')).toBe('');
    expect(sanitizeTerminalText('a\u2028b\u2029c')).toBe('a�b�c');
    expect(sanitizeTerminalText(`a${String.fromCharCode(0x85)}b`)).toBe('ab');
  });
});
