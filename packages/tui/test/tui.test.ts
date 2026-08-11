import {
  fieldDefinitionSchema,
  fieldTypeSchema,
  fieldValueElementIdSchema,
  groupPayloadSchema,
  itemPayloadSchema,
} from '@kavrix/schemas';
import { describe, expect, it } from 'vitest';

import { describeFieldEditor, fieldEditorRegistry } from '../src/field-registry.js';
import { buildTuiScreenModel, renderTuiScreenText } from '../src/screen-model.js';
import {
  createInitialTuiState,
  keyboardTransition,
  revealGrantKey,
  selectedItem,
  transitionTui,
  type TuiState,
} from '../src/state.js';
import { sanitizeTerminalText, truncateTerminalText } from '../src/terminal-text.js';
import {
  backupCodesField,
  browserState,
  group,
  item,
  passwordField,
  secondGroup,
  secondItem,
  tenantField,
  usernameField,
} from './fixtures.js';

function hydrate(width = 80, height = 24, ascii = false): TuiState {
  const fixtures = browserState(width, height, ascii);
  let transition = transitionTui(createInitialTuiState(width, height, ascii), {
    type: 'start',
  });
  transition = transitionTui(transition.state, {
    type: 'groups-loaded',
    requestId: 1,
    groups: fixtures.groups,
  });
  transition = transitionTui(transition.state, {
    type: 'items-loaded',
    requestId: 2,
    groupId: group.id,
    items: fixtures.items,
  });
  return transition.state;
}

function detailState(state: TuiState): TuiState {
  return keyboardTransition(
    keyboardTransition(state, { name: 'tab' }, 0).state,
    { name: 'tab' },
    0,
  ).state;
}

describe('professional screen model', () => {
  it('renders an exact three-pane 80x24 dashboard with dynamic fields and note counts', () => {
    const model = buildTuiScreenModel(detailState(hydrate()), 1_000);
    const output = renderTuiScreenText(model);

    expect(model.panes.map(({ id }) => id)).toEqual(['groups', 'items', 'details']);
    expect(output.split('\n')).toHaveLength(24);
    expect(output).toContain('CredVault');
    expect(output).toContain('Gmail Work');
    expect(output).toContain('4 fields | 4 item notes | 3 group no');
    expect(output).toContain('Workspace Tenant ID');
    expect(output).not.toContain('PASSWORD-CANARY');
    expect(output).not.toContain('ITEM-NOTE-CANARY');
    expect(output).not.toContain('GROUP-NOTE-CANARY');
  });

  it('switches to one focused pane below 80 columns and reacts to resize', () => {
    const narrow = hydrate(52, 24);
    expect(buildTuiScreenModel(narrow, 0).panes).toHaveLength(1);
    expect(buildTuiScreenModel(narrow, 0).context).toContain('NARROW GROUPS');

    const items = keyboardTransition(narrow, { name: 'tab' }, 0).state;
    expect(buildTuiScreenModel(items, 0).panes[0]?.id).toBe('items');

    const wide = transitionTui(narrow, {
      type: 'resize',
      width: 100,
      height: 30,
    }).state;
    expect(buildTuiScreenModel(wide, 0).panes).toHaveLength(3);
    expect(buildTuiScreenModel(wide, 0).height).toBe(30);
  });

  it('produces strictly ASCII output in fallback mode', () => {
    const output = renderTuiScreenText(
      buildTuiScreenModel(detailState(hydrate(80, 24, true)), 0),
    );
    expect(
      Array.from(output).every((glyph) => (glyph.codePointAt(0) ?? 128) <= 0x7f),
    ).toBe(true);
    expect(output).toContain('********');
    expect(output).not.toContain('\u2502');
  });

  it('sanitizes terminal escapes, controls, bidi overrides, and length', () => {
    const hostile =
      'safe\u001b]2;OSC-CANARY\u0007\u001b[31mred\u001b[0m\rnext\u202Espoof';
    const sanitized = sanitizeTerminalText(hostile);
    expect(sanitized).toBe('safered next\uFFFDspoof');
    expect(sanitized).not.toContain('\u001b');
    expect(sanitized).not.toContain('OSC-CANARY');
    expect(sanitizeTerminalText('\u{1F512}', true)).toBe('?');
    expect(truncateTerminalText('abcdef', 4)).toBe('abc\u2026');
    expect(truncateTerminalText('abcdef', 1)).toBe('\u2026');
    expect(truncateTerminalText('abcdef', 0)).toBe('');
  });
});

describe('dynamic field and keyboard behavior', () => {
  it('registers every canonical field type with schema-driven edit semantics', () => {
    expect(Object.keys(fieldEditorRegistry).toSorted()).toEqual(
      fieldTypeSchema.options.toSorted(),
    );
    expect(describeFieldEditor(backupCodesField)).toMatchObject({
      inputMode: 'masked-multiline',
      supportsMultiple: true,
      allowsNewlines: true,
    });
    expect(describeFieldEditor(tenantField).inputMode).toBe('single-line');
  });

  it('reveals only the selected secret and auto-hides it on the deterministic tick', () => {
    let state = detailState(hydrate());
    state = keyboardTransition(state, { name: 'down' }, 1_000).state;
    expect(state.selectedField).toBe(1);

    state = keyboardTransition(state, { text: 'r' }, 1_000).state;
    expect(state.pending?.kind).toBe('reveal');
    expect(renderTuiScreenText(buildTuiScreenModel(state, 1_001))).not.toContain(
      'PASSWORD-CANARY',
    );
    state = transitionTui(state, {
      type: 'reveal-authorized',
      requestId: 3,
      itemId: item.id,
      fieldId: passwordField.id,
      expiresAt: 16_000,
    }).state;
    expect(renderTuiScreenText(buildTuiScreenModel(state, 1_001))).toContain(
      'PASSWORD-CANARY',
    );
    expect(renderTuiScreenText(buildTuiScreenModel(state, 1_001))).not.toContain(
      'code-a',
    );

    state = transitionTui(state, { type: 'tick', nowMs: 16_001 }).state;
    expect(renderTuiScreenText(buildTuiScreenModel(state, 16_001))).not.toContain(
      'PASSWORD-CANARY',
    );
  });

  it('edits repeatable elements by stable ID without reviving used recovery codes', () => {
    const usedAt = '2026-08-11T00:00:00.000Z';
    const recoveryItem = itemPayloadSchema.parse({
      ...item,
      templateValues: item.templateValues.map((stored) =>
        stored.fieldId === backupCodesField.id &&
        stored.value.state === 'present' &&
        stored.value.content.cardinality === 'multiple'
          ? {
              ...stored,
              value: {
                ...stored.value,
                content: {
                  ...stored.value.content,
                  elements: stored.value.content.elements.map((element, index) =>
                    index === 1
                      ? {
                          ...element,
                          lifecycle: { version: 1, status: 'used', usedAt },
                        }
                      : element,
                  ),
                },
              },
            }
          : stored,
      ),
    });
    let state: TuiState = {
      ...detailState(hydrate()),
      items: [recoveryItem],
      draft: recoveryItem,
      selectedField: 2,
    };

    state = keyboardTransition(state, { text: 'e' }, 0).state;
    expect(state.editor).toMatchObject({
      kind: 'repeatable',
      selectedElementId: 'code.0',
      elements: [{ id: 'code.0' }, { id: 'code.1' }],
    });

    state = keyboardTransition(state, { ctrl: true, text: 'a' }, 0).state;
    const firstAddedId =
      state.editor?.kind === 'repeatable' ? state.editor.selectedElementId : undefined;
    expect(firstAddedId).toBe('tui.1');
    for (const character of 'code-a') {
      state = keyboardTransition(state, { text: character }, 0).state;
    }
    state = keyboardTransition(state, { name: 'up', shift: true }, 0).state;
    state = keyboardTransition(state, { ctrl: true, text: 'd' }, 0).state;
    state = keyboardTransition(state, { ctrl: true, text: 'a' }, 0).state;
    const replacementId =
      state.editor?.kind === 'repeatable' ? state.editor.selectedElementId : undefined;
    expect(replacementId).toBe('tui.2');
    expect(replacementId).not.toBe(firstAddedId);
    for (const character of 'code-a') {
      state = keyboardTransition(state, { text: character }, 0).state;
    }
    state = keyboardTransition(state, { name: 'up', shift: true }, 0).state;
    state = keyboardTransition(state, { name: 'down' }, 0).state;
    for (const character of '-edited') {
      state = keyboardTransition(state, { text: character }, 0).state;
    }
    state = keyboardTransition(state, { name: 'return' }, 0).state;

    const stored = state.draft?.templateValues.find(
      ({ fieldId }) => fieldId === backupCodesField.id,
    );
    expect(stored?.value).toMatchObject({
      state: 'present',
      content: {
        cardinality: 'multiple',
        elements: [
          {
            id: 'code.0',
            value: { value: 'code-a' },
            lifecycle: { status: 'available' },
          },
          {
            id: 'tui.2',
            value: { value: 'code-a' },
            lifecycle: { status: 'available' },
          },
          {
            id: 'code.1',
            value: { value: 'code-b-edited' },
            lifecycle: { status: 'used', usedAt },
          },
        ],
      },
    });
    expect(state.selectedElement).toBe(3);
    const saving = keyboardTransition(state, { text: 's' }, 1);
    const savedItem =
      saving.effects[0]?.kind === 'save-item' ? saving.effects[0].item : null;
    expect(savedItem).not.toBeNull();
    state = transitionTui(saving.state, {
      type: 'save-finished',
      requestId: 3,
      result: { status: 'saved', item: itemPayloadSchema.parse(savedItem) },
    }).state;
    const usedCopy = keyboardTransition(state, { text: 'c' }, 1);
    const usedReveal = keyboardTransition(state, { text: 'r' }, 1);
    expect(usedCopy.effects).toEqual([]);
    expect(usedReveal.effects).toEqual([]);
    expect(usedCopy.state.message).toContain('no longer available');
    expect(usedReveal.state.message).toContain('no longer available');
  });

  it('targets one repeatable element and requires saving dirty values before copy or reveal', () => {
    let state: TuiState = {
      ...detailState(hydrate()),
      selectedField: 2,
    };
    state = keyboardTransition(state, { text: ']' }, 1_000).state;
    expect(state.selectedElement).toBe(2);

    let transition = keyboardTransition(state, { text: 'c' }, 1_000);
    expect(transition.state.overlay).toBe('confirm-copy');
    transition = keyboardTransition(transition.state, { text: 'y' }, 1_000);
    expect(transition.effects[0]).toMatchObject({
      kind: 'copy-field',
      itemId: item.id,
      fieldId: backupCodesField.id,
      elementIndex: 2,
    });
    state = transitionTui(transition.state, {
      type: 'copy-finished',
      requestId: 3,
    }).state;

    transition = keyboardTransition(state, { text: 'r' }, 1_000);
    expect(transition.effects[0]).toMatchObject({
      kind: 'authorize-reveal',
      itemId: item.id,
      fieldId: backupCodesField.id,
      elementIndex: 2,
      elementId: fieldValueElementIdSchema.parse('code.1'),
    });
    state = transitionTui(transition.state, {
      type: 'reveal-authorized',
      requestId: 4,
      itemId: item.id,
      fieldId: backupCodesField.id,
      elementIndex: 2,
      elementId: fieldValueElementIdSchema.parse('code.1'),
      expiresAt: 16_000,
    }).state;
    const revealed = renderTuiScreenText(
      buildTuiScreenModel({ ...state, width: 160 }, 1_001),
    );
    expect(revealed).toContain('[2]: code-b');
    expect(revealed).not.toContain('code-a');

    state = keyboardTransition(state, { text: 'e' }, 2_000).state;
    state = keyboardTransition(state, { ctrl: true, text: 'a' }, 2_000).state;
    for (const character of 'draft-code') {
      state = keyboardTransition(state, { text: character }, 2_000).state;
    }
    state = keyboardTransition(state, { name: 'return' }, 2_000).state;
    expect(state.dirty).toBe(true);

    const dirtyCopy = keyboardTransition(state, { text: 'c' }, 2_001);
    const dirtyReveal = keyboardTransition(state, { text: 'r' }, 2_001);
    expect(dirtyCopy.effects).toEqual([]);
    expect(dirtyReveal.effects).toEqual([]);
    expect(dirtyCopy.state.message).toContain('Save');
    expect(dirtyReveal.state.message).toContain('Save');

    const saving = keyboardTransition(state, { text: 's' }, 2_002);
    const savedItem =
      saving.effects[0]?.kind === 'save-item' ? saving.effects[0].item : null;
    expect(savedItem).not.toBeNull();
    state = transitionTui(saving.state, {
      type: 'save-finished',
      requestId: 5,
      result: { status: 'saved', item: itemPayloadSchema.parse(savedItem) },
    }).state;
    state = { ...state, selectedElement: 3 };
    transition = keyboardTransition(state, { text: 'c' }, 2_003);
    transition = keyboardTransition(transition.state, { text: 'y' }, 2_003);
    expect(transition.effects[0]).toMatchObject({
      kind: 'copy-field',
      elementIndex: 3,
    });
    state = transitionTui(transition.state, {
      type: 'copy-finished',
      requestId: 6,
    }).state;
    transition = keyboardTransition(state, { text: 'r' }, 2_004);
    expect(transition.effects[0]).toMatchObject({
      kind: 'authorize-reveal',
      elementIndex: 3,
      elementId: fieldValueElementIdSchema.parse('tui.1'),
    });
    state = transitionTui(transition.state, {
      type: 'reveal-authorized',
      requestId: 7,
      itemId: item.id,
      fieldId: backupCodesField.id,
      elementIndex: 3,
      elementId: fieldValueElementIdSchema.parse('tui.1'),
      expiresAt: 17_004,
    }).state;
    const savedReveal = renderTuiScreenText(
      buildTuiScreenModel({ ...state, width: 160 }, 2_005),
    );
    expect(savedReveal).toContain('[3]: draft-code');
    expect(savedReveal).not.toContain('code-b');
  });

  it('binds confirm-policy repeatable reveal to the exact element identity', () => {
    const confirmField = fieldDefinitionSchema.parse({
      ...backupCodesField,
      revealPolicy: 'confirm',
    });
    const confirmGroup = groupPayloadSchema.parse({
      ...group,
      template: {
        ...group.template,
        fields: group.template.fields.map((field) =>
          field.id === confirmField.id ? confirmField : field,
        ),
      },
    });
    let state: TuiState = {
      ...detailState(hydrate()),
      groups: [confirmGroup],
      selectedField: 2,
      selectedElement: 2,
    };

    const confirming = keyboardTransition(state, { text: 'r' }, 1_000);
    expect(confirming.state).toMatchObject({
      overlay: 'confirm-reveal',
      revealConfirmationElementIndex: 2,
      revealConfirmationElementId: 'code.1',
    });

    const reorderedItem = itemPayloadSchema.parse({
      ...item,
      templateValues: item.templateValues.map((stored) =>
        stored.fieldId === backupCodesField.id &&
        stored.value.state === 'present' &&
        stored.value.content.cardinality === 'multiple'
          ? {
              ...stored,
              value: {
                ...stored.value,
                content: {
                  ...stored.value.content,
                  elements: [...stored.value.content.elements].reverse(),
                },
              },
            }
          : stored,
      ),
    });
    const staleConfirmation = keyboardTransition(
      { ...confirming.state, items: [reorderedItem], draft: reorderedItem },
      { text: 'y' },
      1_000,
    );
    expect(staleConfirmation.effects).toEqual([]);
    expect(staleConfirmation.state.message).toContain('changed');

    const transition = keyboardTransition(confirming.state, { text: 'y' }, 1_000);
    expect(transition.effects[0]).toMatchObject({
      kind: 'authorize-reveal',
      itemId: item.id,
      fieldId: backupCodesField.id,
      elementIndex: 2,
      elementId: fieldValueElementIdSchema.parse('code.1'),
    });
    state = transitionTui(transition.state, {
      type: 'reveal-authorized',
      requestId: 3,
      itemId: item.id,
      fieldId: backupCodesField.id,
      elementIndex: 2,
      elementId: fieldValueElementIdSchema.parse('code.1'),
      expiresAt: 16_000,
    }).state;
    const screen = renderTuiScreenText(
      buildTuiScreenModel({ ...state, width: 160 }, 1_001),
    );
    expect(screen).toContain('[2]: code-b');
    expect(screen).not.toContain('code-a');
  });

  it('binds reveal authorization to the pending item and invalidates it on item navigation', () => {
    const secondCanaryItem = itemPayloadSchema.parse({
      ...secondItem,
      templateValues: secondItem.templateValues.map((stored) =>
        stored.fieldId === passwordField.id
          ? {
              ...stored,
              value: {
                version: 1,
                state: 'present',
                content: {
                  cardinality: 'single',
                  value: {
                    kind: 'secret',
                    value: 'SECOND-PASSWORD-CANARY',
                  },
                },
              },
            }
          : stored,
      ),
    });
    let state = detailState({
      ...hydrate(),
      items: [item, secondCanaryItem],
      draft: item,
    });
    state = keyboardTransition(state, { name: 'down' }, 1_000).state;
    const revealingFirst = keyboardTransition(state, { text: 'r' }, 1_000);
    expect(revealingFirst.effects[0]).toMatchObject({
      kind: 'authorize-reveal',
      itemId: item.id,
      fieldId: passwordField.id,
    });

    const navigated = keyboardTransition(
      { ...revealingFirst.state, activePane: 'items' },
      { name: 'down' },
      1_001,
    );
    expect(navigated.effects).toEqual([{ kind: 'abort-active' }]);
    state = navigated.state;
    expect(state.pending).toBeNull();
    expect(state.draft?.id).toBe(secondCanaryItem.id);
    state = transitionTui(state, {
      type: 'reveal-authorized',
      requestId: 3,
      itemId: item.id,
      fieldId: passwordField.id,
      expiresAt: 16_000,
    }).state;
    expect(state.revealedUntil).toEqual({});
    expect(renderTuiScreenText(buildTuiScreenModel(state, 1_002))).not.toContain(
      'SECOND-PASSWORD-CANARY',
    );

    state = keyboardTransition(
      { ...state, activePane: 'details', selectedField: 1 },
      { text: 'r' },
      2_000,
    ).state;
    const staleReverse = transitionTui(state, {
      type: 'reveal-authorized',
      requestId: 4,
      itemId: item.id,
      fieldId: passwordField.id,
      expiresAt: 17_000,
    }).state;
    expect(staleReverse.pending).toEqual(state.pending);
    expect(renderTuiScreenText(buildTuiScreenModel(staleReverse, 2_001))).not.toContain(
      'SECOND-PASSWORD-CANARY',
    );

    state = transitionTui(state, {
      type: 'reveal-authorized',
      requestId: 4,
      itemId: secondCanaryItem.id,
      fieldId: passwordField.id,
      expiresAt: 17_000,
    }).state;
    expect(Object.keys(state.revealedUntil)).toEqual([
      revealGrantKey(secondCanaryItem.id, passwordField.id),
    ]);
    expect(renderTuiScreenText(buildTuiScreenModel(state, 2_001))).toContain(
      'SECOND-PASSWORD-CANARY',
    );
    state = transitionTui(state, { type: 'tick', nowMs: 17_001 }).state;
    expect(state.revealedUntil).toEqual({});
    const locking = keyboardTransition(
      {
        ...state,
        revealedUntil: {
          [revealGrantKey(secondCanaryItem.id, passwordField.id)]: 30_000,
        },
      },
      { text: 'l' },
      17_002,
    );
    expect(locking.state.revealedUntil).toEqual({});
  });

  it('emits a confirmed copy intent without putting a secret in the effect', () => {
    let state = detailState(hydrate());
    state = keyboardTransition(state, { name: 'down' }, 0).state;
    let result = keyboardTransition(state, { text: 'c' }, 0);
    expect(result.state.overlay).toBe('confirm-copy');
    expect(result.effects).toEqual([]);

    result = keyboardTransition(result.state, { text: 'y' }, 0);
    expect(result.effects).toEqual([
      {
        kind: 'copy-field',
        requestId: 3,
        itemId: item.id,
        fieldId: passwordField.id,
      },
    ]);
    expect(JSON.stringify(result.effects)).not.toContain('PASSWORD-CANARY');
  });

  it('edits a canonical dynamic field, tracks unsaved state, and saves by revision', () => {
    let state = detailState(hydrate());
    state = keyboardTransition(state, { text: 'e' }, 0).state;
    expect(state.overlay).toBe('editor');
    expect(state.editor?.fieldId).toBe(usernameField.id);

    let remainingCharacters = 'operator@example.test'.length;
    while (remainingCharacters > 0) {
      state = keyboardTransition(state, { name: 'backspace' }, 0).state;
      remainingCharacters -= 1;
    }
    for (const character of 'new@example.test') {
      state = keyboardTransition(state, { text: character }, 0).state;
    }
    state = keyboardTransition(state, { name: 'return' }, 0).state;
    expect(state.dirty).toBe(true);
    expect(itemPayloadSchema.parse(state.draft).templateValues[0]?.value).toMatchObject(
      {
        state: 'present',
        content: { value: { value: 'new@example.test' } },
      },
    );

    const saving = keyboardTransition(state, { text: 's' }, 0);
    expect(saving.effects[0]).toMatchObject({
      kind: 'save-item',
      expectedRevision: item.revision,
    });
  });

  it('supports search, palette, help, ASCII toggle, and stable pane navigation', () => {
    let state: TuiState = {
      ...hydrate(),
      selectedField: 2,
      revealedUntil: { stale: 99_999 },
      copyConfirmationFieldId: passwordField.id,
      revealConfirmationFieldId: passwordField.id,
    };
    state = keyboardTransition(state, { text: '/' }, 0).state;
    for (const character of 'outlook')
      state = keyboardTransition(state, { text: character }, 0).state;
    expect(buildTuiScreenModel(state, 0).panes[0]?.title).toBe('Search');
    state = keyboardTransition(state, { name: 'return' }, 0).state;
    expect(state.selectedItem).toBe(1);
    expect(state.draft?.id).toBe(secondItem.id);
    expect(selectedItem(state)?.id).toBe(secondItem.id);
    expect(state.selectedField).toBe(0);
    expect(state.revealedUntil).toEqual({});
    expect(state.copyConfirmationFieldId).toBeNull();
    expect(state.revealConfirmationFieldId).toBeNull();
    expect(buildTuiScreenModel(state, 0).panes[2]?.title).toBe(secondItem.title);

    const reveal = keyboardTransition(
      { ...state, activePane: 'details', selectedField: 1 },
      { text: 'r' },
      1_000,
    );
    expect(reveal.effects[0]).toMatchObject({
      kind: 'authorize-reveal',
      itemId: secondItem.id,
      fieldId: passwordField.id,
    });
    const confirmCopy = keyboardTransition(
      { ...state, activePane: 'details', selectedField: 1 },
      { text: 'c' },
      1_000,
    );
    const copy = keyboardTransition(confirmCopy.state, { text: 'y' }, 1_000);
    expect(copy.effects[0]).toMatchObject({
      kind: 'copy-field',
      itemId: secondItem.id,
      fieldId: passwordField.id,
    });

    state = keyboardTransition(state, { ctrl: true, text: 'p' }, 0).state;
    expect(state.overlay).toBe('palette');
    state = keyboardTransition(state, { text: 'a' }, 0).state;
    expect(state.ascii).toBe(true);
    expect(state.overlay).toBe('none');
    state = keyboardTransition(state, { text: '?' }, 0).state;
    expect(state.overlay).toBe('help');
    state = keyboardTransition(state, { name: 'escape' }, 0).state;
    expect(state.overlay).toBe('none');
  });

  it('keeps search selection atomic and refuses to cross a dirty draft identity', () => {
    let state = detailState(hydrate());
    state = keyboardTransition(state, { text: 'e' }, 0).state;
    state = keyboardTransition(state, { text: 'x' }, 0).state;
    state = keyboardTransition(state, { name: 'return' }, 0).state;
    expect(state.dirty).toBe(true);
    expect(state.draft?.id).toBe(item.id);

    state = keyboardTransition(state, { text: '/' }, 0).state;
    for (const character of 'outlook') {
      state = keyboardTransition(state, { text: character }, 0).state;
    }
    state = keyboardTransition(state, { name: 'return' }, 0).state;
    expect(state.selectedItem).toBe(0);
    expect(state.draft?.id).toBe(item.id);
    expect(selectedItem(state)?.id).toBe(item.id);
    expect(state.message).toContain('Save');

    const saving = keyboardTransition(state, { text: 's' }, 0);
    expect(saving.effects[0]).toMatchObject({
      kind: 'save-item',
      item: { id: item.id },
      expectedRevision: item.revision,
    });
  });

  it('keeps a conflict explicit until local or remote is chosen', () => {
    let state = detailState(hydrate());
    state = keyboardTransition(state, { text: 'e' }, 0).state;
    state = keyboardTransition(state, { text: 'x' }, 0).state;
    state = keyboardTransition(state, { name: 'return' }, 0).state;
    const saving = keyboardTransition(state, { text: 's' }, 0);
    const local = saving.state.draft;
    if (local === null) throw new Error('Expected a canonical local draft');
    const remote = itemPayloadSchema.parse({
      ...item,
      revision: 8,
      title: 'Remote title',
    });
    state = transitionTui(saving.state, {
      type: 'save-finished',
      requestId: 3,
      result: { status: 'conflict', local, remote },
    }).state;
    expect(state.overlay).toBe('conflict');
    expect(renderTuiScreenText(buildTuiScreenModel(state, 0))).toContain(
      'newer remote revision',
    );

    state = keyboardTransition(state, { text: 'r' }, 0).state;
    expect(state.dirty).toBe(false);
    expect(state.draft?.title).toBe('Remote title');
  });

  it('requires confirmation before locking with a draft and clears all decrypted state', () => {
    let state = detailState(hydrate());
    state = keyboardTransition(state, { text: 'e' }, 0).state;
    state = keyboardTransition(state, { text: 'x' }, 0).state;
    state = keyboardTransition(state, { name: 'return' }, 0).state;
    state = keyboardTransition(state, { text: 'l' }, 0).state;
    expect(state.overlay).toBe('confirm-lock');

    const locking = keyboardTransition(state, { text: 'y' }, 0);
    expect(locking.effects).toEqual([{ kind: 'lock', requestId: 3 }]);
    expect(locking.state.screen).toBe('loading');
    const locked = transitionTui(locking.state, {
      type: 'lock-finished',
      requestId: 3,
    }).state;
    expect(locked.screen).toBe('locked');
    expect(locked.groups).toEqual([]);
    expect(locked.items).toEqual([]);
    expect(locked.draft).toBeNull();
    expect(locked.revealedUntil).toEqual({});
  });

  it('ignores stale item loads after an interrupting group selection', () => {
    let state = hydrate();
    const moved = keyboardTransition(state, { name: 'down' }, 0);
    expect(moved.effects).toEqual([
      { kind: 'load-items', requestId: 3, groupId: secondGroup.id },
    ]);
    state = moved.state;

    const stale = transitionTui(state, {
      type: 'items-loaded',
      requestId: 2,
      groupId: group.id,
      items: [item],
    }).state;
    expect(stale).toBe(state);

    const current = transitionTui(state, {
      type: 'items-loaded',
      requestId: 3,
      groupId: secondGroup.id,
      items: [{ ...secondItem, groupId: secondGroup.id }],
    }).state;
    expect(current.items).toHaveLength(1);
  });
});
