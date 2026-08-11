import {
  attachmentIdSchema,
  fieldValueElementIdSchema,
  fieldValueMatchesDefinition,
  itemIdSchema,
  itemPayloadSchema,
  secretValueSchema,
  type ActiveFieldValue,
  type FieldDefinition,
  type FieldScalarValue,
  type GroupPayload,
  type ItemPayload,
  type RecordRevision,
} from '@kavrix/schemas';

import type { TuiSaveResult } from './contracts.js';
import { describeFieldEditor } from './field-registry.js';

export type TuiPane = 'groups' | 'items' | 'details';
export type TuiOverlay =
  | 'none'
  | 'help'
  | 'palette'
  | 'search'
  | 'editor'
  | 'confirm-copy'
  | 'confirm-reveal'
  | 'confirm-lock'
  | 'conflict';

export interface TuiKey {
  readonly name?:
    'up' | 'down' | 'left' | 'right' | 'tab' | 'return' | 'escape' | 'backspace';
  readonly text?: string;
  readonly ctrl?: boolean;
  readonly shift?: boolean;
}

interface PendingOperation {
  readonly requestId: number;
  readonly kind: 'groups' | 'items' | 'copy' | 'reveal' | 'save' | 'lock';
  readonly itemId?: ItemPayload['id'];
  readonly fieldId?: FieldDefinition['id'];
}

export interface TuiConflictState {
  readonly local: ItemPayload;
  readonly remote: ItemPayload;
}

interface FieldEditorState {
  readonly fieldId: FieldDefinition['id'];
  readonly input: string;
}

export interface TuiState {
  readonly screen: 'loading' | 'browser' | 'locked' | 'error';
  readonly width: number;
  readonly height: number;
  readonly ascii: boolean;
  readonly groups: readonly GroupPayload[];
  readonly items: readonly ItemPayload[];
  readonly selectedGroup: number;
  readonly selectedItem: number;
  readonly selectedField: number;
  readonly activePane: TuiPane;
  readonly query: string;
  readonly overlay: TuiOverlay;
  readonly revealedUntil: Readonly<Record<string, number>>;
  readonly draft: ItemPayload | null;
  readonly dirty: boolean;
  readonly editor: FieldEditorState | null;
  readonly conflict: TuiConflictState | null;
  readonly copyConfirmationFieldId: FieldDefinition['id'] | null;
  readonly revealConfirmationFieldId: FieldDefinition['id'] | null;
  readonly pending: PendingOperation | null;
  readonly nextRequestId: number;
  readonly nextElementId: number;
  readonly message: string | null;
}

export type TuiEffect =
  | Readonly<{ kind: 'abort-active' }>
  | Readonly<{ kind: 'load-groups'; requestId: number }>
  | Readonly<{
      kind: 'load-items';
      requestId: number;
      groupId: GroupPayload['id'];
    }>
  | Readonly<{
      kind: 'copy-field';
      requestId: number;
      itemId: ItemPayload['id'];
      fieldId: FieldDefinition['id'];
    }>
  | Readonly<{
      kind: 'authorize-reveal';
      requestId: number;
      itemId: ItemPayload['id'];
      fieldId: FieldDefinition['id'];
      expiresAt: number;
    }>
  | Readonly<{
      kind: 'save-item';
      requestId: number;
      item: ItemPayload;
      expectedRevision: RecordRevision;
    }>
  | Readonly<{ kind: 'lock'; requestId: number }>;

export interface TuiTransition {
  readonly state: TuiState;
  readonly effects: readonly TuiEffect[];
}

export type TuiAction =
  | Readonly<{ type: 'start' }>
  | Readonly<{
      type: 'groups-loaded';
      requestId: number;
      groups: readonly GroupPayload[];
    }>
  | Readonly<{
      type: 'items-loaded';
      requestId: number;
      groupId: GroupPayload['id'];
      items: readonly ItemPayload[];
    }>
  | Readonly<{ type: 'operation-failed'; requestId: number }>
  | Readonly<{ type: 'copy-finished'; requestId: number }>
  | Readonly<{
      type: 'reveal-authorized';
      requestId: number;
      itemId: ItemPayload['id'];
      fieldId: FieldDefinition['id'];
      expiresAt: number;
    }>
  | Readonly<{
      type: 'save-finished';
      requestId: number;
      result: TuiSaveResult;
    }>
  | Readonly<{ type: 'lock-finished'; requestId: number }>
  | Readonly<{ type: 'resize'; width: number; height: number }>
  | Readonly<{ type: 'tick'; nowMs: number }>
  | Readonly<{ type: 'key'; key: TuiKey; nowMs: number }>;

export function createInitialTuiState(
  width = 80,
  height = 24,
  ascii = false,
): TuiState {
  return {
    screen: 'loading',
    width: Math.max(1, width),
    height: Math.max(1, height),
    ascii,
    groups: [],
    items: [],
    selectedGroup: 0,
    selectedItem: 0,
    selectedField: 0,
    activePane: 'groups',
    query: '',
    overlay: 'none',
    revealedUntil: {},
    draft: null,
    dirty: false,
    editor: null,
    conflict: null,
    copyConfirmationFieldId: null,
    revealConfirmationFieldId: null,
    pending: null,
    nextRequestId: 1,
    nextElementId: 1,
    message: null,
  };
}

export function transitionTui(state: TuiState, action: TuiAction): TuiTransition {
  switch (action.type) {
    case 'start':
      return request(state, 'groups', (requestId) => ({
        kind: 'load-groups',
        requestId,
      }));
    case 'groups-loaded':
      return groupsLoaded(state, action);
    case 'items-loaded':
      return itemsLoaded(state, action);
    case 'operation-failed':
      if (state.pending?.requestId !== action.requestId) return unchanged(state);
      return unchanged({
        ...state,
        screen: state.groups.length === 0 ? 'error' : 'browser',
        pending: null,
        message: 'Operation failed safely. Retry or lock the vault.',
      });
    case 'copy-finished':
      if (state.pending?.requestId !== action.requestId) return unchanged(state);
      return unchanged({
        ...state,
        pending: null,
        message: 'Copied; clipboard expiry is active.',
      });
    case 'reveal-authorized':
      if (
        state.pending?.requestId !== action.requestId ||
        state.pending.kind !== 'reveal' ||
        state.pending.itemId !== action.itemId ||
        state.pending.fieldId !== action.fieldId ||
        state.items[state.selectedItem]?.id !== action.itemId ||
        state.draft?.id !== action.itemId
      )
        return unchanged(state);
      return unchanged({
        ...state,
        pending: null,
        revealedUntil: {
          ...state.revealedUntil,
          [revealGrantKey(action.itemId, action.fieldId)]: action.expiresAt,
        },
        message: 'Revealed temporarily; press lock to clear immediately.',
      });
    case 'save-finished':
      return saveFinished(state, action.requestId, action.result);
    case 'lock-finished':
      if (state.pending?.requestId !== action.requestId) return unchanged(state);
      return unchanged(clearForLock(state));
    case 'resize':
      return unchanged({
        ...state,
        width: Math.max(1, action.width),
        height: Math.max(1, action.height),
      });
    case 'tick':
      return unchanged(expireReveals(state, action.nowMs));
    case 'key':
      return keyboardTransition(state, action.key, action.nowMs);
  }
}

export function keyboardTransition(
  state: TuiState,
  key: TuiKey,
  nowMs: number,
): TuiTransition {
  if (key.ctrl === true && key.text?.toLowerCase() === 'c') return requestLock(state);
  if (
    (state.screen === 'loading' || state.screen === 'error') &&
    key.text?.toLowerCase() === 'l'
  )
    return requestLock(state);
  if (state.screen !== 'browser') return unchanged(state);
  if (state.overlay !== 'none') return overlayKey(state, key, nowMs);

  if (key.name === 'tab')
    return unchanged({ ...state, activePane: nextPane(state.activePane) });
  if (key.name === 'left')
    return unchanged({ ...state, activePane: previousPane(state.activePane) });
  if (key.name === 'right')
    return unchanged({ ...state, activePane: nextPane(state.activePane) });
  if (key.name === 'up' || key.text === 'k') return moveSelection(state, -1);
  if (key.name === 'down' || key.text === 'j') return moveSelection(state, 1);
  if (key.text === '?') return unchanged({ ...state, overlay: 'help' });
  if (key.ctrl === true && key.text?.toLowerCase() === 'p') {
    return unchanged({ ...state, overlay: 'palette' });
  }
  if (key.text === '/') return unchanged({ ...state, overlay: 'search', query: '' });
  if (key.text?.toLowerCase() === 'a')
    return unchanged({ ...state, ascii: !state.ascii });
  if (key.text?.toLowerCase() === 'e') return openEditor(state);
  if (key.text?.toLowerCase() === 'r') return revealSelectedField(state, nowMs);
  if (key.text?.toLowerCase() === 'c') return copySelectedField(state);
  if (key.text?.toLowerCase() === 's') return saveDraft(state);
  if (key.text?.toLowerCase() === 'l') {
    if (state.dirty) return unchanged({ ...state, overlay: 'confirm-lock' });
    return requestLock(state);
  }
  return unchanged(state);
}

function groupsLoaded(
  state: TuiState,
  action: Extract<TuiAction, { type: 'groups-loaded' }>,
): TuiTransition {
  if (state.pending?.requestId !== action.requestId) return unchanged(state);
  const groups = action.groups.filter((group) => group.deletedAt === undefined);
  const base: TuiState = {
    ...state,
    screen: 'browser',
    groups,
    selectedGroup: 0,
    pending: null,
    message: groups.length === 0 ? 'No groups yet.' : null,
  };
  const group = groups[0];
  if (group === undefined) return unchanged(base);
  return request(base, 'items', (requestId) => ({
    kind: 'load-items',
    requestId,
    groupId: group.id,
  }));
}

function itemsLoaded(
  state: TuiState,
  action: Extract<TuiAction, { type: 'items-loaded' }>,
): TuiTransition {
  if (state.pending?.requestId !== action.requestId) return unchanged(state);
  if (selectedGroup(state)?.id !== action.groupId) return unchanged(state);
  const items = action.items.filter((item) => item.deletedAt === undefined);
  return unchanged({
    ...state,
    items,
    selectedItem: 0,
    selectedField: 0,
    draft: items[0] ?? null,
    dirty: false,
    pending: null,
    message: items.length === 0 ? 'This group has no credentials.' : null,
  });
}

function saveFinished(
  state: TuiState,
  requestId: number,
  result: TuiSaveResult,
): TuiTransition {
  if (state.pending?.requestId !== requestId) return unchanged(state);
  if (result.status === 'conflict') {
    return unchanged({
      ...state,
      pending: null,
      overlay: 'conflict',
      conflict: { local: result.local, remote: result.remote },
      message: 'A newer remote revision exists.',
    });
  }
  const items = state.items.map((item) =>
    item.id === result.item.id ? result.item : item,
  );
  return unchanged({
    ...state,
    items,
    draft: result.item,
    dirty: false,
    pending: null,
    conflict: null,
    overlay: 'none',
    message: 'Saved.',
  });
}

function moveSelection(state: TuiState, offset: number): TuiTransition {
  if (state.activePane === 'groups') {
    if (state.dirty)
      return unchanged({ ...state, message: 'Save or discard local changes first.' });
    const selectedGroupIndex = clamp(state.selectedGroup + offset, state.groups.length);
    if (selectedGroupIndex === state.selectedGroup) return unchanged(state);
    const group = state.groups[selectedGroupIndex];
    if (group === undefined) return unchanged(state);
    const base: TuiState = {
      ...state,
      selectedGroup: selectedGroupIndex,
      items: [],
      selectedItem: 0,
      selectedField: 0,
      draft: null,
      dirty: false,
      editor: null,
      conflict: null,
      revealedUntil: {},
      copyConfirmationFieldId: null,
      revealConfirmationFieldId: null,
      message: null,
    };
    return request(base, 'items', (requestId) => ({
      kind: 'load-items',
      requestId,
      groupId: group.id,
    }));
  }
  if (state.activePane === 'items') {
    if (state.dirty)
      return unchanged({ ...state, message: 'Save or discard local changes first.' });
    const visible = filteredItemIndexes(state);
    const currentVisible = Math.max(0, visible.indexOf(state.selectedItem));
    const nextVisible = clamp(currentVisible + offset, visible.length);
    const selectedItemIndex = visible[nextVisible] ?? state.selectedItem;
    return selectItem(state, selectedItemIndex);
  }
  return unchanged({
    ...state,
    selectedField: clamp(state.selectedField + offset, selectedFields(state).length),
  });
}

function overlayKey(state: TuiState, key: TuiKey, nowMs: number): TuiTransition {
  if (state.overlay === 'help' || state.overlay === 'palette') {
    if (key.name === 'escape' || key.text === '?' || key.name === 'return') {
      return unchanged({ ...state, overlay: 'none' });
    }
    if (state.overlay === 'palette') {
      if (key.text?.toLowerCase() === 'l') {
        return keyboardTransition({ ...state, overlay: 'none' }, { text: 'l' }, nowMs);
      }
      if (key.text === '/')
        return unchanged({ ...state, overlay: 'search', query: '' });
      if (key.text?.toLowerCase() === 'a')
        return unchanged({ ...state, overlay: 'none', ascii: !state.ascii });
    }
    return unchanged(state);
  }
  if (state.overlay === 'search') {
    if (key.name === 'escape')
      return unchanged({ ...state, overlay: 'none', query: '' });
    if (key.name === 'return')
      return selectItem({ ...state, overlay: 'none' }, firstFilteredItem(state));
    if (key.name === 'backspace')
      return unchanged({ ...state, query: removeLastGlyph(state.query) });
    if (isPrintable(key.text))
      return unchanged({ ...state, query: `${state.query}${key.text}`.slice(0, 256) });
    return unchanged(state);
  }
  if (state.overlay === 'editor') return editorKey(state, key);
  if (state.overlay === 'confirm-copy') {
    if (key.text?.toLowerCase() === 'y') return confirmedCopy(state);
    if (key.text?.toLowerCase() === 'n' || key.name === 'escape') {
      return unchanged({ ...state, overlay: 'none', copyConfirmationFieldId: null });
    }
    return unchanged(state);
  }
  if (state.overlay === 'confirm-reveal') {
    if (key.text?.toLowerCase() === 'y') return confirmedReveal(state, nowMs);
    if (key.text?.toLowerCase() === 'n' || key.name === 'escape') {
      return unchanged({
        ...state,
        overlay: 'none',
        revealConfirmationFieldId: null,
      });
    }
    return unchanged(state);
  }
  if (state.overlay === 'confirm-lock') {
    if (key.text?.toLowerCase() === 'y') {
      return requestLock({ ...state, overlay: 'none' });
    }
    if (key.text?.toLowerCase() === 'n' || key.name === 'escape')
      return unchanged({ ...state, overlay: 'none' });
    return unchanged(state);
  }
  if (state.overlay === 'conflict') return conflictKey(state, key);
  return unchanged(state);
}

function editorKey(state: TuiState, key: TuiKey): TuiTransition {
  const editor = state.editor;
  if (editor === null) return unchanged({ ...state, overlay: 'none' });
  if (key.name === 'escape')
    return unchanged({
      ...state,
      overlay: 'none',
      editor: null,
      message: 'Edit cancelled.',
    });
  if (key.name === 'backspace')
    return unchanged({
      ...state,
      editor: { ...editor, input: removeLastGlyph(editor.input) },
    });
  if (key.name === 'return' && key.shift !== true) return commitEditor(state);
  if (key.name === 'return' && key.shift === true) return appendEditorText(state, '\n');
  if (isPrintable(key.text)) return appendEditorText(state, key.text);
  return unchanged(state);
}

function conflictKey(state: TuiState, key: TuiKey): TuiTransition {
  const conflict = state.conflict;
  if (conflict === null) return unchanged({ ...state, overlay: 'none' });
  if (key.text?.toLowerCase() === 'r') {
    const items = state.items.map((item) =>
      item.id === conflict.remote.id ? conflict.remote : item,
    );
    return unchanged({
      ...state,
      items,
      draft: conflict.remote,
      dirty: false,
      overlay: 'none',
      conflict: null,
      revealedUntil: {},
      message: 'Remote revision accepted.',
    });
  }
  if (key.text?.toLowerCase() === 'l') {
    return request({ ...state, overlay: 'none' }, 'save', (requestId) => ({
      kind: 'save-item',
      requestId,
      item: conflict.local,
      expectedRevision: conflict.remote.revision,
    }));
  }
  return unchanged(state);
}

function openEditor(state: TuiState): TuiTransition {
  const field = selectedFields(state)[state.selectedField];
  const draft = state.draft;
  if (field === undefined || draft === null) return unchanged(state);
  const stored = [...draft.templateValues, ...draft.itemValues].find(
    (value) => value.fieldId === field.id,
  );
  return unchanged({
    ...state,
    overlay: 'editor',
    editor: { fieldId: field.id, input: editableValue(stored?.value) },
    message: null,
  });
}

function commitEditor(state: TuiState): TuiTransition {
  const editor = state.editor;
  const draft = state.draft;
  const group = selectedGroup(state);
  if (editor === null || draft === null || group === undefined) return unchanged(state);
  const field = [...group.template.fields, ...draft.itemFields].find(
    ({ id }) => id === editor.fieldId,
  );
  if (field === undefined)
    return unchanged({ ...state, overlay: 'none', editor: null });
  const updated = updateDraftValue(
    draft,
    group,
    field,
    editor.input,
    state.nextElementId,
  );
  if (updated === null) {
    return unchanged({ ...state, message: 'Value does not satisfy the field policy.' });
  }
  return unchanged({
    ...state,
    draft: updated,
    dirty: true,
    overlay: 'none',
    editor: null,
    nextElementId: state.nextElementId + 10_001,
    message: 'Local changes are not saved.',
  });
}

function updateDraftValue(
  item: ItemPayload,
  group: GroupPayload,
  field: FieldDefinition,
  input: string,
  idSeed: number,
): ItemPayload | null {
  const descriptor = describeFieldEditor(field);
  const multiple = field.repeatable || descriptor.supportsMultiple;
  const lines = multiple
    ? input.split('\n').filter((line) => line.length > 0)
    : [input];
  let value: ActiveFieldValue;
  if (input.length === 0 || lines.length === 0) {
    value = { version: 1, state: 'empty' };
  } else {
    const parsedScalars = lines.map((line) => scalarFromInput(field, line));
    const scalars = parsedScalars.filter(
      (candidate): candidate is FieldScalarValue => candidate !== null,
    );
    if (scalars.length !== parsedScalars.length) return null;
    if (multiple) {
      const prior = [...item.templateValues, ...item.itemValues].find(
        ({ fieldId }) => fieldId === field.id,
      );
      const priorIds =
        prior?.value.state === 'present' &&
        prior.value.content.cardinality === 'multiple'
          ? prior.value.content.elements.map(({ id }) => id)
          : [];
      value = {
        version: 1,
        state: 'present',
        content: {
          cardinality: 'multiple',
          elements: scalars.map((scalar, index) => ({
            id:
              priorIds[index] ??
              fieldValueElementIdSchema.parse(`tui.${String(idSeed + index)}`),
            value: scalar,
            lifecycle: { version: 1, status: 'available' },
          })),
        },
      };
    } else {
      const scalar = scalars[0];
      if (scalar === undefined) return null;
      value = {
        version: 1,
        state: 'present',
        content: { cardinality: 'single', value: scalar },
      };
    }
  }
  if (!fieldValueMatchesDefinition(field, value)) return null;
  const stored = {
    fieldId: field.id,
    stableKey: field.stableKey,
    value,
    updatedAt: item.updatedAt,
  };
  const isItemField = item.itemFields.some(({ id }) => id === field.id);
  const key = isItemField ? 'itemValues' : 'templateValues';
  const values = item[key];
  const nextValues = values.some(({ fieldId }) => fieldId === field.id)
    ? values.map((candidate) => (candidate.fieldId === field.id ? stored : candidate))
    : [...values, stored];
  const candidate = { ...item, [key]: nextValues };
  if (item.templateId !== group.template.id) return null;
  const parsed = itemPayloadSchema.safeParse(candidate);
  return parsed.success ? parsed.data : null;
}

function scalarFromInput(
  field: FieldDefinition,
  input: string,
): FieldScalarValue | null {
  const kind = describeFieldEditor(field).valueKind;
  try {
    switch (kind) {
      case 'text':
        return { kind: 'text', value: input };
      case 'secret':
        return { kind: 'secret', value: secretValueSchema.parse(input) };
      case 'number': {
        const value = Number(input);
        return Number.isFinite(value) ? { kind: 'number', value } : null;
      }
      case 'boolean':
        if (input.toLowerCase() === 'true' || input.toLowerCase() === 'yes')
          return { kind: 'boolean', value: true };
        if (input.toLowerCase() === 'false' || input.toLowerCase() === 'no')
          return { kind: 'boolean', value: false };
        return null;
      case 'item-reference':
        return { kind: 'item-reference', itemId: itemIdSchema.parse(input) };
      case 'attachment-reference':
        return {
          kind: 'attachment-reference',
          attachmentId: attachmentIdSchema.parse(input),
        };
      case 'environment-entry': {
        const separator = input.indexOf('=');
        if (separator < 1) return null;
        const key = input.slice(0, separator);
        const rawValue = input.slice(separator + 1);
        return {
          kind: 'environment-entry',
          key,
          value: field.sensitive
            ? { classification: 'secret', value: secretValueSchema.parse(rawValue) }
            : { classification: 'text', value: rawValue },
        };
      }
    }
  } catch {
    return null;
  }
}

function editableValue(value: ActiveFieldValue | undefined): string {
  if (value?.state !== 'present') return '';
  const values =
    value.content.cardinality === 'single'
      ? [value.content.value]
      : value.content.elements.map(({ value: scalar }) => scalar);
  return values
    .map((scalar) => {
      if (scalar.kind === 'text' || scalar.kind === 'secret') return scalar.value;
      if (scalar.kind === 'number' || scalar.kind === 'boolean')
        return String(scalar.value);
      if (scalar.kind === 'item-reference') return scalar.itemId;
      if (scalar.kind === 'attachment-reference') return scalar.attachmentId;
      return `${scalar.key}=${scalar.value.value}`;
    })
    .join('\n');
}

function appendEditorText(state: TuiState, text: string): TuiTransition {
  const editor = state.editor;
  if (
    editor === null ||
    Buffer.byteLength(editor.input) + Buffer.byteLength(text) > 1_048_576
  )
    return unchanged(state);
  return unchanged({
    ...state,
    editor: { ...editor, input: `${editor.input}${text}` },
  });
}

function revealSelectedField(state: TuiState, nowMs: number): TuiTransition {
  const field = selectedFields(state)[state.selectedField];
  const item = state.draft;
  if (
    field === undefined ||
    item === null ||
    !field.sensitive ||
    field.revealPolicy === 'never'
  )
    return unchanged(state);
  if (field.revealPolicy === 'confirm') {
    return unchanged({
      ...state,
      overlay: 'confirm-reveal',
      revealConfirmationFieldId: field.id,
    });
  }
  return request(
    state,
    'reveal',
    (requestId) => ({
      kind: 'authorize-reveal',
      requestId,
      itemId: item.id,
      fieldId: field.id,
      expiresAt: nowMs + 15_000,
    }),
    { itemId: item.id, fieldId: field.id },
  );
}

function confirmedReveal(state: TuiState, nowMs: number): TuiTransition {
  const item = state.draft;
  const fieldId = state.revealConfirmationFieldId;
  if (item === null || fieldId === null) {
    return unchanged({ ...state, overlay: 'none' });
  }
  return request(
    { ...state, overlay: 'none', revealConfirmationFieldId: null },
    'reveal',
    (requestId) => ({
      kind: 'authorize-reveal',
      requestId,
      itemId: item.id,
      fieldId,
      expiresAt: nowMs + 15_000,
    }),
    { itemId: item.id, fieldId },
  );
}

function copySelectedField(state: TuiState): TuiTransition {
  const field = selectedFields(state)[state.selectedField];
  const item = state.draft;
  if (
    field === undefined ||
    item === null ||
    !field.copyable ||
    field.copyPolicy === 'never'
  )
    return unchanged(state);
  if (field.copyPolicy === 'confirm') {
    return unchanged({
      ...state,
      overlay: 'confirm-copy',
      copyConfirmationFieldId: field.id,
    });
  }
  return request(state, 'copy', (requestId) => ({
    kind: 'copy-field',
    requestId,
    itemId: item.id,
    fieldId: field.id,
  }));
}

function confirmedCopy(state: TuiState): TuiTransition {
  const item = state.draft;
  const fieldId = state.copyConfirmationFieldId;
  if (item === null || fieldId === null)
    return unchanged({ ...state, overlay: 'none' });
  return request(
    { ...state, overlay: 'none', copyConfirmationFieldId: null },
    'copy',
    (requestId) => ({
      kind: 'copy-field',
      requestId,
      itemId: item.id,
      fieldId,
    }),
  );
}

function saveDraft(state: TuiState): TuiTransition {
  const draft = state.draft;
  const original = state.items[state.selectedItem];
  if (!state.dirty || draft === null || draft.id !== original?.id)
    return unchanged(state);
  return request(state, 'save', (requestId) => ({
    kind: 'save-item',
    requestId,
    item: draft,
    expectedRevision: original.revision,
  }));
}

function clearForLock(state: TuiState): TuiState {
  return {
    ...state,
    screen: 'locked',
    groups: [],
    items: [],
    selectedGroup: 0,
    selectedItem: 0,
    selectedField: 0,
    draft: null,
    dirty: false,
    editor: null,
    conflict: null,
    revealedUntil: {},
    query: '',
    overlay: 'none',
    revealConfirmationFieldId: null,
    copyConfirmationFieldId: null,
    pending: null,
    message: 'Vault locked.',
  };
}

function requestLock(state: TuiState): TuiTransition {
  return request(
    { ...clearForLock(state), screen: 'loading' },
    'lock',
    (requestId) => ({
      kind: 'lock',
      requestId,
    }),
  );
}

function expireReveals(state: TuiState, nowMs: number): TuiState {
  const entries = Object.entries(state.revealedUntil).filter(
    ([, expiresAt]) => expiresAt > nowMs,
  );
  if (entries.length === Object.keys(state.revealedUntil).length) return state;
  return { ...state, revealedUntil: Object.fromEntries(entries) };
}

export function selectedGroup(state: TuiState): GroupPayload | undefined {
  return state.groups[state.selectedGroup];
}

export function selectedItem(state: TuiState): ItemPayload | undefined {
  const item = state.items[state.selectedItem];
  return state.draft !== null && state.draft.id === item?.id ? state.draft : item;
}

export function revealGrantKey(
  itemId: ItemPayload['id'],
  fieldId: FieldDefinition['id'],
): string {
  return JSON.stringify([itemId, fieldId]);
}

export function selectedFields(state: TuiState): readonly FieldDefinition[] {
  const group = selectedGroup(state);
  const item = selectedItem(state);
  if (group === undefined || item === undefined) return [];
  return [...group.template.fields, ...item.itemFields].sort(
    (left, right) => left.sortOrder - right.sortOrder,
  );
}

export function filteredItemIndexes(state: TuiState): readonly number[] {
  const query = state.query.trim().toLocaleLowerCase();
  return state.items.flatMap((item, index) => {
    if (query.length === 0) return [index];
    const candidates = [
      item.title,
      item.subtitle,
      item.environment,
      item.owner,
      ...item.tags,
      ...item.aliases,
    ];
    return candidates.some(
      (candidate) => candidate?.toLocaleLowerCase().includes(query) === true,
    )
      ? [index]
      : [];
  });
}

function firstFilteredItem(state: TuiState): number {
  return filteredItemIndexes(state)[0] ?? state.selectedItem;
}

function selectItem(state: TuiState, selectedItemIndex: number): TuiTransition {
  const nextItem = state.items[selectedItemIndex];
  if (nextItem === undefined || selectedItemIndex === state.selectedItem) {
    return unchanged(state);
  }
  if (state.dirty) {
    return unchanged({
      ...state,
      message: 'Save or discard local changes first.',
    });
  }
  const abortReveal = state.pending?.kind === 'reveal';
  return {
    state: {
      ...state,
      selectedItem: selectedItemIndex,
      selectedField: 0,
      draft: nextItem,
      dirty: false,
      editor: null,
      conflict: null,
      copyConfirmationFieldId: null,
      revealConfirmationFieldId: null,
      pending: abortReveal ? null : state.pending,
      revealedUntil: {},
      message: null,
    },
    effects: abortReveal ? [{ kind: 'abort-active' }] : [],
  };
}

function request(
  state: TuiState,
  kind: PendingOperation['kind'],
  createEffect: (requestId: number) => TuiEffect,
  target?: Readonly<{
    itemId: ItemPayload['id'];
    fieldId: FieldDefinition['id'];
  }>,
): TuiTransition {
  const requestId = state.nextRequestId;
  return {
    state: {
      ...state,
      pending:
        target === undefined ? { requestId, kind } : { requestId, kind, ...target },
      nextRequestId: requestId + 1,
      message: null,
    },
    effects: [createEffect(requestId)],
  };
}

function nextPane(pane: TuiPane): TuiPane {
  if (pane === 'groups') return 'items';
  if (pane === 'items') return 'details';
  return 'groups';
}

function previousPane(pane: TuiPane): TuiPane {
  if (pane === 'details') return 'items';
  if (pane === 'items') return 'groups';
  return 'details';
}

function clamp(index: number, length: number): number {
  return Math.max(0, Math.min(index, Math.max(0, length - 1)));
}

function removeLastGlyph(value: string): string {
  return Array.from(value).slice(0, -1).join('');
}

function isPrintable(value: string | undefined): value is string {
  return value !== undefined && value.length > 0 && !/\p{C}/u.test(value);
}

function unchanged(state: TuiState): TuiTransition {
  return { state, effects: [] };
}
