import type {
  FieldDefinition,
  FieldScalarValue,
  Note,
  StoredFieldValue,
} from '@kavrix/schemas';

import { describeFieldEditor, scalarDisplayValue } from './field-registry.js';
import {
  filteredItemIndexes,
  revealGrantKey,
  selectedFields,
  selectedGroup,
  selectedItem,
  type TuiPane,
  type TuiState,
} from './state.js';
import {
  sanitizeTerminalText,
  secretMask,
  truncateTerminalText,
} from './terminal-text.js';

export interface TuiPaneModel {
  readonly id: TuiPane | 'overlay';
  readonly title: string;
  readonly active: boolean;
  readonly width: number;
  readonly lines: readonly string[];
}

export interface TuiScreenModel {
  readonly width: number;
  readonly height: number;
  readonly ascii: boolean;
  readonly header: string;
  readonly context: string;
  readonly panes: readonly TuiPaneModel[];
  readonly footer: string;
}

export function buildTuiScreenModel(state: TuiState, nowMs: number): TuiScreenModel {
  const ascii = state.ascii;
  const separator = ascii ? ' | ' : ' \u00b7 ';
  const group = selectedGroup(state);
  const item = selectedItem(state);
  const visibleItems = filteredItemIndexes(state);
  const stateLabel = state.screen.toUpperCase();
  const header = [
    'CredVault',
    stateLabel,
    `${String(state.groups.length)} groups`,
    `${String(state.items.length)} items`,
  ].join(separator);
  const context =
    state.width >= 80
      ? 'Vault browser'
      : `NARROW ${state.activePane.toUpperCase()} ${ascii ? '>' : '\u203a'} Tab changes pane`;

  const paneHeight = Math.max(1, state.height - 5);
  let panes: readonly TuiPaneModel[];
  if (state.overlay !== 'none') {
    panes = [overlayPane(state, nowMs, paneHeight)];
  } else if (state.width >= 80) {
    const groupWidth = Math.max(18, Math.floor(state.width * 0.23));
    const itemWidth = Math.max(22, Math.floor(state.width * 0.29));
    const detailWidth = Math.max(24, state.width - groupWidth - itemWidth - 2);
    panes = [
      makePane(
        'groups',
        'Groups',
        state.activePane === 'groups',
        groupWidth,
        paneHeight,
        groupLines(state),
      ),
      makePane(
        'items',
        'Credentials',
        state.activePane === 'items',
        itemWidth,
        paneHeight,
        itemLines(state, visibleItems),
      ),
      makePane(
        'details',
        item === undefined ? 'Details' : safe(item.title, ascii),
        state.activePane === 'details',
        detailWidth,
        paneHeight,
        detailLines(state, nowMs),
      ),
    ];
  } else {
    const lines =
      state.activePane === 'groups'
        ? groupLines(state)
        : state.activePane === 'items'
          ? itemLines(state, visibleItems)
          : detailLines(state, nowMs);
    const title =
      state.activePane === 'groups'
        ? 'Groups'
        : state.activePane === 'items'
          ? group === undefined
            ? 'Credentials'
            : safe(group.name, ascii)
          : item === undefined
            ? 'Details'
            : safe(item.title, ascii);
    panes = [makePane(state.activePane, title, true, state.width, paneHeight, lines)];
  }

  const status = state.dirty
    ? 'UNSAVED'
    : state.pending === null
      ? 'READY'
      : state.pending.kind.toUpperCase();
  const message =
    state.message === null ? '' : `${separator}${safe(state.message, ascii)}`;
  const footer = `${status}${message}${separator}? help${separator}Ctrl+P commands${separator}l lock`;
  return {
    width: state.width,
    height: state.height,
    ascii,
    header: truncateTerminalText(header, state.width),
    context: truncateTerminalText(context, state.width),
    panes,
    footer: truncateTerminalText(footer, state.width),
  };
}

export function renderTuiScreenText(model: TuiScreenModel): string {
  const border = model.ascii ? '-' : '\u2500';
  const vertical = model.ascii ? '|' : '\u2502';
  const lines = [model.header, model.context, border.repeat(model.width)];
  const contentHeight = Math.max(1, model.height - 5);
  for (let row = 0; row < contentHeight; row += 1) {
    const cells = model.panes.map((pane) => {
      const prefix =
        row === 0
          ? `${pane.active ? '>' : ' '} ${pane.title}`
          : (pane.lines[row - 1] ?? '');
      return padCell(truncateTerminalText(prefix, pane.width), pane.width);
    });
    lines.push(cells.join(vertical));
  }
  lines.push(border.repeat(model.width));
  lines.push(model.footer);
  return lines
    .slice(0, model.height)
    .map((line) => (model.ascii ? sanitizeTerminalText(line, true) : line))
    .join('\n');
}

function makePane(
  id: TuiPane,
  title: string,
  active: boolean,
  width: number,
  height: number,
  lines: readonly string[],
): TuiPaneModel {
  return {
    id,
    title: truncateTerminalText(title, Math.max(1, width - 2)),
    active,
    width,
    lines: lines
      .slice(0, Math.max(0, height - 1))
      .map((line) => truncateTerminalText(line, width)),
  };
}

function groupLines(state: TuiState): readonly string[] {
  if (state.groups.length === 0) return ['No groups'];
  return state.groups.map((group, index) => {
    const marker = index === state.selectedGroup ? '>' : ' ';
    return `${marker} ${safe(group.name, state.ascii)} (${String(group.notes.length)} notes)`;
  });
}

function itemLines(
  state: TuiState,
  visibleIndexes: readonly number[],
): readonly string[] {
  if (state.pending?.kind === 'items') return ['Loading selected group...'];
  if (visibleIndexes.length === 0)
    return [state.query.length === 0 ? 'No credentials' : 'No search matches'];
  return visibleIndexes.map((index) => {
    const item = state.items[index];
    if (item === undefined) return '';
    const marker = index === state.selectedItem ? '>' : ' ';
    const favorite = item.favorite ? (state.ascii ? '*' : '\u2605') : ' ';
    const subtitle =
      item.subtitle === undefined ? '' : ` - ${safe(item.subtitle, state.ascii)}`;
    return `${marker}${favorite} ${safe(item.title, state.ascii)}${subtitle}`;
  });
}

function detailLines(state: TuiState, nowMs: number): readonly string[] {
  const item = selectedItem(state);
  const group = selectedGroup(state);
  if (item === undefined || group === undefined) return ['Select a credential'];
  const values = new Map(
    [...item.templateValues, ...item.itemValues].map((stored) => [
      stored.fieldId,
      stored,
    ]),
  );
  const fields = selectedFields(state);
  const lines: string[] = [
    `${item.favorite ? (state.ascii ? '*' : '\u2605') : '-'} ${safe(item.title, state.ascii)}`,
    `${String(fields.length)} fields | ${String(item.notes.length)} item notes | ${String(group.notes.length)} group notes`,
  ];
  for (const [index, field] of fields.entries()) {
    const marker = index === state.selectedField ? '>' : ' ';
    const required = field.required ? '*' : '';
    const rendered = renderFieldValue(field, values.get(field.id), state, nowMs);
    lines.push(`${marker} ${safe(field.label, state.ascii)}${required}: ${rendered}`);
  }
  if (item.notes.length > 0) {
    lines.push('');
    lines.push(state.ascii ? '[ITEM NOTES]' : '\u2500 Item notes');
    lines.push(...item.notes.map((note) => renderNote(note, state.ascii)));
  }
  if (group.notes.length > 0) {
    lines.push('');
    lines.push(state.ascii ? '[GROUP NOTES]' : '\u2500 Group notes');
    lines.push(...group.notes.map((note) => renderNote(note, state.ascii)));
  }
  return lines;
}

function overlayPane(state: TuiState, nowMs: number, height: number): TuiPaneModel {
  const width = state.width;
  switch (state.overlay) {
    case 'help':
      return makeOverlay('Help', width, height, [
        'Tab / arrows  change pane',
        'j / k         move selection',
        '/             search locally',
        'e             edit selected field',
        'r             reveal for 15 seconds',
        'c             copy without printing',
        's             save local changes',
        'a             toggle ASCII mode',
        'l             lock and clear screen state',
        'Ctrl+C        secure lock and exit',
        'Esc / ?       close help',
      ]);
    case 'palette':
      return makeOverlay('Command palette', width, height, [
        '/  Search credentials',
        'a  Toggle ASCII mode',
        'l  Lock vault',
        'Esc  Close',
      ]);
    case 'search':
      return makeOverlay('Search', width, height, [
        `Query: ${safe(state.query, state.ascii)}`,
        `${String(filteredItemIndexes(state).length)} matching credentials`,
        'Enter apply | Esc clear',
      ]);
    case 'editor': {
      const field = selectedFields(state).find(
        ({ id }) => id === state.editor?.fieldId,
      );
      const descriptor = field === undefined ? null : describeFieldEditor(field);
      const input =
        field?.sensitive === true
          ? secretMask(state.ascii)
          : safe(state.editor?.input ?? '', state.ascii);
      return makeOverlay('Dynamic field editor', width, height, [
        `Field: ${field === undefined ? 'Unavailable' : safe(field.label, state.ascii)}`,
        `Type: ${field?.type ?? '-'} | Input: ${descriptor?.inputMode ?? '-'}`,
        `Value: ${input}`,
        descriptor?.supportsMultiple === true ? 'One value per line' : 'Single value',
        'Enter apply | Shift+Enter newline | Esc cancel',
      ]);
    }
    case 'confirm-copy':
      return makeOverlay('Confirm copy', width, height, [
        'Copy this protected field? y / n',
        'The value will not be rendered.',
      ]);
    case 'confirm-reveal':
      return makeOverlay('Confirm reveal', width, height, [
        'Reveal this protected field temporarily? y / n',
        'Reauthentication policy is enforced before display.',
      ]);
    case 'confirm-lock':
      return makeOverlay('Unsaved changes', width, height, [
        'Locking discards the local draft. Continue? y / n',
      ]);
    case 'conflict':
      return makeOverlay('Sync conflict', width, height, [
        'A newer remote revision was received.',
        'r  Accept remote revision',
        'l  Retry the local draft against the remote revision',
        'Lock remains available after resolving.',
      ]);
    case 'none':
      return makeOverlay('Details', width, height, detailLines(state, nowMs));
  }
}

function makeOverlay(
  title: string,
  width: number,
  height: number,
  lines: readonly string[],
): TuiPaneModel {
  return {
    id: 'overlay',
    title,
    active: true,
    width,
    lines: lines.slice(0, Math.max(0, height - 1)),
  };
}

function renderFieldValue(
  field: FieldDefinition,
  stored: StoredFieldValue | undefined,
  state: TuiState,
  nowMs: number,
): string {
  const value = stored?.value;
  const itemId = selectedItem(state)?.id;
  if (value === undefined || value.state === 'missing') return '<missing>';
  if (value.state === 'empty') return '<empty>';
  if (value.state === 'inapplicable') return '<not applicable>';
  if (value.state === 'unreadable') return '<unreadable>';
  if (
    field.sensitive &&
    (itemId === undefined ||
      (state.revealedUntil[revealGrantKey(itemId, field.id)] ?? 0) <= nowMs)
  )
    return secretMask(state.ascii);
  const parts =
    value.content.cardinality === 'single'
      ? [renderScalar(value.content.value, state.ascii)]
      : value.content.elements.map((element) => {
          const rendered = renderScalar(element.value, state.ascii);
          return element.lifecycle.status === 'used' ? `${rendered} (used)` : rendered;
        });
  return parts.join(state.ascii ? ' | ' : ' \u00b7 ');
}

function renderScalar(value: FieldScalarValue, ascii: boolean): string {
  return safe(scalarDisplayValue(value), ascii);
}

function renderNote(note: Note, ascii: boolean): string {
  const pin = note.isPinned ? (ascii ? '*' : '\u25c6') : '-';
  const content = note.isSensitive ? secretMask(ascii) : safe(note.content, ascii);
  return `${pin} ${safe(note.title, ascii)}: ${content}`;
}

function safe(value: string, ascii: boolean): string {
  return sanitizeTerminalText(value, ascii);
}

function padCell(value: string, width: number): string {
  return `${value}${' '.repeat(Math.max(0, width - Array.from(value).length))}`;
}
