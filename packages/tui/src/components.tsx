import type { FieldDefinition, Note } from '@kavrix/schemas';
import { Box, Text, useApp, useInput, useStdout } from 'ink';
import { useCallback, useEffect, useRef, useState, type ReactElement } from 'react';

import type { TuiUseCasePort } from './contracts.js';
import { describeFieldEditor } from './field-registry.js';
import { buildTuiScreenModel, renderTuiScreenText } from './screen-model.js';
import {
  createInitialTuiState,
  transitionTui,
  type TuiAction,
  type TuiEffect,
  type TuiKey,
  type TuiState,
} from './state.js';
import { sanitizeTerminalText, secretMask } from './terminal-text.js';

export interface TuiScreenProps {
  readonly state: TuiState;
  readonly nowMs: number;
}

/** Presentational screen. Keeping it pure makes exact resize/security snapshots deterministic. */
export function TuiScreen({ state, nowMs }: TuiScreenProps): ReactElement {
  const model = buildTuiScreenModel(state, nowMs);
  return (
    <Box width={model.width} height={model.height} overflow="hidden">
      <Text>{renderTuiScreenText(model)}</Text>
    </Box>
  );
}

export interface DynamicSchemaBuilderProps {
  readonly fields: readonly FieldDefinition[];
  readonly ascii?: boolean;
}

/** Schema-driven template view; every row comes from the canonical field registry. */
export function DynamicSchemaBuilder({
  fields,
  ascii = false,
}: DynamicSchemaBuilderProps): ReactElement {
  return (
    <Box flexDirection="column">
      {fields
        .toSorted((left, right) => left.sortOrder - right.sortOrder)
        .map((field) => {
          const editor = describeFieldEditor(field);
          const flags = [
            field.required ? 'required' : null,
            field.sensitive ? 'masked' : null,
            editor.supportsMultiple ? 'multiple' : null,
          ].filter((flag): flag is string => flag !== null);
          return (
            <Text key={field.id}>
              {sanitizeTerminalText(field.label, ascii)} [{field.type}]{' '}
              {editor.inputMode}
              {flags.length === 0 ? '' : ` (${flags.join(', ')})`}
            </Text>
          );
        })}
    </Box>
  );
}

export interface MultipleNoteEditorProps {
  readonly notes: readonly Note[];
  readonly selectedIndex: number;
  readonly ascii?: boolean;
}

/** Multiple notes are independent canonical records; sensitive content is never previewed. */
export function MultipleNoteEditor({
  notes,
  selectedIndex,
  ascii = false,
}: MultipleNoteEditorProps): ReactElement {
  return (
    <Box flexDirection="column">
      {notes.map((note, index) => (
        <Text key={note.id}>
          {index === selectedIndex ? '>' : ' '}{' '}
          {note.isPinned ? (ascii ? '*' : '\u25c6') : '-'}{' '}
          {sanitizeTerminalText(note.title, ascii)}:{' '}
          {note.isSensitive
            ? secretMask(ascii)
            : sanitizeTerminalText(note.content, ascii)}
        </Text>
      ))}
    </Box>
  );
}

export interface VaultTuiProps {
  readonly useCases: TuiUseCasePort;
  readonly ascii?: boolean;
  readonly now?: () => number;
  readonly onLocked?: () => void;
}

/**
 * Runtime shell. It owns no persistence or cryptography and aborts an older
 * operation before starting the next one.
 */
export function VaultTui({
  useCases,
  ascii = false,
  now = Date.now,
  onLocked,
}: VaultTuiProps): ReactElement {
  const { stdout } = useStdout();
  const { exit } = useApp();
  const initial = createInitialTuiState(stdout.columns, stdout.rows, ascii);
  const [state, setState] = useState(initial);
  const stateRef = useRef(state);
  const activeController = useRef<AbortController | null>(null);
  const dispatchRef = useRef<(action: TuiAction) => void>(() => undefined);
  const useCasesRef = useRef(useCases);
  const onLockedRef = useRef(onLocked);
  const exitRef = useRef(exit);
  useCasesRef.current = useCases;
  onLockedRef.current = onLocked;
  exitRef.current = exit;

  const runEffect = useCallback((effect: TuiEffect): void => {
    activeController.current?.abort();
    const controller = new AbortController();
    activeController.current = controller;
    const complete = (action: TuiAction): void => {
      if (!controller.signal.aborted) dispatchRef.current(action);
    };
    const failed = (): void => {
      complete({ type: 'operation-failed', requestId: effect.requestId });
    };

    switch (effect.kind) {
      case 'load-groups':
        void useCasesRef.current.listGroups(controller.signal).then((groups) => {
          complete({ type: 'groups-loaded', requestId: effect.requestId, groups });
        }, failed);
        return;
      case 'load-items':
        void useCasesRef.current
          .listItems(effect.groupId, controller.signal)
          .then((items) => {
            complete({
              type: 'items-loaded',
              requestId: effect.requestId,
              groupId: effect.groupId,
              items,
            });
          }, failed);
        return;
      case 'copy-field':
        void useCasesRef.current
          .copyField(effect.itemId, effect.fieldId, controller.signal)
          .then(() => {
            complete({ type: 'copy-finished', requestId: effect.requestId });
          }, failed);
        return;
      case 'authorize-reveal':
        void useCasesRef.current
          .authorizeReveal(effect.itemId, effect.fieldId, controller.signal)
          .then(() => {
            complete({
              type: 'reveal-authorized',
              requestId: effect.requestId,
              fieldId: effect.fieldId,
              expiresAt: effect.expiresAt,
            });
          }, failed);
        return;
      case 'save-item':
        void useCasesRef.current
          .saveItem(effect.item, effect.expectedRevision, controller.signal)
          .then((result) => {
            complete({ type: 'save-finished', requestId: effect.requestId, result });
          }, failed);
        return;
      case 'lock':
        void useCasesRef.current.lock(controller.signal).then(() => {
          complete({ type: 'lock-finished', requestId: effect.requestId });
        }, failed);
    }
  }, []);

  const dispatch = useCallback(
    (action: TuiAction): void => {
      const next = transitionTui(stateRef.current, action);
      stateRef.current = next.state;
      setState(next.state);
      for (const effect of next.effects) runEffect(effect);
    },
    [runEffect],
  );
  dispatchRef.current = dispatch;

  useEffect(() => {
    dispatch({ type: 'start' });
    return () => {
      activeController.current?.abort();
    };
  }, [dispatch]);

  useEffect(() => {
    const resize = (): void => {
      dispatch({
        type: 'resize',
        width: stdout.columns,
        height: stdout.rows,
      });
    };
    stdout.on('resize', resize);
    return () => {
      stdout.off('resize', resize);
    };
  }, [dispatch, stdout]);

  useEffect(() => {
    if (Object.keys(state.revealedUntil).length === 0) return undefined;
    const interval = setInterval(() => {
      dispatch({ type: 'tick', nowMs: now() });
    }, 250);
    return () => {
      clearInterval(interval);
    };
  }, [dispatch, now, state.revealedUntil]);

  useEffect(() => {
    if (state.screen !== 'locked' || state.pending !== null) return;
    onLockedRef.current?.();
    exitRef.current();
  }, [state.pending, state.screen]);

  useInput((input, key) => {
    const mapped = mapInkInput(input, key);
    if (mapped !== null) {
      dispatch({ type: 'key', key: mapped, nowMs: now() });
    }
  });

  return <TuiScreen state={state} nowMs={now()} />;
}

function mapInkInput(
  input: string,
  key: Readonly<{
    upArrow: boolean;
    downArrow: boolean;
    leftArrow: boolean;
    rightArrow: boolean;
    tab: boolean;
    return: boolean;
    escape: boolean;
    backspace: boolean;
    ctrl: boolean;
    shift: boolean;
  }>,
): TuiKey | null {
  if (key.upArrow) return { name: 'up' };
  if (key.downArrow) return { name: 'down' };
  if (key.leftArrow) return { name: 'left' };
  if (key.rightArrow) return { name: 'right' };
  if (key.tab) return { name: 'tab', shift: key.shift };
  if (key.return) return { name: 'return', shift: key.shift };
  if (key.escape) return { name: 'escape' };
  if (key.backspace) return { name: 'backspace' };
  if (input.length === 0) return null;
  return { text: input, ctrl: key.ctrl, shift: key.shift };
}
