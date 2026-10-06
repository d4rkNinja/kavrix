import { Box, Text } from 'ink';
import type { ComponentProps, ReactElement, ReactNode } from 'react';
import { useEffect, useState } from 'react';

import { subscribeToFrameClock } from '../frame-clock.js';
import {
  animatedDots,
  barFill,
  clamp01,
  enterOffsetCells,
  MOTION,
  revealProgress,
  revealRemainingMs,
  staggerVisibleCount,
  sweepBarRow,
  useElapsedMs,
  useEnterProgress,
  useMotionFrame,
} from '../motion.js';
import { sanitizeTerminalText } from '../terminal-text.js';
import { APP_MENU, type AppScreenId } from './ids.js';
import { keyForChip, useAppInteraction, useInputInteraction } from './interaction.js';
import { ClickTarget } from './mouse.js';
import {
  accentColor,
  CHROME,
  dividerRule,
  panelBorderStyle,
  pointerGlyph,
  sectionTitle,
  toneGlyph,
  type AppAccent,
} from './theme.js';

function safe(value: string, ascii: boolean): string {
  return sanitizeTerminalText(value, ascii);
}

/** Clip at cell boundaries without Ink inserting a Unicode ellipsis in ASCII mode. */
export function SingleLine({
  children,
  ...props
}: ComponentProps<typeof Text>): ReactElement {
  return (
    <Box height={1} minHeight={1} minWidth={0} flexGrow={1} overflow="hidden">
      <Text {...props} wrap="hard">
        {children}
      </Text>
    </Box>
  );
}

export function SectionTitle({
  label,
  ascii,
  color,
  accent = CHROME.accent,
}: Readonly<{
  label: string;
  ascii: boolean;
  color: boolean;
  accent?: AppAccent;
}>): ReactElement {
  return (
    <Text bold {...accentColor(color, accent)}>
      {sectionTitle(safe(label, ascii), ascii)}
    </Text>
  );
}

/**
 * OpenTUI-style bordered panel. Ink has no `title=` on borders, so the title
 * is rendered as a labeled header row inside the box.
 */
export function Panel({
  title,
  accent = CHROME.accent,
  ascii,
  color,
  children,
  flexGrow,
  width,
  paddingX = CHROME.paddingX,
  paddingY = CHROME.paddingY,
  kind = 'panel',
}: Readonly<{
  title?: string;
  accent?: AppAccent;
  ascii: boolean;
  color: boolean;
  children: ReactNode;
  flexGrow?: number;
  width?: number | string;
  paddingX?: number;
  paddingY?: number;
  kind?: 'panel' | 'modal';
}>): ReactElement {
  const borderStyle = panelBorderStyle(ascii, kind);
  return (
    <Box
      flexDirection="column"
      flexShrink={0}
      borderStyle={borderStyle}
      {...(color ? { borderColor: accent } : {})}
      {...(flexGrow === undefined ? {} : { flexGrow })}
      {...(width === undefined ? {} : { width })}
      paddingX={paddingX}
      paddingY={paddingY}
    >
      {title === undefined ? null : (
        <Box marginBottom={0}>
          <SectionTitle label={title} ascii={ascii} color={color} accent={accent} />
        </Box>
      )}
      {children}
    </Box>
  );
}

export function StatusPill({
  label,
  value,
  accent,
  color,
  ascii,
  pulse = false,
}: Readonly<{
  label: string;
  value: string;
  accent: AppAccent;
  color: boolean;
  ascii: boolean;
  pulse?: boolean;
}>): ReactElement {
  const frame = useMotionFrame(pulse, MOTION.pulseMs);
  const dim = pulse && frame % 2 === 1;
  const open = ascii ? '[' : '\u27e6';
  const close = ascii ? ']' : '\u27e7';
  return (
    <Text>
      <Text {...accentColor(color, CHROME.muted)}>{open}</Text>
      <Text dimColor={dim} {...accentColor(color, CHROME.muted)}>
        {safe(label, ascii)}:
      </Text>
      <Text bold dimColor={dim} {...accentColor(color, accent)}>
        {safe(value, ascii)}
      </Text>
      <Text {...accentColor(color, CHROME.muted)}>{close}</Text>
    </Text>
  );
}

export function KeyChip({
  keyLabel,
  hint,
  color,
  keyAccent = CHROME.accent,
  onPress,
  disabled = false,
  active = false,
  button = false,
}: Readonly<{
  keyLabel: string;
  hint: string;
  color: boolean;
  keyAccent?: AppAccent;
  onPress?: () => void;
  disabled?: boolean;
  active?: boolean;
  /** Larger pointer target for primary controls on roomy terminal layouts. */
  button?: boolean;
}>): ReactElement {
  const interaction = useInputInteraction();
  const key = keyForChip(keyLabel);
  const press =
    onPress ??
    (key === null
      ? undefined
      : () => {
          interaction.press(key);
        });
  return (
    <ClickTarget
      paddingX={button ? 1 : 0}
      paddingY={button ? 1 : 0}
      enabled={
        (interaction.enabled || keyLabel === 'Esc' || keyLabel === 'q') &&
        !disabled &&
        press !== undefined
      }
      {...(press === undefined ? {} : { onClick: press })}
    >
      <Text dimColor={disabled}>
        <Text bold {...accentColor(color, keyAccent)}>
          {keyLabel}
        </Text>
        <Text
          bold={active}
          dimColor={!active}
          {...accentColor(color, active ? keyAccent : CHROME.muted)}
        >
          {' '}
          {hint}
        </Text>
      </Text>
    </ClickTarget>
  );
}

/**
 * OpenTUI select-row: accent bar + label + hint with clear active highlight.
 * Active uses inverse; inactive is dim. Keyboard moves do not animate.
 */
export function SelectRow({
  active,
  label,
  hint,
  accent = CHROME.accent,
  color,
  ascii,
  labelWidth,
  pending = false,
  onPress,
}: Readonly<{
  active: boolean;
  label: string;
  hint?: string;
  accent?: AppAccent;
  color: boolean;
  ascii: boolean;
  /** When set, pads the label column so hints align across rows. */
  labelWidth?: number;
  /** Decorative stagger: row is present but not yet visually settled. */
  pending?: boolean;
  onPress?: () => void;
}>): ReactElement {
  const interaction = useInputInteraction();
  const pointer = pointerGlyph(ascii);
  const bar = active ? pointer : ' ';
  const rawLabel = safe(label, ascii);
  const paddedLabel =
    labelWidth === undefined
      ? rawLabel
      : rawLabel.length >= labelWidth
        ? rawLabel.slice(0, labelWidth)
        : `${rawLabel}${' '.repeat(labelWidth - rawLabel.length)}`;
  return (
    <ClickTarget
      enabled={interaction.enabled && onPress !== undefined}
      {...(onPress === undefined ? {} : { onClick: onPress })}
    >
      <SingleLine dimColor={pending || !active}>
        <Text
          bold={active}
          {...accentColor(color, active ? accent : CHROME.muted)}
          inverse={active && color}
        >
          {active ? ` ${bar} ${paddedLabel} ` : `   ${paddedLabel} `}
        </Text>
        {hint === undefined || hint.length === 0 ? null : (
          <Text dimColor {...accentColor(color, CHROME.muted)}>
            {' '}
            {safe(hint, ascii)}
          </Text>
        )}
      </SingleLine>
    </ClickTarget>
  );
}

export function MotionEnter({
  enabled,
  children,
}: Readonly<{
  enabled: boolean;
  children: ReactNode;
}>): ReactElement {
  const progress = useEnterProgress(enabled, MOTION.enterMs);
  const offset = enterOffsetCells(progress, enabled);
  return (
    <Box flexDirection="column" marginTop={offset} flexGrow={1}>
      {children}
    </Box>
  );
}

/**
 * List stagger: every row stays mounted and interactive. Unsettled rows are
 * only dimmed. Keyboard navigation must not change `enabled` mid-move.
 */
/**
 * List stagger: every row stays mounted and interactive. Unsettled rows are
 * only dimmed. Keyboard navigation must not change `enabled` mid-move.
 *
 * The stagger owns its clock subscription and stops updating state once every
 * row has settled, so a list screen does not keep redrawing at the frame
 * clock's rate for the rest of its lifetime after the entrance finishes. The
 * shared clock itself is unaffected: this only removes the per-tick state
 * commit that nothing consumes anymore.
 */
export function useListStagger(
  itemCount: number,
  enabled: boolean,
): (index: number) => boolean {
  const [visible, setVisible] = useState(() =>
    enabled ? staggerVisibleCount(0, itemCount) : itemCount,
  );
  useEffect(() => {
    if (!enabled) {
      setVisible(itemCount);
      return undefined;
    }
    let settled = itemCount === 0;
    let lastVisible = -1;
    const update = (elapsedMs: number): void => {
      if (settled) return;
      const next = staggerVisibleCount(elapsedMs, itemCount);
      if (next !== lastVisible) {
        lastVisible = next;
        setVisible(next);
      }
      if (next >= itemCount) settled = true;
    };
    update(0);
    return subscribeToFrameClock(update);
  }, [enabled, itemCount]);
  return (index: number): boolean => enabled && index >= visible;
}

/**
 * Centered modal/dialog frame — OpenTUI modal pattern (double border unicode,
 * classic ASCII). Entrance is a one-cell settle; exits stay instant.
 */
export function ModalFrame({
  title,
  accent = CHROME.warning,
  ascii,
  color,
  width,
  animate = false,
  children,
}: Readonly<{
  title: string;
  accent?: AppAccent;
  ascii: boolean;
  color: boolean;
  width: number;
  animate?: boolean;
  children: ReactNode;
}>): ReactElement {
  const modalWidth = Math.min(
    CHROME.modalMaxWidth,
    Math.max(1, width - (width < 44 ? 0 : 4)),
  );
  const progress = useEnterProgress(animate, MOTION.enterMs);
  const offset = enterOffsetCells(progress, animate);
  return (
    <Box
      width={width}
      justifyContent="center"
      alignItems="center"
      flexDirection="column"
      paddingY={0}
      marginTop={offset}
    >
      <Panel
        title={title}
        accent={accent}
        ascii={ascii}
        color={color}
        kind="modal"
        width={modalWidth}
        paddingX={width < 60 ? 1 : CHROME.modalPaddingX}
        paddingY={0}
      >
        {children}
      </Panel>
    </Box>
  );
}

export function CardRow({
  active,
  title,
  subtitle,
  accent = CHROME.accent,
  color,
  ascii,
  pending = false,
  onPress,
}: Readonly<{
  active: boolean;
  title: string;
  subtitle: string;
  accent?: AppAccent;
  color: boolean;
  ascii: boolean;
  pending?: boolean;
  onPress?: () => void;
}>): ReactElement {
  const interaction = useAppInteraction();
  const pointer = pointerGlyph(ascii);
  return (
    <ClickTarget
      enabled={interaction.enabled && onPress !== undefined}
      {...(onPress === undefined ? {} : { onClick: onPress })}
    >
      <Box flexDirection="column" paddingX={1}>
        <SingleLine
          bold={active}
          inverse={active && color}
          dimColor={pending}
          {...accentColor(color, active ? accent : CHROME.muted)}
        >
          {active ? pointer : ' '} {safe(title, ascii)}
        </SingleLine>
        <SingleLine dimColor={pending} {...accentColor(color, CHROME.muted)}>
          {'   '}
          {safe(subtitle, ascii)}
        </SingleLine>
      </Box>
    </ClickTarget>
  );
}

export function EmptyState({
  title,
  hint,
  color,
  ascii,
}: Readonly<{
  title: string;
  hint: string;
  color: boolean;
  ascii: boolean;
}>): ReactElement {
  return (
    <Box flexDirection="column" paddingY={1}>
      <Text {...accentColor(color, CHROME.warning)}>{safe(title, ascii)}</Text>
      <Text {...accentColor(color, CHROME.muted)}>{safe(hint, ascii)}</Text>
    </Box>
  );
}

export function ErrorState({
  title,
  recovery,
  color,
  ascii,
}: Readonly<{
  title: string;
  recovery: string;
  color: boolean;
  ascii: boolean;
}>): ReactElement {
  return (
    <Box flexDirection="column" paddingY={1}>
      <Text bold {...accentColor(color, CHROME.danger)}>
        {safe(title, ascii)}
      </Text>
      <Text {...accentColor(color, CHROME.muted)}>{safe(recovery, ascii)}</Text>
    </Box>
  );
}

export function LoadingState({
  label,
  color,
  ascii,
  animate = false,
}: Readonly<{
  label: string;
  color: boolean;
  ascii: boolean;
  animate?: boolean;
}>): ReactElement {
  const frame = useMotionFrame(animate, MOTION.feedbackMs);
  const elapsedMs = useElapsedMs(animate);
  const spinner = ascii
    ? ['|', '/', '-', '\\'][frame % 4]
    : ['\u280b', '\u2819', '\u2839', '\u2838'][frame % 4];
  const seconds = Math.floor(elapsedMs / 1_000);
  // Callers may pass a label that already ends in an ellipsis; dots animate in
  // its place so the two never stack.
  const base = safe(label, ascii)
    .replace(/\u2026$/u, '')
    .replace(/\.\.\.$/u, '');
  return (
    <Box flexDirection="row" columnGap={1} paddingY={1}>
      <Text {...accentColor(color, CHROME.accent)}>{spinner ?? '|'}</Text>
      <Text {...accentColor(color, CHROME.muted)}>
        {animate ? `${base}${animatedDots(frame)}` : safe(label, ascii)}
      </Text>
      {animate && seconds > 0 ? (
        <Text dimColor {...accentColor(color, CHROME.muted)}>
          {`${String(seconds)}s`}
        </Text>
      ) : null}
    </Box>
  );
}

/** Determinate progress bar (OpenTUI ProgressBar pattern on a cell grid). */
export function ProgressBar({
  progress,
  width = 24,
  color,
  ascii,
  accent = CHROME.accent,
  label,
}: Readonly<{
  progress: number;
  width?: number;
  color: boolean;
  ascii: boolean;
  accent?: AppAccent;
  label?: string;
}>): ReactElement {
  const pct = Math.round(clamp01(progress) * 100);
  return (
    <Box flexDirection="row" columnGap={1}>
      {label === undefined ? null : (
        <Text {...accentColor(color, CHROME.muted)}>{safe(label, ascii)}</Text>
      )}
      <Text {...accentColor(color, accent)}>{barFill(progress, width, ascii)}</Text>
      <Text {...accentColor(color, CHROME.muted)}>{`${String(pct)}%`}</Text>
    </Box>
  );
}

/**
 * Indeterminate sweep for unknown-duration work. The traveling segment is
 * decorative motion, not a claimed measurement.
 */
export function SweepBar({
  width = 24,
  color,
  ascii,
  animate = false,
  accent = CHROME.accent,
}: Readonly<{
  width?: number;
  color: boolean;
  ascii: boolean;
  animate?: boolean;
  accent?: AppAccent;
}>): ReactElement {
  const frame = useMotionFrame(animate, MOTION.sweepMs);
  const segment = Math.max(3, Math.floor(width / 5));
  const row = animate
    ? sweepBarRow(frame, width, segment, ascii)
    : barFill(1, width, ascii);
  return <Text {...accentColor(color, accent)}>{row}</Text>;
}

/** Wizard position indicator: filled dots up to the current step. */
export function StepDots({
  index,
  total,
  color,
  ascii,
  accent = CHROME.accent,
}: Readonly<{
  index: number;
  total: number;
  color: boolean;
  ascii: boolean;
  accent?: AppAccent;
}>): ReactElement {
  const count = Math.max(1, Math.floor(total));
  const current = Math.max(0, Math.min(count - 1, Math.floor(index)));
  const filled = ascii ? '#' : '\u25cf';
  const empty = ascii ? '.' : '\u25cb';
  const dots = Array.from({ length: count }, (_, position) =>
    position <= current ? filled : empty,
  ).join(' ');
  return (
    <Text>
      <Text {...accentColor(color, accent)}>{dots}</Text>
      <Text
        {...accentColor(color, CHROME.muted)}
      >{` ${String(current + 1)}/${String(count)}`}</Text>
    </Text>
  );
}

/** Live countdown for the timed REVEAL window before the value remasks. */
export function RevealCountdown({
  expiresAtMs,
  nowMs,
  windowMs = MOTION.revealWindowMs,
  width = 24,
  color,
  ascii,
}: Readonly<{
  expiresAtMs: number;
  nowMs: number;
  windowMs?: number;
  width?: number;
  color: boolean;
  ascii: boolean;
}>): ReactElement {
  const remaining = revealRemainingMs(expiresAtMs, nowMs);
  const seconds = Math.ceil(remaining / 1_000);
  const bar = barFill(revealProgress(expiresAtMs, nowMs, windowMs), width, ascii);
  return (
    <Text {...accentColor(color, CHROME.danger)}>
      {`${ascii ? '[!] ' : ' \u26a0 '}REVEAL remasks in ${String(seconds)}s ${bar}`}
    </Text>
  );
}

/** Soft full-width divider between content sections. */
export function Divider({
  width,
  color,
  ascii,
  accent = CHROME.muted,
}: Readonly<{
  width: number;
  color: boolean;
  ascii: boolean;
  accent?: AppAccent;
}>): ReactElement {
  return <Text {...accentColor(color, accent)}>{dividerRule(ascii, width)}</Text>;
}

const TABNAV_MIN_ENTRIES = 4;
const TABNAV_MIN_WIDTH = 56;

/**
 * Compact screen tab strip (OpenTUI tab-select pattern). Numbers mirror the
 * router's digit shortcuts; `Tab`/`Shift+Tab` cycle in listed order. Hides on
 * narrow terminals instead of wrapping. `navigable` mirrors the router's
 * navigation gate so the strip stops looking clickable while the router would
 * reject `navigate` (an open overlay); it defaults to inert because a caller
 * that has not stated the gate cannot promise the click would navigate.
 */
export function TabNav({
  activeId,
  navigable = false,
  color,
  ascii,
  width,
}: Readonly<{
  activeId: AppScreenId;
  navigable?: boolean;
  color: boolean;
  ascii: boolean;
  width: number;
}>): ReactElement | null {
  const interaction = useAppInteraction();
  const clickable = interaction.enabled && navigable;
  if (width < TABNAV_MIN_WIDTH) return null;
  // The row spends `paddingX={1}` on each side, and a truncated strip also needs
  // one `columnGap` plus one cell for the overflow marker. Budgeting for exactly
  // those — and charging the marker only when the strip really does truncate —
  // keeps the last reachable destination instead of dropping it while columns
  // are still free.
  const available = width - 2;
  const overflowCost = 3;
  const sep = '  ';
  const kept: readonly {
    id: AppScreenId;
    label: string;
    number: string | null;
    active: boolean;
    accent: AppAccent;
  }[] = (() => {
    const rows = APP_MENU.map((entry, index) => ({
      id: entry.id,
      label: sanitizeTerminalText(entry.short ?? entry.label, ascii),
      number: index < 9 ? String(index + 1) : null,
      active: entry.id === activeId,
      accent: entry.accent,
    }));
    const cost = (row: (typeof rows)[number], first: boolean): number =>
      (first ? 0 : sep.length) +
      (row.number === null ? 0 : row.number.length + 1) +
      row.label.length;
    const measure = (list: readonly (typeof rows)[number][]): number =>
      list.reduce((total, row, index) => total + cost(row, index === 0), 0);
    const fit = (budget: number): (typeof rows)[number][] => {
      const chosen: (typeof rows)[number][] = [];
      let used = 0;
      for (const row of rows) {
        const extra = cost(row, chosen.length === 0);
        if (chosen.length >= TABNAV_MIN_ENTRIES && used + extra > budget) break;
        chosen.push(row);
        used += extra;
      }
      return chosen;
    };
    const unreserved = fit(available);
    const truncates = unreserved.length < rows.length;
    const budget = truncates ? available - overflowCost : available;
    const keptRows = truncates ? fit(budget) : unreserved;
    if (!keptRows.some((row) => row.active)) {
      const active = rows.find((row) => row.active);
      if (active === undefined) return keptRows;
      // Trade the last visible entry for the active one so the current screen
      // is always highlighted, even at the minimum fit.
      if (keptRows.length > 0) keptRows.pop();
      keptRows.push(active);
    }
    while (keptRows.length > 1 && measure(keptRows) > budget) {
      const removeAt = keptRows.findLastIndex((row) => !row.active);
      if (removeAt < 0) break;
      keptRows.splice(removeAt, 1);
    }
    return keptRows;
  })();
  if (kept.length < TABNAV_MIN_ENTRIES) return null;
  const truncated = kept.length < APP_MENU.length;
  return (
    <Box paddingX={1} height={1} flexDirection="row" columnGap={2} overflow="hidden">
      {kept.map((row) => (
        <ClickTarget
          key={`${row.number ?? ''}${row.label}`}
          enabled={clickable}
          onClick={() => {
            interaction.dispatch({ type: 'navigate', screen: row.id });
          }}
        >
          <Text
            bold
            inverse={row.active && color}
            dimColor={!row.active}
            {...accentColor(color, row.active ? row.accent : CHROME.muted)}
          >
            {`${row.number === null ? '' : `${row.number} `}${row.label}`}
          </Text>
        </ClickTarget>
      ))}
      {truncated ? (
        <ClickTarget
          enabled={clickable}
          onClick={() => {
            interaction.dispatch({ type: 'navigate', screen: 'home' });
          }}
        >
          <Text {...accentColor(color, CHROME.muted)}>{ascii ? '...' : '\u2026'}</Text>
        </ClickTarget>
      ) : null}
    </Box>
  );
}

export function NoticeBar({
  message,
  accent,
  color,
  ascii,
}: Readonly<{
  message: string;
  accent: AppAccent;
  color: boolean;
  ascii: boolean;
}>): ReactElement {
  const glyph = glyphForAccent(accent, ascii);
  return (
    <Panel accent={accent} ascii={ascii} color={color} paddingX={CHROME.paddingX}>
      <Text {...accentColor(color, accent)}>{`${glyph}${safe(message, ascii)}`}</Text>
    </Panel>
  );
}

function glyphForAccent(accent: AppAccent, ascii: boolean): string {
  switch (accent) {
    case 'green':
      return toneGlyph('success', ascii);
    case 'yellow':
      return toneGlyph('warning', ascii);
    case 'red':
      return toneGlyph('error', ascii);
    case 'cyan':
      return toneGlyph('info', ascii);
    default:
      return toneGlyph('muted', ascii);
  }
}
