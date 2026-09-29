import { Box, Text } from 'ink';
import type { ReactElement, ReactNode } from 'react';

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
      {sectionTitle(label, ascii)}
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
}: Readonly<{
  keyLabel: string;
  hint: string;
  color: boolean;
  keyAccent?: AppAccent;
}>): ReactElement {
  return (
    <Text>
      <Text bold {...accentColor(color, keyAccent)}>
        {keyLabel}
      </Text>
      <Text dimColor {...accentColor(color, CHROME.muted)}>
        {' '}
        {hint}
      </Text>
    </Text>
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
}>): ReactElement {
  const pointer = pointerGlyph(ascii);
  const bar = active ? pointer : ' ';
  const rawLabel = safe(label, ascii);
  const paddedLabel =
    labelWidth === undefined
      ? rawLabel
      : rawLabel.length >= labelWidth
        ? rawLabel.slice(0, labelWidth)
        : `${rawLabel}${' '.repeat(labelWidth - rawLabel.length)}`;
  if (active) {
    return (
      <Text dimColor={pending}>
        <Text bold {...accentColor(color, accent)} inverse={color}>
          {` ${bar} ${paddedLabel} `}
        </Text>
        {hint === undefined || hint.length === 0 ? null : (
          <Text dimColor {...accentColor(color, CHROME.muted)}>
            {' '}
            {safe(hint, ascii)}
          </Text>
        )}
      </Text>
    );
  }
  return (
    <Text dimColor {...accentColor(color, CHROME.muted)}>
      {` ${bar} ${paddedLabel}`}
      {hint === undefined || hint.length === 0 ? null : (
        <Text dimColor {...accentColor(color, CHROME.muted)}>
          {'  '}
          {safe(hint, ascii)}
        </Text>
      )}
    </Text>
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
export function useListStagger(
  itemCount: number,
  enabled: boolean,
): (index: number) => boolean {
  const elapsedMs = useElapsedMs(enabled);
  const visible = enabled ? staggerVisibleCount(elapsedMs, itemCount) : itemCount;
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
    Math.max(CHROME.modalMinWidth, width - 4),
  );
  const progress = useEnterProgress(animate, MOTION.enterMs);
  const offset = enterOffsetCells(progress, animate);
  return (
    <Box
      width={width}
      justifyContent="center"
      alignItems="center"
      flexDirection="column"
      paddingY={1}
      marginTop={offset}
    >
      <Panel
        title={title}
        accent={accent}
        ascii={ascii}
        color={color}
        kind="modal"
        width={modalWidth}
        paddingX={CHROME.modalPaddingX}
        paddingY={CHROME.modalPaddingY}
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
}: Readonly<{
  active: boolean;
  title: string;
  subtitle: string;
  accent?: AppAccent;
  color: boolean;
  ascii: boolean;
  pending?: boolean;
}>): ReactElement {
  const pointer = pointerGlyph(ascii);
  return (
    <Box
      flexDirection="column"
      paddingX={1}
      {...(active && color
        ? { borderStyle: panelBorderStyle(ascii, 'panel'), borderColor: accent }
        : {})}
    >
      <Text
        bold={active}
        dimColor={pending}
        {...accentColor(color, active ? accent : CHROME.muted)}
      >
        {active ? pointer : ' '} {safe(title, ascii)}
      </Text>
      <Text dimColor={pending} {...accentColor(color, CHROME.muted)}>
        {'   '}
        {safe(subtitle, ascii)}
      </Text>
    </Box>
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
 * narrow terminals instead of wrapping.
 */
export function TabNav({
  activeId,
  color,
  ascii,
  width,
}: Readonly<{
  activeId: AppScreenId;
  color: boolean;
  ascii: boolean;
  width: number;
}>): ReactElement | null {
  if (width < TABNAV_MIN_WIDTH) return null;
  const budget = width - 2;
  const sep = '  ';
  const kept: readonly {
    label: string;
    number: string | null;
    active: boolean;
    accent: AppAccent;
  }[] = (() => {
    const rows = APP_MENU.map((entry, index) => ({
      label: sanitizeTerminalText(entry.short ?? entry.label, ascii),
      number: index < 9 ? String(index + 1) : null,
      active: entry.id === activeId,
      accent: entry.accent,
    }));
    const cost = (row: (typeof rows)[number], first: boolean): number =>
      (first ? 0 : sep.length) +
      (row.number === null ? 0 : row.number.length + 1) +
      row.label.length;
    const fits: (typeof rows)[number][] = [];
    let used = 0;
    for (const row of rows) {
      const extra = cost(row, fits.length === 0);
      if (fits.length >= TABNAV_MIN_ENTRIES && used + extra > budget - 1) break;
      fits.push(row);
      used += extra;
    }
    if (!fits.some((row) => row.active)) {
      const active = rows.find((row) => row.active);
      if (active === undefined) return fits;
      // Trade the last visible entry for the active one so the current screen
      // is always highlighted, even at the minimum fit.
      if (fits.length > 0) fits.pop();
      fits.push(active);
    }
    return fits;
  })();
  if (kept.length < TABNAV_MIN_ENTRIES) return null;
  const truncated = kept.length < APP_MENU.length;
  return (
    <Box paddingX={1}>
      <Text>
        {kept.map((row, index) => (
          <Text key={`${row.number ?? ''}${row.label}`}>
            {index === 0 ? null : (
              <Text {...accentColor(color, CHROME.muted)}>{sep}</Text>
            )}
            <Text
              bold
              inverse={row.active && color}
              dimColor={!row.active}
              {...accentColor(color, row.active ? row.accent : CHROME.muted)}
            >
              {`${row.number === null ? '' : `${row.number} `}${row.label}`}
            </Text>
          </Text>
        ))}
        {truncated ? (
          <Text {...accentColor(color, CHROME.muted)}>
            {ascii ? ' ...' : ' \u2026'}
          </Text>
        ) : null}
      </Text>
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
