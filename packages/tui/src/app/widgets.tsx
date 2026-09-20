import { Box, Text } from 'ink';
import type { ReactElement, ReactNode } from 'react';

import {
  enterOffsetCells,
  MOTION,
  staggerVisibleCount,
  useElapsedMs,
  useEnterProgress,
  useMotionFrame,
} from '../motion.js';
import { sanitizeTerminalText } from '../terminal-text.js';
import {
  accentColor,
  CHROME,
  panelBorderStyle,
  pointerGlyph,
  sectionTitle,
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
  const spinner = ascii
    ? ['|', '/', '-', '\\'][frame % 4]
    : ['\u280b', '\u2819', '\u2839', '\u2838'][frame % 4];
  return (
    <Box flexDirection="row" columnGap={1} paddingY={1}>
      <Text {...accentColor(color, CHROME.accent)}>{spinner ?? '|'}</Text>
      <Text {...accentColor(color, CHROME.muted)}>{safe(label, ascii)}</Text>
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
  return (
    <Panel accent={accent} ascii={ascii} color={color} paddingX={CHROME.paddingX}>
      <Text {...accentColor(color, accent)}>{safe(message, ascii)}</Text>
    </Panel>
  );
}
