import { Box, Text } from 'ink';
import type { ReactElement, ReactNode } from 'react';

import { sanitizeTerminalText } from '../terminal-text.js';
import {
  panelBorderStyle,
  pointerGlyph,
  sectionTitle,
  type AppAccent,
} from './theme.js';

function tint(
  enabled: boolean,
  accent: AppAccent,
): Readonly<{ color: AppAccent }> | Readonly<Record<string, never>> {
  return enabled ? { color: accent } : {};
}

function safe(value: string, ascii: boolean): string {
  return sanitizeTerminalText(value, ascii);
}

export function SectionTitle({
  label,
  ascii,
  color,
  accent = 'cyan',
}: Readonly<{
  label: string;
  ascii: boolean;
  color: boolean;
  accent?: AppAccent;
}>): ReactElement {
  return (
    <Text bold {...tint(color, accent)}>
      {sectionTitle(label, ascii)}
    </Text>
  );
}

/**
 * OpenTUI-style bordered panel. Ink has no `title=` on borders, so the title
 * is rendered as a labeled header row inside the box (top border label line).
 */
export function Panel({
  title,
  accent = 'cyan',
  ascii,
  color,
  children,
  flexGrow,
  width,
  paddingX = 1,
  paddingY = 0,
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
        <Box marginBottom={paddingY > 0 ? 0 : 0}>
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
}: Readonly<{
  label: string;
  value: string;
  accent: AppAccent;
  color: boolean;
  ascii: boolean;
}>): ReactElement {
  const open = ascii ? '[' : '\u27e6';
  const close = ascii ? ']' : '\u27e7';
  return (
    <Text>
      <Text {...tint(color, 'gray')}>{open}</Text>
      <Text {...tint(color, 'gray')}>{safe(label, ascii)}:</Text>
      <Text bold {...tint(color, accent)}>
        {safe(value, ascii)}
      </Text>
      <Text {...tint(color, 'gray')}>{close}</Text>
    </Text>
  );
}

export function KeyChip({
  keyLabel,
  hint,
  color,
  keyAccent = 'cyan',
}: Readonly<{
  keyLabel: string;
  hint: string;
  color: boolean;
  keyAccent?: AppAccent;
}>): ReactElement {
  return (
    <Text>
      <Text bold {...tint(color, keyAccent)}>
        {keyLabel}
      </Text>
      <Text dimColor {...tint(color, 'gray')}>
        {' '}
        {hint}
      </Text>
    </Text>
  );
}

/**
 * OpenTUI select-row: accent bar + label + hint with clear active highlight.
 * Active uses inverse / bright background; inactive is dim.
 */
export function SelectRow({
  active,
  label,
  hint,
  accent = 'cyan',
  color,
  ascii,
}: Readonly<{
  active: boolean;
  label: string;
  hint?: string;
  accent?: AppAccent;
  color: boolean;
  ascii: boolean;
}>): ReactElement {
  const pointer = pointerGlyph(ascii);
  const bar = active ? pointer : ' ';
  if (active) {
    return (
      <Text>
        <Text bold {...tint(color, accent)} inverse={color}>
          {` ${bar} ${safe(label, ascii)} `}
        </Text>
        {hint === undefined || hint.length === 0 ? null : (
          <Text dimColor {...tint(color, 'gray')}>
            {' '}
            {safe(hint, ascii)}
          </Text>
        )}
      </Text>
    );
  }
  return (
    <Text dimColor {...tint(color, 'gray')}>
      {` ${bar} ${safe(label, ascii)}`}
      {hint === undefined || hint.length === 0 ? null : (
        <Text dimColor {...tint(color, 'gray')}>
          {' '}
          {safe(hint, ascii)}
        </Text>
      )}
    </Text>
  );
}

/**
 * Centered modal/dialog frame — OpenTUI modal pattern (double border unicode,
 * classic ASCII). Used for passphrase / confirm overlays.
 */
export function ModalFrame({
  title,
  accent = 'yellow',
  ascii,
  color,
  width,
  children,
}: Readonly<{
  title: string;
  accent?: AppAccent;
  ascii: boolean;
  color: boolean;
  width: number;
  children: ReactNode;
}>): ReactElement {
  const modalWidth = Math.min(56, Math.max(36, width - 4));
  return (
    <Box
      width={width}
      justifyContent="center"
      alignItems="center"
      flexDirection="column"
      paddingY={1}
    >
      <Panel
        title={title}
        accent={accent}
        ascii={ascii}
        color={color}
        kind="modal"
        width={modalWidth}
        paddingX={2}
        paddingY={1}
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
  accent = 'green',
  color,
  ascii,
}: Readonly<{
  active: boolean;
  title: string;
  subtitle: string;
  accent?: AppAccent;
  color: boolean;
  ascii: boolean;
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
      <Text bold={active} {...tint(color, active ? accent : 'gray')}>
        {active ? pointer : ' '} {safe(title, ascii)}
      </Text>
      <Text {...tint(color, 'gray')}>
        {'   '}
        {safe(subtitle, ascii)}
      </Text>
    </Box>
  );
}
