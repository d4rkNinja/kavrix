import { Box, Text, render } from 'ink';
import type { ReactElement } from 'react';

import type { StorageSelectionShowcaseProps } from './contracts.js';
import { MOTION, resolveMotionPolicy, useMotionFrame } from './motion.js';
import { sanitizeTerminalText } from './terminal-text.js';
import { accentColor, CHROME, panelBorderStyle, pointerGlyph } from './app/theme.js';

const SPINNER_FRAMES = [
  '\u280b',
  '\u2819',
  '\u2839',
  '\u2838',
  '\u283c',
  '\u2834',
  '\u2826',
  '\u2827',
  '\u2807',
  '\u2817',
] as const;
const ASCII_SPINNER_FRAMES = ['|', '/', '-', '\\'] as const;

export interface MountStorageShowcaseOptions {
  readonly stdout: NodeJS.WriteStream;
  readonly color?: boolean;
  readonly ascii?: boolean;
}

export interface StorageShowcaseHandle {
  select: (selected: StorageSelectionShowcaseProps['selected']) => void;
  end: () => Promise<void>;
}

/**
 * Animated, colorful storage-selection frame for interactive `kavrix init`.
 * Purely presentational: every rendered string is a static constant, and the
 * caller owns input parsing, raw mode, and outcome resolution.
 */
export function StorageSelectionShowcase({
  selected,
  color = false,
  ascii = false,
}: StorageSelectionShowcaseProps): ReactElement {
  const motion = resolveMotionPolicy();
  const frame = useMotionFrame(motion.animate, MOTION.pulseMs);
  const spinnerFrames = ascii ? ASCII_SPINNER_FRAMES : SPINNER_FRAMES;
  const spinner = spinnerFrames[frame % spinnerFrames.length] ?? '|';
  const pointer = pointerGlyph(ascii);
  const upKey = ascii ? 'Up' : '\u2191';
  const downKey = ascii ? 'Down' : '\u2193';
  const options = [
    {
      id: 'file' as const,
      title: 'Local encrypted file',
      description: 'Simplest choice for one device; ciphertext stays beside you.',
    },
    {
      id: 'mongodb' as const,
      title: 'MongoDB',
      description: 'Sync opaque ciphertext through your own MongoDB deployment.',
    },
  ];

  return (
    <Box flexDirection="column" gap={1}>
      <BrandBanner color={color} ascii={ascii} dualTone />
      <Text bold {...accentColor(color, CHROME.accent)}>
        STEP 2 / STORAGE
      </Text>
      <Text>
        Both choices preserve client-side encryption. The datastore never receives a
        vault key.
      </Text>
      <Box
        flexDirection="column"
        borderStyle={panelBorderStyle(ascii, 'panel')}
        {...(color ? { borderColor: CHROME.accent } : {})}
        paddingX={1}
      >
        {options.map((option) => {
          const active = option.id === selected;
          if (active) {
            return (
              <Box key={option.id} flexDirection="column">
                <Text bold {...accentColor(color, CHROME.accent)} inverse={color}>
                  {` ${pointer} ${option.title} `}
                </Text>
                <Text {...accentColor(color, CHROME.heading)}>
                  {'  '}
                  {option.description}
                </Text>
              </Box>
            );
          }
          return (
            <Box key={option.id} flexDirection="column">
              <Text dimColor {...accentColor(color, CHROME.muted)}>
                {' '}
                {option.title}
              </Text>
              <Text {...accentColor(color, CHROME.muted)}>
                {'  '}
                {option.description}
              </Text>
            </Box>
          );
        })}
      </Box>
      <Text>
        <Text {...accentColor(color, CHROME.accent)}>{spinner}</Text>{' '}
        {`${upKey}/${downKey} navigate`} <Text bold>Enter</Text> confirm{' '}
        <Text bold>Esc</Text> back <Text bold>Ctrl+C</Text> cancel
      </Text>
    </Box>
  );
}

/**
 * Dual-tone brandmark: KAV in ivory, RIX in gold. Letter order stays stable.
 * A quiet pulse mark keeps interactive frames alive without rainbow cycling.
 */
export function BrandBanner({
  color = false,
  ascii = false,
  dualTone = false,
}: Readonly<{ color?: boolean; ascii?: boolean; dualTone?: boolean }>): ReactElement {
  const motion = resolveMotionPolicy();
  const frame = useMotionFrame(motion.animate, MOTION.pulseMs);
  const title = sanitizeTerminalText('Kavrix', ascii).toUpperCase();
  const kav = title.slice(0, 3);
  const rix = title.slice(3);
  const pulse = motion.animate && frame % 2 === 0;
  const mark = ascii ? (pulse ? '.' : ' ') : pulse ? '\u00b7' : ' ';
  return (
    <Box flexDirection="column">
      <Box flexDirection="row" columnGap={2}>
        <Text bold>
          {dualTone ? (
            <>
              <Text {...accentColor(color, CHROME.heading)}>{kav}</Text>
              <Text {...accentColor(color, CHROME.accent)}>{rix}</Text>
            </>
          ) : (
            <Text {...accentColor(color, CHROME.accent)}>{title}</Text>
          )}
        </Text>
        <Text {...accentColor(color, CHROME.muted)}>local-first secrets firewall</Text>
        <Text {...accentColor(color, CHROME.accent)}>{mark}</Text>
      </Box>
    </Box>
  );
}

/**
 * Mounts the showcase on an already-validated TTY stream. The CLI keeps full
 * ownership of stdin parsing and raw mode; this bridge only paints frames and
 * guarantees a bounded teardown.
 */
export function mountStorageSelectionShowcase(
  options: MountStorageShowcaseOptions,
): StorageShowcaseHandle {
  const color = options.color ?? true;
  const ascii = options.ascii ?? false;
  let currentSelected: StorageSelectionShowcaseProps['selected'] = 'file';
  const instance = render(
    <StorageSelectionShowcase selected={currentSelected} color={color} ascii={ascii} />,
    {
      stdout: options.stdout,
      interactive: true,
      exitOnCtrlC: false,
      patchConsole: false,
    },
  );
  return {
    select(selected): void {
      currentSelected = selected;
      instance.rerender(
        <StorageSelectionShowcase
          selected={currentSelected}
          color={color}
          ascii={ascii}
        />,
      );
    },
    async end(): Promise<void> {
      instance.unmount();
      await instance.waitUntilExit();
    },
  };
}
