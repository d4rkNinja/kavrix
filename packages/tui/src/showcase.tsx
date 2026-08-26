import { Box, Text, render } from 'ink';
import { useEffect, useState, type ReactElement } from 'react';

import type { StorageSelectionShowcaseProps } from './contracts.js';
import { sanitizeTerminalText } from './terminal-text.js';

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
];
const ASCII_SPINNER_FRAMES = ['|', '/', '-', '\\'];
const ACCENT_CYCLE = ['cyan', 'magenta', 'blue', 'green'] as const;
type Accent = (typeof ACCENT_CYCLE)[number] | 'gray' | 'yellow';
const ANIMATION_INTERVAL_MS = 120;

export interface MountStorageShowcaseOptions {
  readonly stdout: NodeJS.WriteStream;
  readonly color?: boolean;
  readonly ascii?: boolean;
}

export interface StorageShowcaseHandle {
  select: (selected: StorageSelectionShowcaseProps['selected']) => void;
  end: () => Promise<void>;
}

function useShowcaseFrame(): number {
  const [frame, setFrame] = useState(0);
  useEffect(() => {
    const interval = setInterval(() => {
      setFrame((value) => value + 1);
    }, ANIMATION_INTERVAL_MS);
    return () => {
      clearInterval(interval);
    };
  }, []);
  return frame;
}

function tint(
  enabled: boolean,
  accent: Accent,
): Readonly<{ color: Accent }> | Readonly<Record<string, never>> {
  return enabled ? { color: accent } : {};
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
  const frame = useShowcaseFrame();
  const accent = ACCENT_CYCLE[frame % ACCENT_CYCLE.length] ?? 'cyan';
  const spinnerFrames = ascii ? ASCII_SPINNER_FRAMES : SPINNER_FRAMES;
  const spinner = spinnerFrames[frame % spinnerFrames.length];
  const pointer = ascii ? '>' : '\u276f';
  const upKey = ascii ? 'Up' : '\u2191';
  const downKey = ascii ? 'Down' : '\u2193';
  const options = [
    {
      id: 'file' as const,
      title: 'Local encrypted file',
      description: 'Simplest choice for one device; ciphertext stays beside you.',
      tint: 'green' as const,
    },
    {
      id: 'mongodb' as const,
      title: 'MongoDB',
      description: 'Sync opaque ciphertext through your own MongoDB deployment.',
      tint: 'yellow' as const,
    },
  ];

  return (
    <Box flexDirection="column" gap={1}>
      <BrandBanner color={color} ascii={ascii} />
      <Text bold {...(color ? { color: 'cyan' as const } : {})}>
        STEP 2 / STORAGE
      </Text>
      <Text>
        Both choices preserve client-side encryption. The datastore never receives a
        vault key.
      </Text>
      <Box flexDirection="column">
        {options.map((option) => {
          const active = option.id === selected;
          return (
            <Box key={option.id} flexDirection="column">
              <Text bold={active} {...tint(color, active ? accent : 'gray')}>
                {active ? pointer : ' '} {option.title}
              </Text>
              <Text {...tint(color, active ? option.tint : 'gray')}>
                {'  '}
                {option.description}
              </Text>
            </Box>
          );
        })}
      </Box>
      <Text>
        <Text {...tint(color, accent)}>{spinner}</Text> {`${upKey}/${downKey} navigate`}{' '}
        <Text bold>Enter</Text> confirm <Text bold>Esc</Text> back{' '}
        <Text bold>Ctrl+C</Text> cancel
      </Text>
    </Box>
  );
}

/**
 * Color-cycling brandmark shown while an interactive showcase is open. Letter
 * order stays stable so snapshots and screen readers remain deterministic.
 */
export function BrandBanner({
  color = false,
  ascii = false,
}: Readonly<{ color?: boolean; ascii?: boolean }>): ReactElement {
  const frame = useShowcaseFrame();
  const title = sanitizeTerminalText('Kavrix', ascii).toUpperCase();
  return (
    <Box flexDirection="row" columnGap={2}>
      <Text bold>
        {Array.from(title).map((letter, index) => (
          <Text
            key={`${letter}-${String(index)}`}
            {...tint(
              color,
              ACCENT_CYCLE[(frame + index) % ACCENT_CYCLE.length] ?? 'cyan',
            )}
          >
            {letter}
          </Text>
        ))}
      </Text>
      <Text {...tint(color, 'gray')}>zero-knowledge credential vault</Text>
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
