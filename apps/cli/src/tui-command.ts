import type { Command } from 'commander';

import { LocalCliError } from './cli-error.js';
import { createCliTuiBackend } from './tui-session.js';
import { terminalColorEnabled } from './terminal-presentation.js';

/**
 * Registers `kavrix tui` / `kavrix ui`. Requires a real TTY on stdin and stdout;
 * non-interactive automation keeps using the numbered CLI commands.
 */
export function registerTuiCommand(program: Command): void {
  program
    .command('tui')
    .alias('ui')
    .description(
      'Open the colorful interactive Kavrix TUI (requires a TTY). Secrets stay masked until an explicit REVEAL confirm.',
    )
    .option('--ascii', 'Force printable ASCII borders and glyphs.')
    .option('--color', 'Force color when the terminal supports it.')
    .option('--no-color', 'Disable ANSI color (also honors NO_COLOR).')
    .option('--profile-config-dir <path>', 'Protected profile configuration directory.')
    .option('--config-dir <path>', 'Protected profile configuration directory.')
    .action(async (...args: unknown[]) => {
      const command = args.at(-1) as Command;
      const options = command.opts() as {
        ascii?: boolean;
        color?: boolean;
        profileConfigDir?: string;
        configDir?: string;
      };
      await runInteractiveTui(options);
    });
}

export async function runInteractiveTui(
  options: Readonly<{
    ascii?: boolean;
    color?: boolean;
    profileConfigDir?: string;
    configDir?: string;
  }>,
): Promise<void> {
  if (process.stdin.isTTY !== true || process.stdout.isTTY !== true) {
    throw new LocalCliError(
      'kavrix tui requires an interactive TTY on stdin and stdout. Use numbered CLI commands for automation.',
    );
  }

  const noColorFlag =
    process.env['NO_COLOR'] !== undefined ||
    process.argv.includes('--no-color') ||
    options.color === false;
  const color =
    options.color === true
      ? true
      : noColorFlag
        ? false
        : terminalColorEnabled(process.stdout);
  const ascii =
    options.ascii === true ||
    process.platform === 'win32' ||
    process.env['TERM'] === 'dumb' ||
    process.env['TERM'] === undefined;

  const profileConfigDir = options.profileConfigDir ?? options.configDir;
  const backend = createCliTuiBackend({
    ascii,
    ...(profileConfigDir === undefined ? {} : { profileConfigDir }),
  });

  // Lazy-load Ink/React only for the interactive path (same pattern as showcase).
  const tui = await import('@kavrix/tui');
  const handle = tui.mountKavrixApp({
    backend,
    stdout: process.stdout,
    stdin: process.stdin,
    ascii,
    color,
  });
  try {
    await handle.waitUntilExit();
  } finally {
    handle.unmount();
  }
}
