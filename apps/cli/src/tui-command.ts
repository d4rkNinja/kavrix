import type { Command } from 'commander';

import { LocalCliError } from './cli-error.js';
import { resolveProfileConfigDirectory } from './profile-config-directory.js';
import { createCliTuiBackend, isTuiThemeId, TUI_THEME_IDS } from './tui-session.js';
import { terminalColorEnabled } from './terminal-presentation.js';
import { CLI_VERSION } from './version.js';

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
    .option('--no-splash', 'Skip the animated startup splash screen.')
    .option(
      '--theme <id>',
      `TUI color theme: ${TUI_THEME_IDS.join(', ')} (also KAVRIX_TUI_THEME; saved from the TUI with t).`,
    )
    .option('--profile-config-dir <path>', 'Protected profile configuration directory.')
    .option('--config-dir <path>', 'Protected profile configuration directory.')
    .action(async (...args: unknown[]) => {
      const command = args.at(-1) as Command;
      const options = command.opts();
      await runInteractiveTui(options);
    });
}

export async function runInteractiveTui(
  options: Readonly<{
    ascii?: boolean;
    color?: boolean;
    splash?: boolean;
    theme?: string;
    profileConfigDir?: string;
    configDir?: string;
  }>,
): Promise<void> {
  const themeSource = options.theme ?? process.env['KAVRIX_TUI_THEME'];
  if (themeSource !== undefined && !isTuiThemeId(themeSource)) {
    throw new LocalCliError(
      `Unknown theme "${themeSource}". Choose one of: ${TUI_THEME_IDS.join(', ')}.`,
    );
  }
  if (!process.stdin.isTTY || !process.stdout.isTTY) {
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
  const noSplash =
    options.splash === false ||
    process.env['KAVRIX_TUI_NO_SPLASH'] === '1' ||
    process.env['KAVRIX_TUI_NO_SPLASH'] === 'true';

  const profileConfigDir = resolveProfileConfigDirectory(
    options.profileConfigDir,
    options.configDir,
  );
  if (themeSource !== undefined) {
    // Apply before mount so the splash and first paint already use the theme.
    const tuiTheme = (await import('@kavrix/tui')) as unknown as {
      applyTuiTheme: (id: (typeof TUI_THEME_IDS)[number]) => void;
    };
    tuiTheme.applyTuiTheme(themeSource);
  }
  const backend = createCliTuiBackend({
    ascii,
    ...(themeSource === undefined ? {} : { theme: themeSource }),
    ...(profileConfigDir === undefined ? {} : { profileConfigDir }),
  });

  // Lazy-load Ink/React only for the interactive path (same pattern as showcase).
  const tui = (await import('@kavrix/tui')) as unknown as {
    mountKavrixApp: (options: {
      backend: ReturnType<typeof createCliTuiBackend>;
      stdout: NodeJS.WriteStream;
      stdin: NodeJS.ReadStream;
      ascii?: boolean;
      color?: boolean;
      version?: string;
      noSplash?: boolean;
    }) => {
      waitUntilExit: () => Promise<void>;
      unmount: () => void;
    };
  };
  const handle = tui.mountKavrixApp({
    backend,
    stdout: process.stdout,
    stdin: process.stdin,
    ascii,
    color,
    version: CLI_VERSION,
    ...(noSplash ? { noSplash: true } : {}),
  });
  try {
    await handle.waitUntilExit();
  } finally {
    handle.unmount();
  }
}
