import type { Command } from 'commander';

import { TUI_THEME_IDS } from './tui-theme.js';

/**
 * Registers `kavrix tui` / `kavrix ui`. Requires a real TTY on stdin and stdout;
 * non-interactive automation keeps using the numbered CLI commands.
 *
 * Light registration only: the heavy TUI session implementation is dynamically
 * imported at action time so every CLI invocation does not load it.
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
    .option('--no-mouse', 'Use keyboard navigation and native terminal selection.')
    .option(
      '--theme <id>',
      `TUI color theme: ${TUI_THEME_IDS.join(', ')} (also KAVRIX_TUI_THEME; saved from the TUI with t).`,
    )
    .option('--profile-config-dir <path>', 'Protected profile configuration directory.')
    .option('--config-dir <path>', 'Protected profile configuration directory.')
    .action(async (...args: unknown[]) => {
      const command = args.at(-1) as Command;
      const { runInteractiveTui } = await import('./tui-session.js');
      await runInteractiveTui(command.opts());
    });
}
