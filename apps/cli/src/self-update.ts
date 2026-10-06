/**
 * `kavrix update` — check the npm registry for a newer `kavrix` release and,
 * for global npm installs only, replace the installed package.
 *
 * Fail-closed for Homebrew, pnpm, yarn, npx, and workspace/dev checkouts.
 * `--check` never installs. Successful checks and check-mode query failures exit 0;
 * pair with `--json` for automation (JSON is always emitted when `--json` is set).
 *
 * Registration is intentionally light; the implementation lives in
 * `self-update-impl.ts` and is imported only when the command runs.
 */
import type { Command } from 'commander';

import type { SelfUpdateOptions } from './self-update-impl.js';

export const DEFAULT_DIST_TAG = 'latest';
export const NODE_ENGINES = '>=24.12.0 <25 || >=25.1.0';

const HELP_DESCRIPTION =
  'Upgrade a global npm install of kavrix from the npm registry. Supports only `npm install -g kavrix` layouts. Homebrew, pnpm, yarn, npx, and workspace/dev checkouts are not supported — upgrade through that package manager or reinstall with npm. Requires Node.js ' +
  NODE_ENGINES +
  '.';

/** Register `kavrix update` on the root program. */
export function registerSelfUpdateCommand(program: Command): void {
  program
    .command('update')
    .description(HELP_DESCRIPTION)
    .option(
      '--check',
      'Report whether a newer release is available without installing (exits 0 on success and on check-mode query failures; use --json for automation).',
    )
    .option(
      '--json',
      'Emit machine-readable JSON ({ installed, latest, updateAvailable, channel, action, error? }); always emitted when set, including failures.',
    )
    .option('--tag <dist-tag>', 'npm dist-tag to follow.', DEFAULT_DIST_TAG)
    .option(
      '--registry <url>',
      'https npm registry URL (http only for localhost; no credentials in URL).',
    )
    .addHelpText(
      'after',
      `
Notes:
  Package name on npm is \`kavrix\`. Only global npm installs are upgraded in place.
  Unsupported: Homebrew, pnpm, yarn, npx, and workspace/dev checkouts.
  On EACCES, set a user prefix: \`npm config set prefix ~/.local\` and put \`~/.local/bin\` on PATH.
  Node.js engines: ${NODE_ENGINES}.
`,
    )
    .action(async (...args: unknown[]) => {
      const command = args.at(-1) as Command;
      const options: SelfUpdateOptions = command.opts();
      // --check never mutates; query failures under --check exit 0 after JSON/status.
      const impl = await import('./self-update-impl.js');
      await impl.executeSelfUpdate(options);
    });
}
