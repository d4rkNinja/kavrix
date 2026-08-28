import { Command } from 'commander';

/**
 * The exact stdin frame contracts for every command that reads secrets.
 * Each entry lists the frames in order so automation authors never have to
 * guess; the same summaries appear in per-command `--help` descriptions.
 */
export const STDIN_FRAME_CONTRACTS: Readonly<Record<string, string>> = Object.freeze({
  init: 'passphrase, passphrase-confirm',
  put: 'passphrase, value',
  get: 'passphrase',
  list: 'passphrase',
  view: 'passphrase',
  search: 'passphrase',
  stats: 'passphrase',
  has: 'passphrase',
  remove: 'passphrase',
  rename: 'passphrase',
  doctor: 'passphrase',
  'doctor health': 'passphrase',
  'recovery create': 'key-passphrase, recovery-passphrase',
  'recovery verify': 'recovery-passphrase',
  'recovery use': 'recovery-passphrase, new-key-passphrase, new-key-passphrase-confirm',
  'recovery revoke': 'key-passphrase',
  'recovery status': '(none; reads no secrets)',
  'key copy|replicate|assign':
    'source-passphrase, new-passphrase, new-passphrase-confirm',
  'key rewrap': 'old-passphrase, new-passphrase, new-passphrase-confirm',
  'db init': '[mongodb-url,] label, passphrase, passphrase-confirm',
  'db status': '[mongodb-url,] passphrase',
  'db key status': '[mongodb-url,] passphrase',
  'db doctor health': '[mongodb-url,] passphrase',
  'db vault create': '[mongodb-url,] passphrase, label',
  'db vault list': '[mongodb-url,] passphrase',
  'db vault status': '[mongodb-url,] passphrase',
  'db vault rename': '[mongodb-url,] passphrase, label',
  'db key create':
    '[mongodb-url,] passphrase, share-passphrase, share-passphrase-confirm',
  'db recovery create':
    '[mongodb-url,] passphrase, rec-passphrase, rec-passphrase-confirm',
  'db recovery verify': '[mongodb-url,] passphrase, rec-passphrase',
  'db recovery status': '[mongodb-url,] passphrase',
  'db recovery revoke': '[mongodb-url,] passphrase',
  'db recovery use':
    'routing frames, then recovery-passphrase, new-passphrase, new-passphrase-confirm',
  'policy create': '[mongodb-url,] passphrase',
  'policy check': '[mongodb-url,] passphrase',
  'policy explain': '[mongodb-url,] passphrase',
  'policy lint': '[mongodb-url,] passphrase',
  'policy diff': '[mongodb-url,] passphrase',
  'policy suggest': '[mongodb-url,] passphrase',
  'policy list': '[mongodb-url,] passphrase',
  'policy show': '[mongodb-url,] passphrase',
  'policy remove': '[mongodb-url,] passphrase',
  grant: '[mongodb-url,] passphrase',
  'grant create': '[mongodb-url,] passphrase',
  'grant list': '[mongodb-url,] passphrase',
  'grant show': '[mongodb-url,] passphrase',
  'grant revoke': '[mongodb-url,] passphrase',
  audit: '[mongodb-url,] passphrase',
  'migrate database --secrets-stdin':
    'source-passphrase, destination-passphrase, migrated-vault-label',
  'migrate database --initialize --secrets-stdin (file destination)':
    'source-passphrase, expected-source-label, destination-passphrase, destination-passphrase-confirm, database-label, vault-label',
  destroy:
    'passphrase[, mongodb-url], "DESTROY <vaultId>", "DELETE REVISION <rev> <challenge>"',
});

/** Adds the exact frame contract to a command's help description. */
export function stdinFrameDescription(command: string, description: string): string {
  const frames = STDIN_FRAME_CONTRACTS[command];
  return frames === undefined ? description : `${description} Stdin frames: ${frames}.`;
}

/** Appends known stdin contracts to the corresponding command help text. */
export function applyStdinFrameHelp(program: Command): void {
  const visit = (command: Command, parents: readonly string[]): void => {
    const path = [...parents, command.name()].filter((part) => part !== program.name());
    const key = path.join(' ');
    const contractKey = Object.keys(STDIN_FRAME_CONTRACTS).find(
      (candidate) =>
        candidate === key || candidate.split(' | ').some((alias) => alias === key),
    );
    if (contractKey !== undefined) {
      command.description(stdinFrameDescription(contractKey, command.description()));
    }
    for (const child of command.commands) visit(child, path);
  };
  for (const command of program.commands) visit(command, []);
}

function renderAll(): string {
  const lines = [
    'Stdin frame contracts (--*-stdin flows read one frame per line):',
    '',
  ];
  for (const [command, frames] of Object.entries(STDIN_FRAME_CONTRACTS)) {
    lines.push(`  kavrix ${command}`);
    lines.push(`    ${frames}`);
  }
  lines.push(
    '',
    'Bracketed frames apply only to the MongoDB datastore. Labels and values are',
    'read as visible single-line frames; passphrases stay masked or framed exactly.',
    '',
  );
  return lines.join('\n');
}

/** Registers the `kavrix frames [command]` stdin-contract reference. */
export function registerFramesCommand(program: Command): void {
  const frames = program
    .command('frames [command]')
    .description('Show the exact stdin frame contract for secret-reading commands.');
  frames.showHelpAfterError(false);
  frames.action((...args: unknown[]) => {
    const command = args.at(-1);
    const requested =
      command instanceof Command
        ? command.args.find((value) => typeof value === 'string')
        : undefined;
    if (requested === undefined) {
      process.stdout.write(renderAll());
      return;
    }
    const key = Object.keys(STDIN_FRAME_CONTRACTS).find(
      (candidate) =>
        candidate === requested ||
        candidate.split(' | ').some((alias) => alias === requested),
    );
    const contract = key === undefined ? undefined : STDIN_FRAME_CONTRACTS[key];
    if (key === undefined || contract === undefined) {
      process.stderr.write(
        `No stdin frame contract is documented for '${requested}'. Run \`kavrix frames\` for every command.\n`,
      );
      process.exitCode = 2;
      return;
    }
    process.stdout.write(`kavrix ${key}\n  Frames: ${contract}\n`);
  });
}
