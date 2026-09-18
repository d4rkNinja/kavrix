import { LocalCliError } from './cli-error.js';
import { terminalColorEnabled } from './terminal-presentation.js';
import { createCliTuiBackend } from './tui-session.js';
import { CLI_VERSION } from './version.js';

export type InitTuiOnboardingOptions = Readonly<{
  ascii?: boolean;
  color?: boolean;
  /** Commander `--no-splash` sets `splash: false`. */
  splash?: boolean;
  profileConfigDir?: string;
  configDir?: string;
}>;

export type InitTuiOnboardingResult =
  | Readonly<{
      status: 'completed';
      profileId: string;
      datastore: 'file' | 'mongodb';
      recoveryFile?: string;
    }>
  | Readonly<{ status: 'cancelled' }>
  | Readonly<{ status: 'failed'; message: string }>;

/**
 * Opens Ink TUI onboarding for interactive `kavrix init`.
 * Uses real `createCliTuiBackend` create-file-profile / create-mongodb-profile
 * with recovery create + verify when the wizard collects a recovery kit.
 */
export async function runInitTuiOnboarding(
  options: InitTuiOnboardingOptions = {},
): Promise<InitTuiOnboardingResult> {
  if (!process.stdin.isTTY || !process.stdout.isTTY || !process.stderr.isTTY) {
    throw new LocalCliError(
      'kavrix init TUI requires an interactive TTY on stdin, stdout, and stderr. Pass --no-tui for classic prompts.',
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

  const profileConfigDir = options.profileConfigDir ?? options.configDir;
  const backend = createCliTuiBackend({
    ascii,
    ...(profileConfigDir === undefined ? {} : { profileConfigDir }),
  });

  // Lazy-load Ink/React; cast like storage showcase so lint works before dist.
  const tui = (await import('@kavrix/tui')) as unknown as {
    mountOnboardingApp: (options: {
      backend: ReturnType<typeof createCliTuiBackend>;
      stdout: NodeJS.WriteStream;
      stdin: NodeJS.ReadStream;
      ascii?: boolean;
      color?: boolean;
      version?: string;
      noSplash?: boolean;
    }) => {
      waitUntilExit: () => Promise<InitTuiOnboardingResult>;
      unmount: () => void;
    };
  };
  const handle = tui.mountOnboardingApp({
    backend,
    stdout: process.stdout,
    stdin: process.stdin,
    ascii,
    color,
    version: CLI_VERSION,
    ...(noSplash ? { noSplash: true } : {}),
  });
  try {
    return await handle.waitUntilExit();
  } finally {
    handle.unmount();
  }
}

export function writeInitTuiOnboardingComplete(
  options: Readonly<{
    write: (text: string) => void;
    profileId: string;
    datastore: 'file' | 'mongodb';
    recoveryFile?: string;
    color?: boolean;
  }>,
): void {
  const color = options.color === true;
  const bold = color ? '\u001b[1m' : '';
  const green = color ? '\u001b[32m' : '';
  const reset = color ? '\u001b[0m' : '';
  const profileId = options.profileId.replace(/[^\w.-]/gu, '');
  const recoveryFile =
    typeof options.recoveryFile === 'string' && options.recoveryFile.length > 0
      ? options.recoveryFile.replace(/[\0\r\n]/gu, '')
      : null;
  const lines = [
    '',
    `${bold}${green}SETUP COMPLETE${reset}`,
    '',
    `${green}[OK]${reset} ${
      options.datastore === 'mongodb' ? 'MongoDB' : 'Local file'
    } profile initialized via TUI onboarding.`,
    `${green}[OK]${reset} Default vault created and selected.`,
    `${green}[OK]${reset} Recovery kit created and verified locally.`,
    `${green}[OK]${reset} Protected datastore profile selected: ${profileId}`,
  ];
  if (recoveryFile !== null) {
    lines.push(`${green}[OK]${reset} Recovery kit path: ${recoveryFile}`);
  }
  lines.push(
    '',
    'Try:',
    `  kavrix tui`,
    `  kavrix put <name> --profile ${profileId}`,
    `  kavrix list --profile ${profileId}`,
    '',
    'Keep the owner key and recovery kit in separate secure locations.',
    'Tip: pass --no-tui next time for classic line prompts.',
    '',
  );
  options.write(lines.join('\n'));
}
