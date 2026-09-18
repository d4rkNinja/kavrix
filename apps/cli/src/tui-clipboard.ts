/**
 * Best-effort clipboard write for the interactive TUI.
 * Prefers OSC 52 (terminal clipboard) so remote/SSH sessions work without
 * native deps; falls back to common OS clipboard CLIs when OSC 52 is unavailable.
 */
import { spawn } from 'node:child_process';

const CLIPBOARD_CLEAR_MS = 30_000;
const OSC_CLEAR_TIMERS = new Set<ReturnType<typeof setTimeout>>();

/** Write UTF-8 text to the terminal clipboard via OSC 52. */
export function writeOsc52Clipboard(
  stdout: NodeJS.WriteStream,
  value: string,
): void {
  const payload = Buffer.from(value, 'utf8').toString('base64');
  stdout.write(`\x1b]52;c;${payload}\x07`);
}

/** Clear the terminal clipboard via OSC 52 (empty payload). */
export function clearOsc52Clipboard(stdout: NodeJS.WriteStream): void {
  stdout.write('\x1b]52;c;\x07');
}

function scheduleOsc52Clear(stdout: NodeJS.WriteStream, clearAfterMs: number): void {
  for (const timer of OSC_CLEAR_TIMERS) {
    clearTimeout(timer);
  }
  OSC_CLEAR_TIMERS.clear();
  const timer = setTimeout(() => {
    OSC_CLEAR_TIMERS.delete(timer);
    try {
      clearOsc52Clipboard(stdout);
    } catch {
      // Best-effort clear; ignore closed streams.
    }
  }, clearAfterMs);
  timer.unref?.();
  OSC_CLEAR_TIMERS.add(timer);
}

function runClipboardCommand(
  executable: string,
  args: readonly string[],
  stdin: string,
): Promise<void> {
  return new Promise((resolve, reject) => {
    const child = spawn(executable, [...args], {
      stdio: ['pipe', 'ignore', 'ignore'],
      env: process.env,
    });
    let settled = false;
    const fail = (error: Error): void => {
      if (settled) return;
      settled = true;
      reject(error);
    };
    child.on('error', fail);
    child.on('close', (code) => {
      if (settled) return;
      settled = true;
      if (code === 0) resolve();
      else reject(new Error(`${executable} exited ${String(code ?? 'null')}`));
    });
    child.stdin?.end(stdin, 'utf8');
  });
}

async function trySystemClipboard(value: string): Promise<void> {
  const platform = process.platform;
  if (platform === 'darwin') {
    await runClipboardCommand('pbcopy', [], value);
    return;
  }
  if (platform === 'win32') {
    await runClipboardCommand(
      'powershell.exe',
      [
        '-NoLogo',
        '-NoProfile',
        '-NonInteractive',
        '-Command',
        'Set-Clipboard -Value ([Console]::In.ReadToEnd())',
      ],
      value,
    );
    return;
  }
  // Linux: prefer wl-copy, then xclip, then xsel.
  const candidates: readonly (readonly [string, readonly string[]])[] = [
    ['wl-copy', ['--type', 'text/plain']],
    ['xclip', ['-selection', 'clipboard', '-in']],
    ['xsel', ['--clipboard', '--input']],
  ];
  let lastError: unknown;
  for (const [executable, args] of candidates) {
    try {
      await runClipboardCommand(executable, args, value);
      return;
    } catch (error) {
      lastError = error;
    }
  }
  throw lastError instanceof Error
    ? lastError
    : new Error('No system clipboard backend available.');
}

/**
 * Copy an already-authorized secret. Prefer OSC 52; fall back to OS clipboard
 * CLIs. Schedules a best-effort OSC 52 clear after ~30s when OSC is used.
 */
export async function copySecretToClipboard(
  value: string,
  options: Readonly<{
    stdout?: NodeJS.WriteStream;
    clearAfterMs?: number;
  }> = {},
): Promise<'osc52' | 'system'> {
  const clearAfterMs = options.clearAfterMs ?? CLIPBOARD_CLEAR_MS;
  const stdout = options.stdout ?? process.stdout;
  if (stdout.isTTY === true) {
    try {
      writeOsc52Clipboard(stdout, value);
      scheduleOsc52Clear(stdout, clearAfterMs);
      return 'osc52';
    } catch {
      // Fall through to system clipboard.
    }
  }

  await trySystemClipboard(value);
  // Best-effort delayed clear via OSC when a TTY appears later is skipped;
  // system clipboard managers vary — message still reports ~30s intent.
  return 'system';
}

export const TUI_CLIPBOARD_CLEAR_MS = CLIPBOARD_CLEAR_MS;
