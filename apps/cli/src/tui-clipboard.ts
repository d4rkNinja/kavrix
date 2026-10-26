/**
 * Best-effort clipboard write for the interactive TUI.
 * Prefers OSC 52 (terminal clipboard) so remote/SSH sessions work without
 * native deps; falls back to common OS clipboard CLIs when OSC 52 is unavailable.
 */
import { spawn } from 'node:child_process';

const CLIPBOARD_CLEAR_MS = 30_000;
const CLIPBOARD_COMMAND_TIMEOUT_MS = 5_000;
// Terminals routinely cap OSC 52 payloads (many well below this bound) and
// silently drop or truncate oversized sequences. Above this base64-payload
// bound the copy is refused with a clear error instead of writing a sequence
// the terminal may only partially apply, which would leave a truncated secret
// resident with no way to clear it.
export const MAX_OSC52_PAYLOAD_CHARS = 64 * 1024;

/**
 * The one still-resident terminal copy. A newer copy evicts it immediately
 * (clear written before the new payload) so at most one secret is ever
 * resident, no matter how quickly copies follow each other.
 */
let pendingOsc52Clear:
  | Readonly<{ stdout: NodeJS.WriteStream; timer: ReturnType<typeof setTimeout> }>
  | undefined;

export function clipboardCopyNotice(backend: 'osc52' | 'system'): string {
  return backend === 'osc52'
    ? 'Copied via terminal clipboard escape; best-effort clear scheduled in ~30s while Kavrix stays open.'
    : 'Copied via system clipboard; automatic clearing is unavailable. Clear it manually after use.';
}

/** Write UTF-8 text to the terminal clipboard via OSC 52. */
export function writeOsc52Clipboard(stdout: NodeJS.WriteStream, value: string): void {
  const payload = Buffer.from(value, 'utf8').toString('base64');
  stdout.write(`\x1b]52;c;${payload}\x07`);
}

/** Clear the terminal clipboard via OSC 52 (empty payload). */
export function clearOsc52Clipboard(stdout: NodeJS.WriteStream): void {
  stdout.write('\x1b]52;c;\x07');
}

/** Evicts the previous terminal copy immediately, before a new one lands. */
function clearPendingOsc52Copy(): void {
  const pending = pendingOsc52Clear;
  pendingOsc52Clear = undefined;
  if (pending === undefined) return;
  clearTimeout(pending.timer);
  try {
    clearOsc52Clipboard(pending.stdout);
  } catch {
    // Best-effort clear; ignore closed streams.
  }
}

function scheduleOsc52Clear(stdout: NodeJS.WriteStream, clearAfterMs: number): void {
  const timer = setTimeout(() => {
    if (pendingOsc52Clear?.timer === timer) pendingOsc52Clear = undefined;
    try {
      clearOsc52Clipboard(stdout);
    } catch {
      // Best-effort clear; ignore closed streams.
    }
  }, clearAfterMs);
  timer.unref();
  pendingOsc52Clear = { stdout, timer };
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
      shell: false,
      windowsHide: true,
    });
    let settled = false;
    const timeout = setTimeout(() => {
      fail(new Error(`${executable} timed out`));
    }, CLIPBOARD_COMMAND_TIMEOUT_MS);
    const fail = (error: Error): void => {
      if (settled) return;
      settled = true;
      clearTimeout(timeout);
      child.stdin.destroy();
      child.kill('SIGKILL');
      reject(error);
    };
    child.on('error', () => {
      fail(new Error(`${executable} is unavailable`));
    });
    child.stdin.on('error', () => {
      fail(new Error(`${executable} input failed`));
    });
    child.on('close', (code) => {
      if (settled) return;
      settled = true;
      clearTimeout(timeout);
      if (code === 0) resolve();
      else reject(new Error(`${executable} exited ${String(code ?? 'null')}`));
    });
    try {
      child.stdin.end(stdin, 'utf8');
    } catch {
      fail(new Error(`${executable} input failed`));
    }
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
        '[Console]::InputEncoding = [System.Text.UTF8Encoding]::new($false); Set-Clipboard -Value ([Console]::In.ReadToEnd())',
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
  const detail =
    lastError instanceof Error ? lastError.message : 'no clipboard CLI responded';
  throw new Error(
    `No clipboard backend available (TTY OSC 52 unavailable; tried wl-copy/xclip/xsel). ${detail}`,
  );
}

/**
 * Copy an already-authorized secret. Prefer OSC 52; fall back to OS clipboard
 * CLIs. A still-resident previous terminal copy is cleared immediately before
 * the new payload, and a best-effort OSC 52 clear is scheduled after ~30s.
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
  if (stdout.isTTY) {
    // The cap is checked outside the fallback try: an oversized value must
    // fail honestly with its own diagnosis instead of silently degrading to a
    // system backend (or to a truncated escape sequence).
    const payload = Buffer.from(value, 'utf8').toString('base64');
    if (payload.length > MAX_OSC52_PAYLOAD_CHARS) {
      throw new Error(
        `The value exceeds the terminal clipboard escape size cap (${String(MAX_OSC52_PAYLOAD_CHARS)} base64 characters); refusing to write a sequence terminals may truncate.`,
      );
    }
    try {
      clearPendingOsc52Copy();
      stdout.write(`\x1b]52;c;${payload}\x07`);
      scheduleOsc52Clear(stdout, clearAfterMs);
      return 'osc52';
    } catch {
      // Fall through to system clipboard.
    }
  }

  await trySystemClipboard(value);
  // Native clipboard clearing is unavailable here; callers must report that
  // limitation instead of promising the terminal timer for this backend.
  return 'system';
}

export const TUI_CLIPBOARD_CLEAR_MS = CLIPBOARD_CLEAR_MS;
