import { posix, win32 } from 'node:path';

import { ClipboardError } from './errors.js';
import {
  MAX_CLIPBOARD_BYTES,
  type ClipboardCommand,
  type ClipboardRuntime,
} from './types.js';

const COMMAND_TIMEOUT_MS = 5_000;
const MAX_STDERR_BYTES = 16 * 1024;
const WINDOWS_ROOT = 'C:\\Windows';
const WINDOWS_POWERSHELL = win32.join(
  WINDOWS_ROOT,
  'System32',
  'WindowsPowerShell',
  'v1.0',
  'powershell.exe',
);

export interface ClipboardBackend {
  readonly name:
    | 'macos-pbcopy'
    | 'wayland-wl-clipboard'
    | 'windows-powershell'
    | 'x11-xclip'
    | 'x11-xsel';
  write(value: Uint8Array, signal?: AbortSignal): Promise<void>;
  read(signal?: AbortSignal): Promise<Uint8Array>;
  clear(signal?: AbortSignal): Promise<void>;
}

export async function detectClipboardBackend(
  runtime: ClipboardRuntime,
): Promise<ClipboardBackend> {
  switch (runtime.platform) {
    case 'win32':
      return detectWindows(runtime);
    case 'darwin':
      return detectMacOs(runtime);
    case 'linux':
      return detectLinux(runtime);
    default:
      throw unavailable();
  }
}

async function detectWindows(runtime: ClipboardRuntime): Promise<ClipboardBackend> {
  const executable = await runtime.executables.resolve('powershell.exe', [
    WINDOWS_POWERSHELL,
  ]);
  if (executable === null) throw unavailable();
  const environment = { SystemRoot: WINDOWS_ROOT };
  const prefix = ['-NoLogo', '-NoProfile', '-NonInteractive', '-Sta', '-Command'];
  const setup =
    '$utf8=New-Object System.Text.UTF8Encoding($false,$true);' +
    '[Console]::InputEncoding=$utf8;[Console]::OutputEncoding=$utf8;' +
    'Add-Type -AssemblyName System.Windows.Forms;';
  return commandBackend(
    'windows-powershell',
    runtime,
    {
      executable,
      args: [
        ...prefix,
        `${setup}[Windows.Forms.Clipboard]::SetText([Console]::In.ReadToEnd())`,
      ],
      environment,
    },
    {
      executable,
      args: [
        ...prefix,
        `${setup}[Console]::Out.Write([Windows.Forms.Clipboard]::GetText())`,
      ],
      environment,
    },
    {
      executable,
      args: [...prefix, `${setup}[Windows.Forms.Clipboard]::Clear()`],
      environment,
    },
  );
}

async function detectMacOs(runtime: ClipboardRuntime): Promise<ClipboardBackend> {
  const pbcopy = await runtime.executables.resolve('pbcopy', ['/usr/bin/pbcopy']);
  const pbpaste = await runtime.executables.resolve('pbpaste', ['/usr/bin/pbpaste']);
  if (pbcopy === null || pbpaste === null) throw unavailable();
  const environment = safeEnvironment(runtime.environment, [
    'LANG',
    'LC_ALL',
    'LC_CTYPE',
    'TMPDIR',
  ]);
  return commandBackend(
    'macos-pbcopy',
    runtime,
    { executable: pbcopy, args: [], environment },
    { executable: pbpaste, args: [], environment },
    { executable: pbcopy, args: [], environment },
  );
}

async function detectLinux(runtime: ClipboardRuntime): Promise<ClipboardBackend> {
  const candidates = executableCandidates();
  const environment = safeEnvironment(runtime.environment, [
    'DISPLAY',
    'LANG',
    'LC_ALL',
    'LC_CTYPE',
    'WAYLAND_DISPLAY',
    'XDG_RUNTIME_DIR',
  ]);
  if (
    hasValue(runtime.environment['WAYLAND_DISPLAY']) &&
    hasValue(runtime.environment['XDG_RUNTIME_DIR'])
  ) {
    const copy = await runtime.executables.resolve('wl-copy', candidates('wl-copy'));
    const paste = await runtime.executables.resolve('wl-paste', candidates('wl-paste'));
    if (copy !== null && paste !== null) {
      return commandBackend(
        'wayland-wl-clipboard',
        runtime,
        { executable: copy, args: ['--type', 'text/plain'], environment },
        { executable: paste, args: ['--no-newline'], environment },
        { executable: copy, args: ['--clear'], environment },
      );
    }
  }
  if (hasValue(runtime.environment['DISPLAY'])) {
    const xclip = await runtime.executables.resolve('xclip', candidates('xclip'));
    if (xclip !== null) {
      return commandBackend(
        'x11-xclip',
        runtime,
        { executable: xclip, args: ['-selection', 'clipboard', '-in'], environment },
        { executable: xclip, args: ['-selection', 'clipboard', '-out'], environment },
        { executable: xclip, args: ['-selection', 'clipboard', '-in'], environment },
      );
    }
    const xsel = await runtime.executables.resolve('xsel', candidates('xsel'));
    if (xsel !== null) {
      return commandBackend(
        'x11-xsel',
        runtime,
        { executable: xsel, args: ['--clipboard', '--input'], environment },
        { executable: xsel, args: ['--clipboard', '--output'], environment },
        { executable: xsel, args: ['--clipboard', '--clear'], environment },
      );
    }
  }
  throw unavailable();
}

function commandBackend(
  name: ClipboardBackend['name'],
  runtime: ClipboardRuntime,
  write: CommandTemplate,
  read: CommandTemplate,
  clear: CommandTemplate,
): ClipboardBackend {
  return {
    name,
    async write(value, signal): Promise<void> {
      const result = await runtime.commands.run(command(write, signal, value, 0));
      result.stdout.fill(0);
    },
    async read(signal): Promise<Uint8Array> {
      const result = await runtime.commands.run(
        command(read, signal, undefined, MAX_CLIPBOARD_BYTES),
      );
      return result.stdout;
    },
    async clear(signal): Promise<void> {
      const result = await runtime.commands.run(
        command(clear, signal, new Uint8Array(), 0),
      );
      result.stdout.fill(0);
    },
  };
}

interface CommandTemplate {
  readonly executable: string;
  readonly args: readonly string[];
  readonly environment: Readonly<Record<string, string>>;
}

function command(
  template: CommandTemplate,
  signal: AbortSignal | undefined,
  stdin: Uint8Array | undefined,
  maxStdoutBytes: number,
): ClipboardCommand {
  return {
    executable: template.executable,
    args: template.args,
    environment: template.environment,
    ...(stdin === undefined ? {} : { stdin }),
    timeoutMs: COMMAND_TIMEOUT_MS,
    maxStdoutBytes,
    maxStderrBytes: MAX_STDERR_BYTES,
    ...(signal === undefined ? {} : { signal }),
  };
}

function executableCandidates() {
  const directories = ['/usr/local/bin', '/usr/bin', '/bin'];
  return (name: string): string[] =>
    directories.map((directory) => posix.join(directory, name));
}

function safeEnvironment(
  source: Readonly<Record<string, string | undefined>>,
  allowed: readonly string[],
): Readonly<Record<string, string>> {
  const result: Record<string, string> = {};
  for (const key of allowed) {
    const value = source[key];
    if (value === undefined || value.length === 0) continue;
    if (value.length > 4_096 || value.includes('\0')) {
      throw new ClipboardError(
        'CLIPBOARD_VALIDATION_FAILED',
        'Clipboard environment is invalid.',
      );
    }
    result[key] = value;
  }
  return result;
}

function hasValue(value: string | undefined): value is string {
  return value !== undefined && value.length > 0;
}

function unavailable(): ClipboardError {
  return new ClipboardError(
    'CLIPBOARD_UNAVAILABLE',
    'No supported system clipboard is available.',
  );
}
