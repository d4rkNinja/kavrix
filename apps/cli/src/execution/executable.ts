import { createHash } from 'node:crypto';
import { createReadStream } from 'node:fs';
import { lstat, realpath, stat } from 'node:fs/promises';
import { basename, delimiter, isAbsolute, join, resolve } from 'node:path';
const MAX_EXECUTABLE_BYTES = 512 * 1024 * 1024;
const WINDOWS_SCRIPT_EXTENSIONS = new Set(['.bat', '.cmd', '.com']);
const WINDOWS_STRIP_EXTENSIONS = new Set(['.exe', '.bat', '.cmd', '.com']);
const DEFAULT_PATHEXT = '.COM;.EXE;.BAT;.CMD';

export type ResolutionStatus =
  | Readonly<{
      status: 'resolved';
      request: string;
      displayName: string;
      absolutePath: string;
      sha256: string;
    }>
  | Readonly<{ status: 'unresolved'; request: string }>
  | Readonly<{ status: 'refused'; request: string; reason: 'windows-command-script' }>;

export type ExecutableResolutionOptions = Readonly<{
  cwd?: string;
  pathValue?: string;
  pathExtValue?: string;
  platform?: NodeJS.Platform;
}>;

/**
 * Resolves the exact executable a child process would run, before any policy
 * decision is made. Bare names are searched through PATH with Windows PATHEXT
 * semantics; the winner is canonicalized through realpath and hashed so
 * policies can bind to identity rather than spelling.
 *
 * The resolved absolute path is what the runner spawns, removing a second,
 * unobserved PATH search after authorization. A file replaced between hashing
 * and spawn remains an inherent platform race (JavaScript cannot open-then-
 * execute one descriptor); hash pinning narrows that window but cannot close it.
 */
export async function resolveExecutable(
  request: string,
  options: ExecutableResolutionOptions = {},
): Promise<ResolutionStatus> {
  const platform = options.platform ?? process.platform;
  const cwd = options.cwd ?? process.cwd();
  const candidatePath = await locate(request, cwd, options);
  if (candidatePath === undefined) return { status: 'unresolved', request };

  const scriptExtension = windowsScriptExtension(candidatePath, platform);
  if (scriptExtension) {
    return { status: 'refused', request, reason: 'windows-command-script' };
  }

  let canonicalPath: string;
  try {
    canonicalPath = await realpath(candidatePath);
    const metadata = await stat(canonicalPath);
    if (!metadata.isFile()) return { status: 'unresolved', request };
  } catch {
    return { status: 'unresolved', request };
  }

  const digest = await sha256File(canonicalPath).catch(() => undefined);
  if (digest === undefined) return { status: 'unresolved', request };

  return {
    status: 'resolved',
    request,
    displayName: displayNameFor(canonicalPath, platform),
    absolutePath: canonicalPath,
    sha256: digest,
  };
}

async function locate(
  request: string,
  cwd: string,
  options: ExecutableResolutionOptions,
): Promise<string | undefined> {
  if (request.length === 0 || request.includes('\0')) return undefined;
  const platform = options.platform ?? process.platform;
  if (isAbsolute(request) || /[\\/]/u.test(request)) {
    const direct = resolve(cwd, request);
    return (await isRegularFile(direct)) ? direct : undefined;
  }
  const directories = searchDirectories(options.pathValue ?? searchPathEnvironment());
  if (platform === 'win32') {
    const extensions = pathExtEntries(options.pathExtValue ?? DEFAULT_PATHEXT);
    for (const directory of directories) {
      for (const extension of extensions) {
        const candidate = join(directory, `${request}${extension}`);
        if (await isRegularFile(candidate)) return candidate;
      }
      const plain = join(directory, request);
      if (await isRegularFile(plain)) return plain;
    }
    return undefined;
  }
  for (const directory of directories) {
    const candidate = join(directory, request);
    if (await isRegularFile(candidate)) return candidate;
  }
  return undefined;
}
function searchPathEnvironment(): string {
  // Node exposes Windows environment names case-insensitively; scanning keeps
  // POSIX behavior explicit and avoids depending on that normalization.
  for (const [name, value] of Object.entries(process.env)) {
    if (name.toUpperCase() === 'PATH' && value !== undefined && value.length > 0) {
      return value;
    }
  }
  return '';
}

function searchDirectories(pathValue: string): string[] {
  if (pathValue.length === 0) return [];
  const directories: string[] = [];
  for (const entry of pathValue.split(delimiter)) {
    if (entry.length > 0) directories.push(entry);
  }
  return directories;
}

function pathExtEntries(pathExtValue: string): readonly string[] {
  const entries = pathExtValue
    .split(';')
    .map((entry) => entry.trim())
    .filter((entry) => entry.startsWith('.'));
  return entries.length > 0 ? entries : ['.exe'];
}

function windowsScriptExtension(candidate: string, platform: NodeJS.Platform): boolean {
  if (platform !== 'win32') return false;
  const extension = extensionOf(candidate);
  return WINDOWS_SCRIPT_EXTENSIONS.has(extension);
}

function displayNameFor(canonicalPath: string, platform: NodeJS.Platform): string {
  const base = basename(canonicalPath);
  if (platform !== 'win32') return base;
  const extension = extensionOf(base);
  const stripped =
    WINDOWS_STRIP_EXTENSIONS.has(extension) && base.length > extension.length
      ? base.slice(0, base.length - extension.length)
      : base;
  return stripped.toLowerCase();
}

function extensionOf(value: string): string {
  const index = value.lastIndexOf('.');
  return index <= 0 ? '' : value.slice(index).toLowerCase();
}

async function isRegularFile(candidate: string): Promise<boolean> {
  try {
    const metadata = await stat(candidate);
    return metadata.isFile();
  } catch {
    return false;
  }
}

export async function sha256File(path: string): Promise<string> {
  const metadata = await lstat(path);
  if (!metadata.isFile() || metadata.size < 1n) {
    throw new Error('not-a-hashable-file');
  }
  if (metadata.size > MAX_EXECUTABLE_BYTES) {
    throw new Error('executable-exceeds-supported-size');
  }
  const hash = createHash('sha256');
  for await (const chunk of createReadStream(path)) {
    hash.update(chunk as Buffer);
  }
  return hash.digest('hex');
}
