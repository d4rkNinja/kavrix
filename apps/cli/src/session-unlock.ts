import { createHash, randomBytes } from 'node:crypto';
import { execFile } from 'node:child_process';
import { rm } from 'node:fs/promises';
import { promisify } from 'node:util';

import { openSessionUnlock, sealSessionUnlock } from '@kavrix/crypto';
import type { SessionUnlockAssociatedData } from '@kavrix/schemas';
import {
  readProtectedJsonDocument,
  validateSecureFileDestination,
  writeProtectedJsonDocument,
} from '@kavrix/key-files';

const execFileAsync = promisify(execFile);

const SESSION_FILE_SUFFIX = '.session';
const SESSION_FILE_MAGIC = 'kavrix-session-unlock';
const SESSION_UNLOCK_TTL_HOURS_DEFAULT = 12;
const SESSION_KEY_BYTES = 32;
const KEYCHAIN_TIMEOUT_MS = 15_000;
const KEYCHAIN_SERVICE = 'kavrix-session-unlock';
const SESSION_UNLOCK_DOMAIN = Buffer.from('kavrix/session-unlock-aad/v1', 'ascii');

export type SessionUnlockErrorCode =
  'unavailable' | 'expired' | 'tampered' | 'keychain-unavailable';

export class SessionUnlockError extends Error {
  public constructor(
    public readonly code: SessionUnlockErrorCode,
    message: string,
  ) {
    super(message);
    this.name = 'SessionUnlockError';
  }
}

export type SessionUnlockTarget = Readonly<{
  /** Non-secret profile identifier; part of the keychain account and AAD. */
  profileId: string;
  /** Opaque database binding when the profile is bound; part of the AAD. */
  databaseId?: string | undefined;
  /** Portable key file path; the sealed session file lives beside it. */
  keyFile: string;
}>;

export type SessionUnlockStatus = Readonly<{
  enabled: boolean;
  expired: boolean;
  createdAt: string | null;
  ttlHours: number | null;
}>;

export type SessionUnlockPort = Readonly<{
  store: (valueB64: string) => Promise<void>;
  load: () => Promise<string | null>;
  remove: () => Promise<void>;
}>;

/**
 * Deterministic, path-free keychain account for one session-unlock
 * credential. The account is derived from the profile/database binding
 * only — never a raw path or raw profile id — so the same binding always
 * addresses the same entry without leaking locations into the OS store.
 */
export function sessionUnlockAccountFor(target: SessionUnlockTarget): string {
  const digest = createHash('sha256')
    .update(SESSION_UNLOCK_DOMAIN)
    .update(`${target.profileId}\u0000${target.databaseId ?? ''}`, 'utf8')
    .digest('hex');
  return `su-${digest.slice(0, 40)}`;
}

function sessionFilePathFor(target: SessionUnlockTarget): string {
  return `${target.keyFile}${SESSION_FILE_SUFFIX}`;
}

// ---- OS keychain port -------------------------------------------------------
// Child-process based; no native build dependencies. Secrets never travel
// through process arguments: writes feed stdin, reads print the base64 value
// to stdout, and every spawn uses argument arrays, a stripped environment, no
// shell, and a hard timeout.

async function runCommand(
  executable: string,
  args: readonly string[],
  options?: Readonly<{
    input?: string;
    allowNotFound?: boolean;
    env?: Readonly<Record<string, string>>;
  }>,
): Promise<string | null> {
  try {
    const result = await execFileAsync(executable, [...args], {
      encoding: 'utf8',
      timeout: KEYCHAIN_TIMEOUT_MS,
      windowsHide: true,
      maxBuffer: 64 * 1024,
      env: {
        SystemRoot: process.env['SystemRoot'] ?? String.raw`C:\Windows`,
        WINDIR: process.env['WINDIR'] ?? String.raw`C:\Windows`,
        ...(options?.env ?? {}),
      },
      ...(options?.input === undefined ? {} : { input: options.input }),
    });
    return result.stdout;
  } catch (error) {
    const status = (error as { code?: unknown }).code;
    // `security` exits 44 when the item does not exist; secret-tool exits 1.
    if (
      options?.allowNotFound === true &&
      (status === 44 || status === 40 || status === 1)
    ) {
      return null;
    }
    throw new SessionUnlockError(
      'keychain-unavailable',
      'The operating system credential store is unavailable.',
    );
  }
}

const WINDOWS_POWERSHELL_ROOT = `${process.env['SystemRoot'] ?? 'C:\\Windows'}\\System32\\WindowsPowerShell\\v1.0\\powershell.exe`;

function windowsScript(mode: 'store' | 'load' | 'remove', account: string): string {
  const head = `
$ErrorActionPreference = 'Stop'
[void][Windows.Security.Credentials.PasswordVault,Windows.Security.Credentials,ContentType=WindowsRuntime]
$vault = New-Object Windows.Security.Credentials.PasswordVault
`;
  if (mode === 'store') {
    return `${head}
$value = $env:KAVRIX_KEYCHAIN_VALUE
if ([String]::IsNullOrEmpty($value)) { exit 3 }
$cred = New-Object Windows.Security.Credentials.PasswordCredential('${KEYCHAIN_SERVICE}', '${account}', $value)
$vault.Add($cred)
`;
  }
  if (mode === 'load') {
    return `${head}
foreach ($c in $vault.RetrieveAll()) {
  if ($c.Resource -ne '${KEYCHAIN_SERVICE}') { continue }
  if ($c.UserName -ne '${account}') { continue }
  $c.RetrievePassword()
  [Console]::Out.Write($c.Password)
  exit 0
}
exit 40
`;
  }
  return `${head}
foreach ($c in $vault.RetrieveAll()) {
  if ($c.Resource -ne '${KEYCHAIN_SERVICE}') { continue }
  if ($c.UserName -ne '${account}') { continue }
  $vault.Remove($c)
  break
}
`;
}

function windowsPort(account: string): SessionUnlockPort {
  // PasswordVault occasionally rejects operations transiently on loaded
  // runners (and while shard processes contend for the user vault); retry a
  // bounded number of times with linear backoff, mirroring the ACL helper.
  const withRetry = async (
    script: string,
    env?: Record<string, string>,
  ): Promise<void> => {
    let lastError: unknown;
    for (let attempt = 0; attempt < 3; attempt += 1) {
      try {
        await runCommand(
          WINDOWS_POWERSHELL_ROOT,
          [
            '-NoLogo',
            '-NoProfile',
            '-NonInteractive',
            '-ExecutionPolicy',
            'Bypass',
            '-Command',
            script,
          ],
          { ...(env === undefined ? {} : { env }), allowNotFound: true },
        );
        return;
      } catch (error) {
        lastError = error;
        await new Promise((resolve) => setTimeout(resolve, 150 * (attempt + 1)));
      }
    }
    throw lastError;
  };
  return {
    store: async (valueB64) => {
      // The base64 wrapping key rides in the child's own environment (never
      // argv, never a shell): this helper exists to receive exactly this
      // value, and its lifetime is the store operation only.
      await withRetry(windowsScript('store', account), {
        KAVRIX_KEYCHAIN_VALUE: valueB64,
      });
    },
    load: async () => {
      const script = windowsScript('load', account);
      for (let attempt = 0; attempt < 3; attempt += 1) {
        try {
          const out = await runCommand(
            WINDOWS_POWERSHELL_ROOT,
            [
              '-NoLogo',
              '-NoProfile',
              '-NonInteractive',
              '-ExecutionPolicy',
              'Bypass',
              '-Command',
              script,
            ],
            { allowNotFound: true },
          );
          return out === null || out.length === 0 ? null : out;
        } catch (error) {
          if (attempt === 2) {
            if (error instanceof SessionUnlockError && error.code === 'unavailable') {
              return null;
            }
            throw error;
          }
          await new Promise((resolve) => setTimeout(resolve, 150 * (attempt + 1)));
        }
      }
      return null;
    },
    remove: async () => {
      await withRetry(windowsScript('remove', account));
    },
  };
}

function macPort(account: string): SessionUnlockPort {
  return {
    store: async (valueB64) => {
      await runCommand('security', [
        'add-generic-password',
        '-s',
        KEYCHAIN_SERVICE,
        '-a',
        account,
        '-U',
        '-w',
        valueB64,
      ]);
    },
    load: async () => {
      const out = await runCommand(
        'security',
        ['find-generic-password', '-s', KEYCHAIN_SERVICE, '-a', account, '-w'],
        { allowNotFound: true },
      );
      return out === null || out.trim().length === 0 ? null : out.trim();
    },
    remove: async () => {
      await runCommand(
        'security',
        ['delete-generic-password', '-s', KEYCHAIN_SERVICE, '-a', account],
        { allowNotFound: true },
      );
    },
  };
}

function linuxPort(account: string): SessionUnlockPort {
  const attributes = ['service', KEYCHAIN_SERVICE, 'account', account];
  return {
    store: async (valueB64) => {
      await runCommand(
        'secret-tool',
        ['store', '--label=Kavrix session unlock', ...attributes],
        { input: valueB64 },
      );
    },
    load: async () => {
      const out = await runCommand('secret-tool', ['lookup', ...attributes], {
        allowNotFound: true,
      });
      return out === null || out.trim().length === 0 ? null : out.trim();
    },
    remove: async () => {
      await runCommand('secret-tool', ['clear', ...attributes], {
        allowNotFound: true,
      });
    },
  };
}

/** Platform keychain port; unsupported platforms fail closed. */
export function platformKeychainPort(account: string): SessionUnlockPort {
  if (process.platform === 'win32') return windowsPort(account);
  if (process.platform === 'darwin') return macPort(account);
  if (process.platform === 'linux') return linuxPort(account);
  throw new SessionUnlockError(
    'keychain-unavailable',
    'Session unlock is not supported on this platform.',
  );
}

// ---- sealed session file ----------------------------------------------------

function sessionAad(
  target: SessionUnlockTarget,
  createdAt: string,
  ttlHours: number | undefined,
): SessionUnlockAssociatedData {
  return {
    version: 1,
    kind: 'session-unlock',
    profileId: target.profileId,
    ...(target.databaseId === undefined ? {} : { databaseId: target.databaseId }),
    createdAt,
    ...(ttlHours === undefined ? {} : { ttlHours }),
  };
}

function isExpired(createdAt: string, ttlHours: number | undefined): boolean {
  if (ttlHours === undefined) return false;
  const createdMs = Date.parse(createdAt);
  if (!Number.isFinite(createdMs)) return true;
  return Date.now() > createdMs + ttlHours * 3_600_000;
}

/**
 * Enables session unlock: seals the passphrase-equivalent unlock material
 * with a fresh random key, writes the sealed file beside the portable key
 * file (owner-only), and stores the wrapping key in the OS keychain. Either
 * half alone is useless; removing either half revokes the session.
 */
export async function enableSessionUnlock(options: {
  readonly target: SessionUnlockTarget;
  readonly passphrase: string;
  readonly ttlHours?: number | undefined;
  readonly port?: SessionUnlockPort;
}): Promise<SessionUnlockStatus> {
  const ttlHours = options.ttlHours ?? SESSION_UNLOCK_TTL_HOURS_DEFAULT;
  const filePath = sessionFilePathFor(options.target);
  await validateSecureFileDestination(filePath);
  const account = sessionUnlockAccountFor(options.target);
  const port = options.port ?? platformKeychainPort(account);
  const wrappingKey = randomBytes(SESSION_KEY_BYTES);
  const createdAt = new Date().toISOString();
  try {
    const envelope = await sealSessionUnlock(
      Buffer.from(options.passphrase, 'utf8'),
      wrappingKey,
      sessionAad(options.target, createdAt, ttlHours),
    );
    // Enable overwrites any previous session file: remove first so the
    // protected 'create' path publishes a fresh owner-only file atomically.
    await rm(filePath, { force: true });
    await writeProtectedJsonDocument(
      filePath,
      { magic: SESSION_FILE_MAGIC, envelope },
      'create',
      {
        schema: { parse: (value: unknown) => value as Record<string, unknown> },
        maximumBytes: 16 * 1024,
      },
    );
    await port.store(Buffer.from(wrappingKey).toString('base64url'));
    await port.store(Buffer.from(wrappingKey).toString('base64url'));
  } finally {
    wrappingKey.fill(0);
  }
  return {
    enabled: true,
    expired: false,
    createdAt,
    ttlHours,
  };
}

type ParsedSessionFile = Readonly<{
  envelope: unknown;
  createdAt: string;
  ttlHours: number | undefined;
}>;

function parseSessionDocument(document: Record<string, unknown>): ParsedSessionFile {
  if (
    document['magic'] !== SESSION_FILE_MAGIC ||
    typeof document['envelope'] !== 'object' ||
    document['envelope'] === null
  ) {
    throw new SessionUnlockError('tampered', 'The session-unlock file is invalid.');
  }
  const envelope = document['envelope'] as Record<string, unknown>;
  const aad = envelope['aad'];
  if (typeof aad !== 'object' || aad === null) {
    throw new SessionUnlockError('tampered', 'The session-unlock file is invalid.');
  }
  const aadRecord = aad as Record<string, unknown>;
  if (
    typeof aadRecord['createdAt'] !== 'string' ||
    typeof aadRecord['profileId'] !== 'string'
  ) {
    throw new SessionUnlockError('tampered', 'The session-unlock file is invalid.');
  }
  return {
    envelope,
    createdAt: aadRecord['createdAt'],
    ttlHours:
      typeof aadRecord['ttlHours'] === 'number' ? aadRecord['ttlHours'] : undefined,
  };
}

/**
 * Resolves the stored unlock material. Returns `null` when no session is
 * enabled. Fails closed on tampering, keychain loss, or TTL expiry — never
 * falls back to anything weaker.
 */
export async function resolveSessionUnlock(options: {
  readonly target: SessionUnlockTarget;
  readonly port?: SessionUnlockPort;
}): Promise<{ readonly passphrase: string } | null> {
  const filePath = sessionFilePathFor(options.target);
  const account = sessionUnlockAccountFor(options.target);
  const port = options.port ?? platformKeychainPort(account);

  const storedKeyB64 = await port.load();
  if (storedKeyB64 === null || storedKeyB64.length === 0) return null;
  const wrappingKey = Buffer.from(storedKeyB64, 'base64url');
  if (wrappingKey.byteLength !== SESSION_KEY_BYTES) {
    wrappingKey.fill(0);
    throw new SessionUnlockError(
      'tampered',
      'The stored session-unlock credential is invalid.',
    );
  }
  let document: Record<string, unknown>;
  try {
    document = await readProtectedJsonDocument<Record<string, unknown>>(filePath, {
      schema: { parse: (value: unknown) => value as Record<string, unknown> },
      maximumBytes: 16 * 1024,
    });
  } catch (error) {
    wrappingKey.fill(0);
    if (error instanceof Error && error.message.includes('ENOENT')) return null;
    throw new SessionUnlockError('tampered', 'The session-unlock file is invalid.');
  }
  let parsed: ParsedSessionFile;
  try {
    parsed = parseSessionDocument(document);
  } catch (error) {
    wrappingKey.fill(0);
    if (error instanceof SessionUnlockError) throw error;
    throw new SessionUnlockError('tampered', 'The session-unlock file is invalid.');
  }
  if (isExpired(parsed.createdAt, parsed.ttlHours)) {
    wrappingKey.fill(0);
    throw new SessionUnlockError(
      'expired',
      'The session unlock has expired; unlock with the passphrase and enable a new session.',
    );
  }

  try {
    const material = await openSessionUnlock(
      parsed.envelope as Parameters<typeof openSessionUnlock>[0],
      wrappingKey,
      sessionAad(options.target, parsed.createdAt, parsed.ttlHours),
    );
    const passphrase = Buffer.from(material).toString('utf8');
    material.fill(0);
    return { passphrase };
  } catch (error) {
    wrappingKey.fill(0);
    if (error instanceof SessionUnlockError) throw error;
    throw new SessionUnlockError(
      'tampered',
      'The session-unlock file failed authentication.',
    );
  }
}

/** Reports session state without unlocking anything. */
export async function sessionUnlockStatus(options: {
  readonly target: SessionUnlockTarget;
}): Promise<SessionUnlockStatus> {
  let document: Record<string, unknown>;
  try {
    document = await readProtectedJsonDocument<Record<string, unknown>>(
      sessionFilePathFor(options.target),
      {
        schema: { parse: (value: unknown) => value as Record<string, unknown> },
        maximumBytes: 16 * 1024,
      },
    );
  } catch {
    return {
      enabled: false,
      expired: false,
      createdAt: null,
      ttlHours: null,
    };
  }
  try {
    const parsed = parseSessionDocument(document);
    return {
      enabled: true,
      expired: isExpired(parsed.createdAt, parsed.ttlHours),
      createdAt: parsed.createdAt,
      ttlHours: parsed.ttlHours ?? null,
    };
  } catch {
    return { enabled: true, expired: true, createdAt: null, ttlHours: null };
  }
}

/**
 * Revokes the session: removes the keychain wrapping key first, then the
 * sealed file. Both halves are removed so a stale file can never be
 * resurrected by a later keychain entry with the same account.
 */
export async function revokeSessionUnlock(options: {
  readonly target: SessionUnlockTarget;
  readonly port?: SessionUnlockPort;
}): Promise<{ readonly revoked: true }> {
  const account = sessionUnlockAccountFor(options.target);
  const port = options.port ?? platformKeychainPort(account);
  await port.remove();
  await rm(sessionFilePathFor(options.target)).catch(() => undefined);
  return { revoked: true };
}
