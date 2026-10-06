import { spawn, type ChildProcessByStdio } from 'node:child_process';
import type { Readable, Writable } from 'node:stream';
import { win32 } from 'node:path';

import { PortableKeyFileError } from './errors.js';

/**
 * Transport for the Windows protected-path boundary.
 *
 * Verifying a Windows security descriptor needs the .NET access-control API,
 * which only ships with the platform interpreter. Starting that interpreter
 * costs roughly 145 ms of pure start-up, and the storage layer performs dozens
 * of protected-path assertions per operation, so paying it once per assertion
 * made every local-file operation seconds long.
 *
 * This module keeps one long-lived helper process per Kavrix process and
 * exchanges newline-delimited JSON over its standard streams, so each
 * assertion costs the interpreter's real work instead of its start-up. It is
 * faster than one interpreter per assertion even when only one assertion is
 * ever made, so there is no second code path to keep correct.
 *
 * The security posture is unchanged and, for request framing, strictly
 * stronger than before:
 *
 * - The helper is a fixed absolute executable, never resolved from `PATH`,
 *   `SystemRoot`, or any caller-controlled value.
 * - The request program is a fixed constant from this source, passed with
 *   `-EncodedCommand`; no caller value is ever interpolated into it.
 * - Requested paths travel base64-encoded over stdin instead of an
 *   environment variable, so a path can never be read as program text.
 * - A path is refused before it is sent unless it is absolute and free of
 *   control characters.
 * - The helper is only ever asked about access control. It never receives key,
 *   passphrase, or ciphertext material.
 *
 * Every failure fails closed: a refused verification, a crash, a timeout, a
 * malformed reply, and an unexpected exit all surface as the same generic
 * error the caller already handles.
 */

const WINDOWS_SYSTEM_ROOT = String.raw`C:\Windows`;
const POWERSHELL_EXECUTABLE = win32.join(
  WINDOWS_SYSTEM_ROOT,
  'System32',
  'WindowsPowerShell',
  'v1.0',
  'powershell.exe',
);

/** Ceiling on interpreter start-up or on any single reply. */
const HELPER_TIMEOUT_MS = 30_000;
/** Bounds how much unexpected output may pass before the helper is discarded. */
const MAX_IGNORED_REPLY_LINES = 64;
const MAX_REPLY_LINE_BYTES = 4_096;

/** Operations the helper understands. */
export type WindowsAclOperation = 'verify-user-only' | 'verify-parent-dir' | 'set';

/**
 * Outcome of one protected-path request. `ok: true` is the only acceptance and
 * is produced solely by a completed verification inside the helper.
 */
export type WindowsAclReply =
  Readonly<{ ok: true }> | Readonly<{ ok: false; reason: string }>;

type HelperProcess = ChildProcessByStdio<Writable, Readable, null>;

interface PendingRequest {
  readonly nonce: number;
  readonly settle: (
    outcome: Readonly<{ ok: true }> | Readonly<{ ok: false; reason: string }>,
  ) => void;
  readonly abort: () => void;
}

/**
 * The helper program. Each request is one JSON object on stdin; each reply is
 * one JSON object on stdout. Paths arrive base64-encoded so they are decoded as
 * opaque bytes rather than parsed as PowerShell source.
 *
 * `verify-user-only` reproduces the historical Kavrix-owned-object rule:
 * inheritance disabled, current user as owner, no inherited or denying rules,
 * and no grant to any principal other than the current user or SYSTEM. A file
 * must also grant inheritable rights so that its children are equally
 * protected. The target may be a file or a directory.
 *
 * `verify-parent-dir` reproduces the historical parent-directory rule, which is
 * deliberately weaker because existing parent directories are not
 * Kavrix-owned: read grants to ordinary principals are compatible with a
 * shared working directory, but any non-inherit-only write or control grant
 * must belong to the current user, SYSTEM, or built-in Administrators.
 *
 * `set` reproduces the historical hardening step: take ownership, disable
 * inheritance, and grant the current user full control.
 */
const HELPER_PROGRAM = String.raw`
$ErrorActionPreference = 'Stop'
$reader = [Console]::In
$writer = [Console]::Out
$systemSid = 'S-1-5-18'
$administratorsSid = 'S-1-5-32-544'
$allow = [Security.AccessControl.AccessControlType]::Allow
$containerInherit = [Security.AccessControl.InheritanceFlags]::ContainerInherit
$objectInherit = [Security.AccessControl.InheritanceFlags]::ObjectInherit
$inheritOnly = [Security.AccessControl.PropagationFlags]::InheritOnly
$sections = [Security.AccessControl.AccessControlSections]::Access -bor [Security.AccessControl.AccessControlSections]::Owner
function Reply([long]$nonce, [bool]$ok, [string]$reason) {
  $payload = [ordered]@{ v = 1; n = $nonce; ok = $ok }
  if (-not $ok) { $payload['r'] = $reason }
  $writer.WriteLine((ConvertTo-Json -InputObject $payload -Compress))
  $writer.Flush()
}
function Accept([long]$nonce) {
  Reply $nonce $true ''
}
function Refuse([long]$nonce, [string]$reason) {
  Reply $nonce $false $reason
}
function Resolve-Item([string]$target, [bool]$wantDirectory) {
  if ([IO.Directory]::Exists($target)) {
    if (-not $wantDirectory) { return $null }
    return [IO.DirectoryInfo]::new($target)
  }
  if ([IO.File]::Exists($target)) {
    if ($wantDirectory) { return $null }
    return [IO.FileInfo]::new($target)
  }
  return $null
}
function Verify-UserOnly([bool]$isDirectory, [string]$currentSid, $acl) {
  if (-not $acl.AreAccessRulesProtected) { return $false }
  $ownerSid = $acl.GetOwner([Security.Principal.SecurityIdentifier]).Value
  if ($ownerSid -ne $currentSid) { return $false }
  $rules = @($acl.GetAccessRules($true, $true, [Security.Principal.SecurityIdentifier]))
  if ($rules.Count -eq 0) { return $false }
  $required = $containerInherit -bor $objectInherit
  $hasCurrentUserAllow = $false
  $hasSafeChildInheritance = -not $isDirectory
  foreach ($rule in $rules) {
    $ruleSid = $rule.IdentityReference.Value
    if ($rule.IsInherited) { return $false }
    if ($rule.AccessControlType -ne $allow) { return $false }
    if ($ruleSid -ne $currentSid -and $ruleSid -ne $systemSid) { return $false }
    if ($ruleSid -eq $currentSid) {
      $hasCurrentUserAllow = $true
      if (($rule.InheritanceFlags -band $required) -eq $required) { $hasSafeChildInheritance = $true }
    }
  }
  return $hasCurrentUserAllow -and $hasSafeChildInheritance
}
function Verify-ParentDirectory([string]$currentSid, $acl) {
  $ownerSid = $acl.GetOwner([Security.Principal.SecurityIdentifier]).Value
  $trustedSids = @($currentSid, $systemSid, $administratorsSid)
  if ($trustedSids -notcontains $ownerSid) { return $false }
  $rules = @($acl.GetAccessRules($true, $true, [Security.Principal.SecurityIdentifier]))
  if ($rules.Count -eq 0) { return $false }
  $writeRights = [Security.AccessControl.FileSystemRights]::Write -bor [Security.AccessControl.FileSystemRights]::WriteData -bor [Security.AccessControl.FileSystemRights]::AppendData -bor [Security.AccessControl.FileSystemRights]::WriteExtendedAttributes -bor [Security.AccessControl.FileSystemRights]::WriteAttributes -bor [Security.AccessControl.FileSystemRights]::Delete -bor [Security.AccessControl.FileSystemRights]::DeleteSubdirectoriesAndFiles -bor [Security.AccessControl.FileSystemRights]::ChangePermissions -bor [Security.AccessControl.FileSystemRights]::TakeOwnership -bor 0x40000000 -bor 0x10000000
  foreach ($rule in $rules) {
    $ruleSid = $rule.IdentityReference.Value
    if ([String]::IsNullOrEmpty($ruleSid)) { return $false }
    if ($rule.AccessControlType -ne $allow) { return $false }
    if (($rule.PropagationFlags -band $inheritOnly) -ne 0) { continue }
    $hasWriteRights = (([int]$rule.FileSystemRights -band [int]$writeRights) -ne 0)
    if ($hasWriteRights -and $trustedSids -notcontains $ruleSid) { return $false }
  }
  return $true
}
while ($true) {
  $line = $reader.ReadLine()
  if ($null -eq $line) { break }
  if ($line.Length -eq 0) { continue }
  $nonce = [long]0
  try {
    $request = ConvertFrom-Json $line
    $nonce = [long]$request.n
    $op = [string]$request.op
    $target = [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String([string]$request.p))
    if ([String]::IsNullOrEmpty($target) -or -not [IO.Path]::IsPathRooted($target)) {
      Refuse $nonce 'kind'
      continue
    }
    if ($op -eq 'set') {
      $isDirectory = [IO.Directory]::Exists($target)
      $item = Resolve-Item $target $isDirectory
      if ($null -eq $item) { Refuse $nonce 'kind'; continue }
      $item.Refresh()
      if (-not $item.Exists -or (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0)) {
        Refuse $nonce 'kind'
        continue
      }
      $sid = [Security.Principal.WindowsIdentity]::GetCurrent().User
      if ($isDirectory) {
        $acl = [Security.AccessControl.DirectorySecurity]::new()
      } else {
        $acl = [Security.AccessControl.FileSecurity]::new()
      }
      $acl.SetOwner($sid)
      $acl.SetAccessRuleProtection($true, $false)
      $inheritance = [Security.AccessControl.InheritanceFlags]::None
      if ($isDirectory) { $inheritance = $containerInherit -bor $objectInherit }
      $propagation = [Security.AccessControl.PropagationFlags]::None
      $rule = [Security.AccessControl.FileSystemAccessRule]::new($sid, [Security.AccessControl.FileSystemRights]::FullControl, $inheritance, $propagation, $allow)
      [void]$acl.AddAccessRule($rule)
      if ($isDirectory) {
        [IO.Directory]::SetAccessControl($target, $acl)
      } else {
        [IO.File]::SetAccessControl($target, $acl)
      }
      Accept $nonce
      continue
    }
    $wantDirectory = ($op -eq 'verify-parent-dir')
    if (-not $wantDirectory -and $op -ne 'verify-user-only') { Refuse $nonce 'unknown-op'; continue }
    $isDirectory = [IO.Directory]::Exists($target)
    if ($wantDirectory -and -not $isDirectory) { Refuse $nonce 'kind'; continue }
    $item = Resolve-Item $target $isDirectory
    if ($null -eq $item) { Refuse $nonce 'kind'; continue }
    $item.Refresh()
    if (-not $item.Exists -or (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0)) {
      Refuse $nonce 'kind'
      continue
    }
    $currentSid = [Security.Principal.WindowsIdentity]::GetCurrent().User.Value
    if ([String]::IsNullOrEmpty($currentSid)) { Refuse $nonce 'error'; continue }
    $acl = $item.GetAccessControl($sections)
    if ($wantDirectory) {
      if (Verify-ParentDirectory $currentSid $acl) {
        Accept $nonce
      } else {
        Refuse $nonce 'policy'
      }
      continue
    }
    if (Verify-UserOnly $isDirectory $currentSid $acl) {
      Accept $nonce
    } else {
      Refuse $nonce 'policy'
    }
  } catch {
    Refuse $nonce 'error'
  }
}
`;

const pending = new Map<number, PendingRequest>();
let helperProcess: HelperProcess | undefined;
let helperUnusable = false;
let replyBuffer = '';
let ignoredLines = 0;
let nextNonce = 0;

/**
 * Environment for the helper interpreter.
 *
 * It carries only the platform root the executable lives under plus the
 * invoking user's own profile directories, which the interpreter needs in order
 * to reuse its per-user module analysis cache. Supplying them keeps start-up
 * near 130 ms instead of roughly 900 ms, because without them the interpreter
 * re-analyses its module set on every launch. No value here can influence which
 * executable runs or the program it executes.
 */
function helperEnvironment(): NodeJS.ProcessEnv {
  const userProfile = process.env['USERPROFILE'] ?? process.env['HOME'];
  const localAppData = process.env['LOCALAPPDATA'] ?? userProfile;
  const environment: NodeJS.ProcessEnv = {
    SystemRoot: WINDOWS_SYSTEM_ROOT,
    WINDIR: WINDOWS_SYSTEM_ROOT,
  };
  if (userProfile !== undefined) environment['USERPROFILE'] = userProfile;
  if (localAppData !== undefined) environment['LOCALAPPDATA'] = localAppData;
  const temporary = process.env['TEMP'] ?? process.env['TMP'] ?? localAppData;
  if (temporary !== undefined) {
    environment['TEMP'] = temporary;
    environment['TMP'] = temporary;
  }
  return environment;
}

/**
 * Runs one protected-path request, starting the helper on first use. Rejects
 * only when the helper itself could not be used, so the caller can distinguish
 * an unusable boundary from a refused verification and apply its retry policy.
 */
export async function runWindowsAclRequest(
  operation: WindowsAclOperation,
  targetPath: string,
): Promise<WindowsAclReply> {
  if (helperUnusable) throw new PortableKeyFileError('KEY_FILE_UNSAFE');
  assertRequestablePath(targetPath);
  const child = ensureHelper();
  setHelperReferenced(true);
  nextNonce += 1;
  const nonce = nextNonce;
  return new Promise<WindowsAclReply>((resolve, reject) => {
    const release = (): void => {
      clearTimeout(timer);
      pending.delete(nonce);
      if (pending.size === 0) setHelperReferenced(false);
    };
    const timer = setTimeout(() => {
      release();
      discardHelper();
      reject(new PortableKeyFileError('KEY_FILE_UNSAFE'));
    }, HELPER_TIMEOUT_MS);
    pending.set(nonce, {
      nonce,
      settle: (outcome) => {
        release();
        resolve(outcome);
      },
      abort: () => {
        release();
        reject(new PortableKeyFileError('KEY_FILE_UNSAFE'));
      },
    });
    try {
      child.stdin.write(
        `${JSON.stringify({
          v: 1,
          n: nonce,
          op: operation,
          p: Buffer.from(targetPath, 'utf8').toString('base64'),
        })}\n`,
      );
    } catch {
      discardHelper();
      pending.get(nonce)?.abort();
    }
  });
}

/**
 * Starts the helper without sending a request, so the interpreter's start-up
 * cost can overlap unrelated work instead of delaying the first verification.
 *
 * The spawned helper behaves exactly like one started by a request: its handles
 * are unreferenced, so it never keeps the owning process alive; the process
 * exit hook still kills it; and if it fails to start, the next real request
 * reports the failure through the normal fail-closed path. A refused or failed
 * prewarm is therefore never observable except as the absence of a delay.
 */
export function prewarmWindowsAclHelper(): void {
  if (helperUnusable || helperProcess !== undefined) return;
  ensureHelper();
}

/**
 * Control characters that cannot appear in a legitimate Windows path and would
 * make a request ambiguous to frame. Checked by code point rather than with a
 * regular expression so the intent stays explicit.
 */
function containsControlCharacter(value: string): boolean {
  for (let index = 0; index < value.length; index += 1) {
    const code = value.charCodeAt(index);
    if (code <= 0x1f || code === 0x7f) return true;
  }
  return false;
}

/**
 * Rejects any path that could not be a real Windows filesystem target. Base64
 * framing already makes request smuggling impossible; this stops a caller from
 * asking the helper about something that was never a Kavrix-owned object.
 */
function assertRequestablePath(targetPath: string): void {
  if (targetPath.length === 0 || !win32.isAbsolute(targetPath)) {
    throw new PortableKeyFileError('KEY_FILE_UNSAFE');
  }
  if (containsControlCharacter(targetPath)) {
    throw new PortableKeyFileError('KEY_FILE_UNSAFE');
  }
}

function ensureHelper(): HelperProcess {
  if (helperProcess !== undefined) return helperProcess;
  const child = spawn(
    POWERSHELL_EXECUTABLE,
    [
      '-NoLogo',
      '-NoProfile',
      '-NonInteractive',
      '-ExecutionPolicy',
      'Bypass',
      '-EncodedCommand',
      Buffer.from(HELPER_PROGRAM, 'utf16le').toString('base64'),
    ],
    {
      stdio: ['pipe', 'pipe', 'ignore'],
      windowsHide: true,
      env: helperEnvironment(),
    },
  );
  replyBuffer = '';
  ignoredLines = 0;
  child.stdout.setEncoding('utf8');
  child.stdout.on('data', (chunk: string) => {
    absorbReplyChunk(chunk);
  });
  child.once('error', () => {
    // The interpreter itself is unavailable, which no retry can repair.
    helperUnusable = true;
    helperProcess = undefined;
    abortEveryRequest();
  });
  child.once('exit', () => {
    helperProcess = undefined;
    // A helper that died has not answered what it was asked; those requests are
    // retried by the caller rather than resolved as successes or failures.
    abortEveryRequest();
  });
  helperProcess = child;
  // An idle helper must never be the reason a Kavrix process stays alive.
  // Handles are referenced again only while a request is actually in flight.
  setHelperReferenced(false);
  return child;
}

/**
 * Adds or removes the helper's handles from the event loop. Keeping them
 * referenced only while work is outstanding lets a short-lived CLI exit as soon
 * as its storage work finishes, while a long operation still waits for replies.
 */
function setHelperReferenced(referenced: boolean): void {
  const child = helperProcess;
  if (child === undefined) return;
  const handles: unknown[] = [child, child.stdin, child.stdout];
  for (const handle of handles) {
    if (handle === null || typeof handle !== 'object') continue;
    const candidate = handle as { ref?: unknown; unref?: unknown };
    const method = referenced ? candidate.ref : candidate.unref;
    if (typeof method === 'function') (method as () => void).call(handle);
  }
}

function absorbReplyChunk(chunk: string): void {
  replyBuffer += chunk;
  let newlineIndex = replyBuffer.indexOf('\n');
  while (newlineIndex !== -1) {
    const line = replyBuffer.slice(0, newlineIndex);
    replyBuffer = replyBuffer.slice(newlineIndex + 1);
    handleReplyLine(line);
    newlineIndex = replyBuffer.indexOf('\n');
  }
  if (replyBuffer.length > MAX_REPLY_LINE_BYTES) {
    ignoredLines += 1;
    discardHelper();
  }
}

/**
 * Delivers one reply to the request that asked for it. Lines that are not a
 * matching reply are ignored rather than trusted: only an explicit acceptance
 * resolves a request, so banner or progress output can never grant access.
 */
function handleReplyLine(rawLine: string): void {
  const line = rawLine.replace(/^\uFEFF/u, '').trim();
  if (line.length === 0) return;
  const reply = parseReply(line);
  if (reply === undefined) {
    ignoredLines += 1;
    if (ignoredLines > MAX_IGNORED_REPLY_LINES) discardHelper();
    return;
  }
  ignoredLines = 0;
  const request = pending.get(reply.nonce);
  if (request === undefined) return;
  if (reply.ok) request.settle({ ok: true });
  else request.settle({ ok: false, reason: reply.reason });
}

type ParsedReply =
  | Readonly<{ nonce: number; ok: true }>
  | Readonly<{ nonce: number; ok: false; reason: string }>;

/** Parses one well-formed reply envelope, or returns undefined for noise. */
function parseReply(line: string): ParsedReply | undefined {
  let parsed: unknown;
  try {
    parsed = JSON.parse(line);
  } catch {
    return undefined;
  }
  if (parsed === null || typeof parsed !== 'object') return undefined;
  const reply = parsed as Readonly<Record<string, unknown>>;
  const nonce = reply['n'];
  if (reply['v'] !== 1 || typeof nonce !== 'number') return undefined;
  if (reply['ok'] === true) return { nonce, ok: true };
  if (reply['ok'] !== false) return undefined;
  return {
    nonce,
    ok: false,
    reason: typeof reply['r'] === 'string' ? reply['r'] : 'error',
  };
}

function abortEveryRequest(): void {
  for (const request of [...pending.values()]) request.abort();
  pending.clear();
}

/** Drops the helper so the next request starts a fresh, trustworthy one. */
function discardHelper(): void {
  const child = helperProcess;
  helperProcess = undefined;
  replyBuffer = '';
  if (child === undefined) return;
  child.removeAllListeners('exit');
  child.kill();
  abortEveryRequest();
}

/**
 * Ends the helper when the owning process exits, so an interpreter is never
 * left running after the work that needed it is finished.
 *
 * The handler is registered at most once per process. Several entry points can
 * load this module, and a second registration would only add another listener
 * that does the same thing.
 */
const exitHookInstalled = Symbol.for('kavrix.windowsAclProcess.exitHook');

function installExitHook(): void {
  const registry = globalThis as unknown as Record<symbol, boolean | undefined>;
  if (registry[exitHookInstalled] === true) return;
  registry[exitHookInstalled] = true;
  process.once('exit', () => {
    const child = helperProcess;
    helperProcess = undefined;
    child?.kill();
  });
}

installExitHook();
