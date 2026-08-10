import { spawn } from 'node:child_process';
import type { Stats } from 'node:fs';
import { open, chmod, lstat, mkdir, realpath } from 'node:fs/promises';
import { dirname, isAbsolute, resolve } from 'node:path';

import { SyncLocalStateError } from '@kavrix/sync';

const WINDOWS_ROOT = 'C:\\Windows';
const WINDOWS_POWERSHELL =
  'C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe';
const WINDOWS_CHECK_TIMEOUT_MS = 15_000;
const SQLITE_SIDE_SUFFIXES = ['-wal', '-shm', '-journal'] as const;
const WINDOWS_DIRECTORY_SCRIPT = [
  "$ErrorActionPreference='Stop'",
  "$path=[Environment]::GetEnvironmentVariable('KAVRIX_LOCAL_PATH_0','Process')",
  'if([String]::IsNullOrWhiteSpace($path)){exit 11}',
  '$identity=[Security.Principal.WindowsIdentity]::GetCurrent()',
  '$sid=$identity.User',
  'if(-not [IO.Directory]::Exists($path)){',
  '  $security=[Security.AccessControl.DirectorySecurity]::new()',
  '  $security.SetOwner($sid)',
  '  $security.SetAccessRuleProtection($true,$false)',
  "  $inherit=[Security.AccessControl.InheritanceFlags]'ContainerInherit,ObjectInherit'",
  '  $propagation=[Security.AccessControl.PropagationFlags]::None',
  '  $allow=[Security.AccessControl.AccessControlType]::Allow',
  '  $full=[Security.AccessControl.FileSystemRights]::FullControl',
  '  $rule=[Security.AccessControl.FileSystemAccessRule]::new($sid,$full,$inherit,$propagation,$allow)',
  '  [void]$security.AddAccessRule($rule)',
  '  [void][IO.Directory]::CreateDirectory($path,$security)',
  '}',
  '$item=[IO.DirectoryInfo]::new($path)',
  '$item.Refresh()',
  'if(-not $item.Exists){exit 12}',
  'if(($item.Attributes -band [IO.FileAttributes]::ReparsePoint)-ne 0){exit 12}',
  "$acl=$item.GetAccessControl('Access,Owner')",
  'if(-not $acl.AreAccessRulesProtected){exit 13}',
  'if($acl.GetOwner([Security.Principal.SecurityIdentifier]).Value -ne $sid.Value){exit 14}',
  '$rules=$acl.GetAccessRules($true,$true,[Security.Principal.SecurityIdentifier])',
  '$allowed=0',
  'foreach($entry in $rules){',
  '  if($entry.IsInherited){exit 15}',
  '  if($entry.AccessControlType -ne [Security.AccessControl.AccessControlType]::Allow){exit 16}',
  '  if($entry.IdentityReference.Value -ne $sid.Value){exit 17}',
  '  if(($entry.FileSystemRights -band [Security.AccessControl.FileSystemRights]::FullControl) -ne [Security.AccessControl.FileSystemRights]::FullControl){exit 18}',
  '  $allowed++',
  '}',
  'if($allowed -ne 1){exit 19}',
  "[Console]::Out.Write('OK')",
].join(';');
const WINDOWS_FILE_SCRIPT = [
  "$ErrorActionPreference='Stop'",
  "$countText=[Environment]::GetEnvironmentVariable('KAVRIX_LOCAL_ENTRY_COUNT','Process')",
  '$count=0',
  'if(-not [Int32]::TryParse($countText,[ref]$count) -or $count -lt 1 -or $count -gt 4){exit 31}',
  '$identity=[Security.Principal.WindowsIdentity]::GetCurrent()',
  '$sid=$identity.User',
  '$allow=[Security.AccessControl.AccessControlType]::Allow',
  '$full=[Security.AccessControl.FileSystemRights]::FullControl',
  'for($index=0;$index -lt $count;$index++){',
  "  $path=[Environment]::GetEnvironmentVariable(('KAVRIX_LOCAL_PATH_{0}' -f $index),'Process')",
  "  $mode=[Environment]::GetEnvironmentVariable(('KAVRIX_LOCAL_MODE_{0}' -f $index),'Process')",
  "  if([String]::IsNullOrWhiteSpace($path) -or ($mode -ne 'secure' -and $mode -ne 'verify')){exit 32}",
  '  $item=[IO.FileInfo]::new($path)',
  '  $item.Refresh()',
  '  if(-not $item.Exists){exit 33}',
  '  if(($item.Attributes -band [IO.FileAttributes]::ReparsePoint)-ne 0){exit 33}',
  "  $before=$item.GetAccessControl('Access,Owner')",
  '  if($before.GetOwner([Security.Principal.SecurityIdentifier]).Value -ne $sid.Value){exit 34}',
  '  $beforeRules=$before.GetAccessRules($true,$true,[Security.Principal.SecurityIdentifier])',
  '  $beforeAllowed=0',
  '  foreach($ruleEntry in $beforeRules){',
  '    if($ruleEntry.AccessControlType -ne $allow){exit 35}',
  '    if($ruleEntry.IdentityReference.Value -ne $sid.Value){exit 36}',
  '    if(($ruleEntry.FileSystemRights -band $full) -ne $full){exit 37}',
  "    if($mode -eq 'verify' -and $ruleEntry.IsInherited){exit 38}",
  '    $beforeAllowed++',
  '  }',
  '  if($beforeAllowed -lt 1){exit 39}',
  "  if($mode -eq 'verify'){",
  '    if(-not $before.AreAccessRulesProtected -or $beforeAllowed -ne 1){exit 40}',
  '  } else {',
  '    $security=[Security.AccessControl.FileSecurity]::new()',
  '    $security.SetOwner($sid)',
  '    $security.SetAccessRuleProtection($true,$false)',
  '    $rule=[Security.AccessControl.FileSystemAccessRule]::new($sid,$full,$allow)',
  '    [void]$security.AddAccessRule($rule)',
  '    $item.SetAccessControl($security)',
  '  }',
  "  $acl=$item.GetAccessControl('Access,Owner')",
  '  if(-not $acl.AreAccessRulesProtected){exit 41}',
  '  if($acl.GetOwner([Security.Principal.SecurityIdentifier]).Value -ne $sid.Value){exit 42}',
  '  $rules=$acl.GetAccessRules($true,$true,[Security.Principal.SecurityIdentifier])',
  '  $allowed=0',
  '  foreach($ruleEntry in $rules){',
  '    if($ruleEntry.IsInherited){exit 43}',
  '    if($ruleEntry.AccessControlType -ne $allow){exit 44}',
  '    if($ruleEntry.IdentityReference.Value -ne $sid.Value){exit 45}',
  '    if(($ruleEntry.FileSystemRights -band $full) -ne $full){exit 46}',
  '    $allowed++',
  '  }',
  '  if($allowed -ne 1){exit 47}',
  '}',
  "[Console]::Out.Write('OK')",
].join(';');

export async function prepareSecureDatabasePath(input: string): Promise<string> {
  const databasePath = await prepareSecureLeafParent(input);
  const existing = await statIfPresent(databasePath);
  if (existing === null) {
    let handle;
    try {
      handle = await open(databasePath, 'wx', 0o600);
    } catch {
      throw invalidState();
    }
    try {
      await handle.close();
    } catch {
      throw invalidState();
    }
    await secureNewLeaf(databasePath);
  } else {
    await verifySecureLeaf(databasePath);
  }
  await secureSqliteFiles(databasePath);
  return databasePath;
}

export async function prepareSecureLeafParent(input: string): Promise<string> {
  if (
    typeof input !== 'string' ||
    !isAbsolute(input) ||
    input.includes('\0') ||
    input.length > 4_096
  ) {
    throw invalidState();
  }
  const leafPath = resolve(input);
  const parent = dirname(leafPath);
  if (parent === leafPath) throw invalidState();

  if (process.platform === 'win32') await prepareWindowsDirectory(parent);
  /* v8 ignore next -- exercised by the Unix permission integration on Unix */
  else await prepareUnixDirectory(parent);
  await assertCanonicalDirectory(parent);
  return leafPath;
}

export async function secureNewLeaf(path: string): Promise<void> {
  const stats = await statIfPresent(path);
  if (stats === null || !isSafeFileIdentity(stats)) throw invalidState();
  if (process.platform === 'win32') {
    await prepareWindowsFiles([{ path, mode: 'secure' }]);
  } else {
    try {
      await chmod(path, 0o600);
    } catch {
      throw invalidState();
    }
  }
  await assertSecureFile(path);
}

export async function verifySecureLeaf(path: string): Promise<Stats> {
  const stats = await statIfPresent(path);
  if (stats === null || !isSafeFileIdentity(stats)) throw invalidState();
  if (process.platform === 'win32') {
    await prepareWindowsFiles([{ path, mode: 'verify' }]);
  }
  await assertSecureFile(path);
  return stats;
}

export async function secureSqliteFiles(
  databasePath: string,
  allowModeTightening = false,
): Promise<void> {
  const paths = [
    databasePath,
    ...SQLITE_SIDE_SUFFIXES.map((suffix) => `${databasePath}${suffix}`),
  ];
  const existingPaths: string[] = [];
  for (const path of paths) {
    const stats = await statIfPresent(path);
    if (stats === null) continue;
    if (!isSafeFileIdentity(stats)) throw invalidState();
    existingPaths.push(path);
    /* v8 ignore start -- exercised by the Unix permission integration on Unix */
    if (process.platform !== 'win32') {
      const mayTighten = allowModeTightening && path !== databasePath;
      if ((stats.mode & 0o777) !== 0o600 && !mayTighten) {
        throw invalidState();
      }
      try {
        await chmod(path, 0o600);
      } catch {
        if ((await statIfPresent(path)) === null) continue;
        throw invalidState();
      }
    }
    /* v8 ignore stop */
  }
  if (process.platform === 'win32' && existingPaths.length > 0) {
    await prepareWindowsFiles(
      existingPaths.map((path) => ({
        path,
        mode: allowModeTightening && path !== databasePath ? 'secure' : 'verify',
      })),
    );
  }
  for (const path of existingPaths) {
    if ((await statIfPresent(path)) !== null) await assertSecureFile(path);
  }
}

/* v8 ignore start -- exercised by the Unix permission integration on Unix */
async function prepareUnixDirectory(path: string): Promise<void> {
  const before = await statIfPresent(path);
  if (before === null) {
    try {
      await mkdir(path, { recursive: true, mode: 0o700 });
      await chmod(path, 0o700);
    } catch {
      throw invalidState();
    }
  }
  const stats = await statIfPresent(path);
  if (
    stats === null ||
    !stats.isDirectory() ||
    stats.isSymbolicLink() ||
    (stats.mode & 0o777) !== 0o700 ||
    !isCurrentOwner(stats.uid)
  ) {
    throw invalidState();
  }
}
/* v8 ignore stop */

async function prepareWindowsDirectory(path: string): Promise<void> {
  await runWindowsCheck(WINDOWS_DIRECTORY_SCRIPT, {
    KAVRIX_LOCAL_PATH_0: path,
  });
}

async function prepareWindowsFiles(
  entries: readonly { path: string; mode: 'secure' | 'verify' }[],
): Promise<void> {
  const environment: Record<string, string> = {
    KAVRIX_LOCAL_ENTRY_COUNT: String(entries.length),
  };
  for (const [index, entry] of entries.entries()) {
    environment[`KAVRIX_LOCAL_PATH_${String(index)}`] = entry.path;
    environment[`KAVRIX_LOCAL_MODE_${String(index)}`] = entry.mode;
  }
  await runWindowsCheck(WINDOWS_FILE_SCRIPT, environment);
}

function encodedCommand(script: string): string {
  return Buffer.from(script, 'utf16le').toString('base64');
}

function runWindowsCheck(
  script: string,
  environment: Readonly<Record<string, string>>,
): Promise<void> {
  return new Promise((resolvePromise, rejectPromise) => {
    const stdout: Uint8Array[] = [];
    let stdoutBytes = 0;
    let failed = false;
    const child = spawn(
      WINDOWS_POWERSHELL,
      [
        '-NoLogo',
        '-NoProfile',
        '-NonInteractive',
        '-ExecutionPolicy',
        'Bypass',
        '-EncodedCommand',
        encodedCommand(script),
      ],
      {
        shell: false,
        windowsHide: true,
        stdio: ['ignore', 'pipe', 'pipe'],
        env: {
          SystemRoot: WINDOWS_ROOT,
          WINDIR: WINDOWS_ROOT,
          ...environment,
        },
      },
    );
    /* v8 ignore next 4 -- the fixed trusted helper's OS failure path */
    const fail = (): void => {
      failed = true;
      child.kill('SIGKILL');
    };
    const timeout = setTimeout(fail, WINDOWS_CHECK_TIMEOUT_MS);
    timeout.unref();
    child.stdout.on('data', (value: Buffer) => {
      stdoutBytes += value.byteLength;
      /* v8 ignore next 5 -- the fixed helper emits only the bounded OK marker */
      if (stdoutBytes > 16) {
        value.fill(0);
        fail();
        return;
      }
      stdout.push(Uint8Array.from(value));
      value.fill(0);
    });
    /* v8 ignore next 4 -- PowerShell failures are covered through generic exit errors */
    child.stderr.on('data', (value: Buffer) => {
      value.fill(0);
      fail();
    });
    child.on('error', fail);
    child.on('close', (code, signal) => {
      clearTimeout(timeout);
      const valid =
        !failed &&
        code === 0 &&
        signal === null &&
        stdoutBytes === 2 &&
        stdout.length > 0;
      const combined = Buffer.concat(stdout);
      const matches = valid && combined.equals(Buffer.from('OK'));
      combined.fill(0);
      for (const value of stdout) value.fill(0);
      if (matches) resolvePromise();
      else rejectPromise(invalidState());
    });
  });
}

async function assertCanonicalDirectory(path: string): Promise<void> {
  let canonical: string;
  try {
    canonical = await realpath(path);
  } catch {
    throw invalidState();
  }
  const expected = resolve(path);
  const matches =
    process.platform === 'win32'
      ? canonical.toLowerCase() === expected.toLowerCase()
      : canonical === expected;
  if (!matches) throw invalidState();
}

async function assertSecureFile(path: string): Promise<void> {
  const stats = await statIfPresent(path);
  if (
    stats === null ||
    !isSafeFileIdentity(stats) ||
    (process.platform !== 'win32' &&
      ((stats.mode & 0o777) !== 0o600 || !isCurrentOwner(stats.uid)))
  ) {
    throw invalidState();
  }
}

function isSafeFileIdentity(stats: Awaited<ReturnType<typeof lstat>>): boolean {
  return (
    stats.isFile() &&
    !stats.isSymbolicLink() &&
    stats.nlink === 1 &&
    (process.platform === 'win32' || isCurrentOwner(stats.uid))
  );
}

async function statIfPresent(path: string): Promise<Stats | null> {
  try {
    return await lstat(path);
  } catch (error) {
    if (isMissing(error)) return null;
    throw invalidState();
  }
}

/* v8 ignore next -- exercised by the Unix permission integration on Unix */
function isCurrentOwner(uid: number | bigint): boolean {
  return (
    typeof process.getuid !== 'function' ||
    (typeof uid === 'number' && process.getuid() === uid)
  );
}

function isMissing(error: unknown): boolean {
  return (
    typeof error === 'object' &&
    error !== null &&
    'code' in error &&
    error.code === 'ENOENT'
  );
}

function invalidState(): SyncLocalStateError {
  return new SyncLocalStateError();
}
