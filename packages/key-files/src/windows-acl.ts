import { execFile } from 'node:child_process';
import { win32 } from 'node:path';
import { promisify } from 'node:util';

import { PortableKeyFileError } from './errors.js';

const execFileAsync = promisify(execFile);
const POWERSHELL_TIMEOUT_MS = 15_000;
const MAX_POWERSHELL_OUTPUT_BYTES = 16_384;
const TARGET_ENVIRONMENT_NAME = 'KAVRIX_ACL_TARGET';
// The ACL helper receives the portable-key path and is therefore security
// sensitive even though it never receives key bytes. Do not resolve it from
// PATH, SystemRoot, WINDIR, or another caller-controlled environment value.
const WINDOWS_SYSTEM_ROOT = String.raw`C:\Windows`;
const POWERSHELL_EXECUTABLE = win32.join(
  WINDOWS_SYSTEM_ROOT,
  'System32',
  'WindowsPowerShell',
  'v1.0',
  'powershell.exe',
);

const SET_USER_ONLY_ACL = String.raw`
$ErrorActionPreference = 'Stop'
$target = [Environment]::GetEnvironmentVariable('KAVRIX_ACL_TARGET', 'Process')
if ([String]::IsNullOrEmpty($target)) { exit 3 }
$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$sid = $identity.User
$acl = Get-Acl -LiteralPath $target -ErrorAction Stop
$acl.SetAccessRuleProtection($true, $false)
$rules = @($acl.GetAccessRules($true, $true, [Security.Principal.SecurityIdentifier]))
foreach ($rule in $rules) { [void]$acl.RemoveAccessRuleSpecific($rule) }
$acl.SetOwner($sid)
$fullControl = [Security.AccessControl.FileSystemRights]::FullControl
$allow = [Security.AccessControl.AccessControlType]::Allow
$inheritance = [Security.AccessControl.InheritanceFlags]::None
if ([IO.Directory]::Exists($target)) {
  $inheritance = [Security.AccessControl.InheritanceFlags]::ContainerInherit -bor [Security.AccessControl.InheritanceFlags]::ObjectInherit
}
$propagation = [Security.AccessControl.PropagationFlags]::None
$rule = [Security.AccessControl.FileSystemAccessRule]::new($sid, $fullControl, $inheritance, $propagation, $allow)
[void]$acl.AddAccessRule($rule)
Set-Acl -LiteralPath $target -AclObject $acl -ErrorAction Stop
`;

const VERIFY_USER_ONLY_ACL = String.raw`
$ErrorActionPreference = 'Stop'
$target = [Environment]::GetEnvironmentVariable('KAVRIX_ACL_TARGET', 'Process')
if ([String]::IsNullOrEmpty($target)) { exit 3 }
$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$currentSid = $identity.User.Value
$systemSid = 'S-1-5-18'
$acl = Get-Acl -LiteralPath $target -ErrorAction Stop
$ownerSid = $acl.GetOwner([Security.Principal.SecurityIdentifier]).Value
if (-not $acl.AreAccessRulesProtected -or $ownerSid -ne $currentSid) { exit 2 }
$rules = @($acl.GetAccessRules($true, $true, [Security.Principal.SecurityIdentifier]))
if ($rules.Count -eq 0) { exit 2 }
$hasCurrentUserAllow = $false
$hasSafeChildInheritance = -not [IO.Directory]::Exists($target)
foreach ($rule in $rules) {
  $ruleSid = $rule.IdentityReference.Value
  if ($rule.IsInherited) { exit 2 }
  if ($rule.AccessControlType -ne [Security.AccessControl.AccessControlType]::Allow) { exit 2 }
  if ($ruleSid -ne $currentSid -and $ruleSid -ne $systemSid) { exit 2 }
  if ($ruleSid -eq $currentSid) {
    $hasCurrentUserAllow = $true
    $required = [Security.AccessControl.InheritanceFlags]::ContainerInherit -bor [Security.AccessControl.InheritanceFlags]::ObjectInherit
    if (($rule.InheritanceFlags -band $required) -eq $required) { $hasSafeChildInheritance = $true }
  }
}
if (-not $hasCurrentUserAllow -or -not $hasSafeChildInheritance) { exit 2 }
`;

function encodedCommand(script: string): string {
  return Buffer.from(script, 'utf16le').toString('base64');
}

async function runAclCommand(script: string, targetPath: string): Promise<void> {
  try {
    await execFileAsync(
      POWERSHELL_EXECUTABLE,
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
        encoding: 'buffer',
        env: {
          [TARGET_ENVIRONMENT_NAME]: targetPath,
          SystemRoot: WINDOWS_SYSTEM_ROOT,
          WINDIR: WINDOWS_SYSTEM_ROOT,
        },
        maxBuffer: MAX_POWERSHELL_OUTPUT_BYTES,
        timeout: POWERSHELL_TIMEOUT_MS,
        windowsHide: true,
      },
    );
  } catch {
    throw new PortableKeyFileError('KEY_FILE_UNSAFE');
  }
}

export async function setWindowsUserOnlyAcl(targetPath: string): Promise<void> {
  await runAclCommand(SET_USER_ONLY_ACL, targetPath);
  await verifyWindowsUserOnlyAcl(targetPath);
}

export async function verifyWindowsUserOnlyAcl(targetPath: string): Promise<void> {
  await runAclCommand(VERIFY_USER_ONLY_ACL, targetPath);
}
