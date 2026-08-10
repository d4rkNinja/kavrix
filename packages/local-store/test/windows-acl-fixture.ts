import { execFile } from 'node:child_process';
import { promisify } from 'node:util';

const execFileAsync = promisify(execFile);
const WINDOWS_ICACLS = 'C:\\Windows\\System32\\icacls.exe';
const WINDOWS_ACL_FIXTURE_TIMEOUT_MS = 15_000;

export async function grantWindowsEveryoneFullControl(path: string): Promise<void> {
  await runIcacls(path, ['/grant', '*S-1-1-0:(F)']);
}

export async function removeWindowsEveryoneGrant(path: string): Promise<void> {
  await runIcacls(path, ['/remove:g', '*S-1-1-0']);
}

async function runIcacls(path: string, operation: readonly string[]): Promise<void> {
  await execFileAsync(WINDOWS_ICACLS, [path, ...operation], {
    env: { SystemRoot: 'C:\\Windows', WINDIR: 'C:\\Windows' },
    maxBuffer: 4_096,
    timeout: WINDOWS_ACL_FIXTURE_TIMEOUT_MS,
    windowsHide: true,
  });
}
