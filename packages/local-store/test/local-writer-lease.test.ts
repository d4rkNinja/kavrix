import { execFileSync } from 'node:child_process';
import { randomUUID } from 'node:crypto';
import { realpathSync } from 'node:fs';
import { chmod, link, readFile, rename, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { afterEach, describe, expect, it } from 'vitest';

import { SyncLocalStateError } from '@kavrix/sync';

import { acquireLocalWriterLease, recoverStaleLocalWriterLease } from '../src/index.js';
import { secureNewLeaf } from '../src/path-security.js';

const WINDOWS_POWERSHELL =
  'C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe';
const TEST_TMPDIR = realpathSync(tmpdir());
const roots: string[] = [];

afterEach(async () => {
  await Promise.all(
    roots.splice(0).map((root) => rm(root, { force: true, recursive: true })),
  );
});

describe('local writer lease', () => {
  it('excludes a second writer and permits reacquisition only after bound release', async () => {
    const path = leasePath();
    const first = await acquireLocalWriterLease(path);
    await expect(acquireLocalWriterLease(path)).rejects.toBeInstanceOf(
      SyncLocalStateError,
    );
    await expect(recoverStaleLocalWriterLease(path)).rejects.toBeInstanceOf(
      SyncLocalStateError,
    );
    await first.release();
    await first.release();

    const next = await acquireLocalWriterLease(path);
    await next.release();
  });

  it('fails closed on a crash-stale file and never steals it', async () => {
    const path = leasePath();
    const bootstrap = await acquireLocalWriterLease(`${path}.bootstrap`);
    await bootstrap.release();
    await writeFile(path, 'stale', { flag: 'wx', mode: 0o600 });
    await secureNewLeaf(path);

    await expect(acquireLocalWriterLease(path)).rejects.toBeInstanceOf(
      SyncLocalStateError,
    );
    await expect(recoverStaleLocalWriterLease(path)).rejects.toBeInstanceOf(
      SyncLocalStateError,
    );
    await expect(
      writeFile(path, 'still-present', { flag: 'wx' }),
    ).rejects.toMatchObject({ code: 'EEXIST' });
  });

  it('rejects noncanonical or impossible stale-owner metadata', async () => {
    for (const metadata of [
      'null',
      '[]',
      JSON.stringify({ version: 2, pid: 123, nonce: 'A'.repeat(22) }),
      JSON.stringify({ version: 1, pid: 0, nonce: 'A'.repeat(22) }),
      JSON.stringify({ version: 1, pid: 123, nonce: 'unsafe+nonce' }),
      JSON.stringify({
        version: 1,
        pid: 123,
        nonce: 'A'.repeat(22),
        extra: true,
      }),
    ]) {
      const path = leasePath();
      const bootstrap = await acquireLocalWriterLease(`${path}.bootstrap`);
      await bootstrap.release();
      await writeFile(path, metadata, { flag: 'wx', mode: 0o600 });
      await secureNewLeaf(path);
      await expect(recoverStaleLocalWriterLease(path)).rejects.toBeInstanceOf(
        SyncLocalStateError,
      );
    }
  }, 30_000);

  it('writes bounded canonical versioned owner metadata without secrets', async () => {
    const path = leasePath();
    const lease = await acquireLocalWriterLease(path);
    const encoded = await readFile(path);
    try {
      expect(encoded.byteLength).toBeLessThanOrEqual(256);
      const text = encoded.toString('utf8');
      const metadata = JSON.parse(text) as Record<string, unknown>;
      expect(Object.keys(metadata)).toEqual(['version', 'pid', 'nonce']);
      expect(metadata).toMatchObject({ version: 1, pid: process.pid });
      expect(metadata['nonce']).toMatch(/^[A-Za-z0-9_-]{22}$/u);
      expect(JSON.stringify(metadata)).toBe(text);
      expect(text).not.toMatch(/bearer|secret|token|vault|device/iu);
    } finally {
      encoded.fill(0);
      await lease.release();
    }
    await expect(recoverStaleLocalWriterLease(path)).resolves.toBe('absent');
  });

  it('does not unlink a replacement path during release', async () => {
    const path = leasePath();
    const displaced = `${path}.displaced`;
    const lease = await acquireLocalWriterLease(path);
    await rename(path, displaced);
    await writeFile(path, 'replacement', { flag: 'wx', mode: 0o600 });
    await secureNewLeaf(path);

    await expect(lease.release()).rejects.toBeInstanceOf(SyncLocalStateError);
    await expect(writeFile(path, 'must-remain', { flag: 'wx' })).rejects.toMatchObject({
      code: 'EEXIST',
    });
  });

  it('fails closed when an acquired lease gains another hardlink', async () => {
    const path = leasePath();
    const alias = `${path}.alias`;
    const lease = await acquireLocalWriterLease(path);
    await link(path, alias);

    await expect(recoverStaleLocalWriterLease(path)).rejects.toBeInstanceOf(
      SyncLocalStateError,
    );
    await expect(lease.release()).rejects.toBeInstanceOf(SyncLocalStateError);
    await expect(writeFile(alias, 'must-remain', { flag: 'wx' })).rejects.toMatchObject(
      {
        code: 'EEXIST',
      },
    );
  });

  it('rejects a live lease whose owner-only protection is weakened', async () => {
    const path = leasePath();
    const lease = await acquireLocalWriterLease(path);
    if (process.platform === 'win32') grantEveryone(path);
    else await chmod(path, 0o644);

    await expect(lease.release()).rejects.toBeInstanceOf(SyncLocalStateError);
  });

  it.runIf(process.platform === 'win32')(
    'creates a protected current-user-only Windows lease leaf',
    async () => {
      const path = leasePath();
      const lease = await acquireLocalWriterLease(path);
      expectCurrentUserOnly(path);
      await lease.release();
    },
  );
});

function leasePath(): string {
  const root = join(
    TEST_TMPDIR,
    `kavrix-writer-lease-${randomUUID().replaceAll('-', '')}`,
  );
  roots.push(root);
  return join(root, 'state.writer.lock');
}

function grantEveryone(path: string): void {
  const script = [
    "$ErrorActionPreference='Stop'",
    '$path=[Console]::In.ReadToEnd()',
    '$item=Get-Item -LiteralPath $path -Force',
    "$acl=$item.GetAccessControl('Access,Owner')",
    '$world=New-Object Security.Principal.SecurityIdentifier("S-1-1-0")',
    '$allow=[Security.AccessControl.AccessControlType]::Allow',
    '$full=[Security.AccessControl.FileSystemRights]::FullControl',
    '$rule=New-Object Security.AccessControl.FileSystemAccessRule($world,$full,$allow)',
    '[void]$acl.AddAccessRule($rule)',
    '$acl.SetAccessRuleProtection($true,$true)',
    '$item.SetAccessControl($acl)',
  ].join(';');
  execFileSync(
    WINDOWS_POWERSHELL,
    ['-NoLogo', '-NoProfile', '-NonInteractive', '-Sta', '-Command', script],
    {
      env: { SystemRoot: 'C:\\Windows' },
      input: path,
      maxBuffer: 4_096,
      timeout: 5_000,
      windowsHide: true,
    },
  );
}

function expectCurrentUserOnly(path: string): void {
  const script = [
    "$ErrorActionPreference='Stop'",
    '$path=[Console]::In.ReadToEnd()',
    '$item=Get-Item -LiteralPath $path -Force',
    "$acl=$item.GetAccessControl('Access,Owner')",
    '$sid=[Security.Principal.WindowsIdentity]::GetCurrent().User',
    'if(-not $acl.AreAccessRulesProtected){exit 41}',
    'if($acl.GetOwner([Security.Principal.SecurityIdentifier]).Value -ne $sid.Value){exit 42}',
    '$rules=$acl.GetAccessRules($true,$true,[Security.Principal.SecurityIdentifier])',
    'if($rules.Count -ne 1){exit 43}',
    '$rule=$rules[0]',
    'if($rule.IsInherited){exit 44}',
    'if($rule.AccessControlType -ne [Security.AccessControl.AccessControlType]::Allow){exit 45}',
    'if($rule.IdentityReference.Value -ne $sid.Value){exit 46}',
    "[Console]::Out.Write('OK')",
  ].join(';');
  const output = execFileSync(
    WINDOWS_POWERSHELL,
    ['-NoLogo', '-NoProfile', '-NonInteractive', '-Sta', '-Command', script],
    {
      env: { SystemRoot: 'C:\\Windows' },
      input: path,
      maxBuffer: 4_096,
      timeout: 5_000,
      windowsHide: true,
    },
  );
  try {
    expect(output.toString('utf8')).toBe('OK');
  } finally {
    output.fill(0);
  }
}
