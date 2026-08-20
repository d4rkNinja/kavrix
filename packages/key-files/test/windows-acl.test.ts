import { afterEach, describe, expect, it, vi } from 'vitest';

const execFileMock = vi.hoisted(() => vi.fn());

vi.mock('node:child_process', () => ({
  execFile: execFileMock,
}));

import { PortableKeyFileError } from '../src/errors.js';
import { verifyWindowsDirectoryAcl } from '../src/windows-acl.js';

afterEach(() => {
  vi.clearAllMocks();
});

describe('read-only Windows directory ACL verification', () => {
  it('passes the directory target to a non-mutating verifier that rejects ordinary writes', async () => {
    execFileMock.mockImplementation((...arguments_: readonly unknown[]) => {
      const callback = arguments_.at(-1);
      if (typeof callback === 'function') {
        callback(null, { stdout: Buffer.alloc(0), stderr: Buffer.alloc(0) });
      }
    });

    await expect(verifyWindowsDirectoryAcl('C:\\workspace')).resolves.toBeUndefined();

    const [executable, arguments_, options] = execFileMock.mock.calls[0] as [
      string,
      readonly string[],
      { env: Record<string, string> },
    ];
    expect(executable).toBe(
      'C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe',
    );
    expect(options.env['KAVRIX_ACL_TARGET']).toBe('C:\\workspace');
    const encodedIndex = arguments_.indexOf('-EncodedCommand');
    expect(encodedIndex).toBeGreaterThanOrEqual(0);
    const script = Buffer.from(arguments_[encodedIndex + 1]!, 'base64').toString(
      'utf16le',
    );
    expect(script).toContain("$administratorsSid = 'S-1-5-32-544'");
    expect(script).toContain('$hasWriteRights');
    expect(script).toContain(
      'if ($hasWriteRights -and $trustedSids -notcontains $ruleSid) { exit 2 }',
    );
    expect(script).not.toContain('SetAccessControl');
    expect(script).not.toContain('SetOwner');
    expect(script).not.toContain('SetAccessRuleProtection');
  });

  it('fails closed when ACL inspection reports an unsafe or malformed ACL', async () => {
    execFileMock.mockImplementation((...arguments_: readonly unknown[]) => {
      const callback = arguments_.at(-1);
      if (typeof callback === 'function') callback(new Error('ACL rejected'));
    });

    await expect(verifyWindowsDirectoryAcl('C:\\workspace')).rejects.toEqual(
      new PortableKeyFileError('KEY_FILE_UNSAFE'),
    );
  });
});
