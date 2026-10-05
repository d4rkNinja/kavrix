import { mkdtemp, mkdir, rm, lstat, writeFile, symlink } from 'node:fs/promises';
import { validateSecureFileDestination } from '@kavrix/key-files';
import { tmpdir } from 'node:os';
import { join, parse } from 'node:path';
import { afterEach, describe, expect, it } from 'vitest';
import { runSetupTool, connectionNotice } from '../src/setup-tools.js';
const scratch: string[] = [];
afterEach(async () => {
  for (const path of scratch.splice(0))
    await rm(path, { recursive: true, force: true });
});
async function fixture() {
  const root = await mkdtemp(join(tmpdir(), 'kavrix-setup-tools-'));
  scratch.push(root);
  const managed = join(root, 'managed');
  await mkdir(managed);
  return { root, managed };
}
describe('setup platform tools', () => {
  it('returns a finite connection result for invalid input without filesystem changes', async () => {
    const { managed } = await fixture();
    expect(
      await runSetupTool(
        {
          type: 'test-setup-mongodb',
          databaseUrl: 'private-invalid-input-canary',
          database: 'test',
        },
        managed,
      ),
    ).toEqual({ kind: 'connection', status: 'invalid' });
    expect(connectionNotice('invalid')).not.toContain('private-invalid-input-canary');
  });
  it.each(['ok', 'invalid', 'transport', 'authentication', 'unreachable'] as const)(
    'gives actionable public guidance for connection status %s',
    (status) => {
      const notice = connectionNotice(status);
      expect(notice.length).toBeGreaterThan(20);
      expect(notice).not.toContain('mongodb://');
      expect(notice).not.toContain('MongoServerError');
    },
  );
  it('refuses filesystem roots and managed paths that are files', async () => {
    const { root, managed } = await fixture();
    await expect(
      runSetupTool(
        {
          type: 'repair-setup-directory',
          path: join(parse(managed).root, 'new.key'),
          mode: 'apply',
        },
        parse(managed).root,
      ),
    ).rejects.toThrow('limited');
    const file = join(root, 'ordinary-file');
    await writeFile(file, 'ordinary-file-content-canary');
    await expect(
      runSetupTool(
        { type: 'repair-setup-directory', path: join(file, 'new.key'), mode: 'apply' },
        file,
      ),
    ).rejects.toThrow('limited');
  });
  it('lists only folders without returning file contents', async () => {
    const { root, managed } = await fixture();
    await mkdir(join(root, 'child'));
    await writeFile(join(root, 'private.key'), 'folder-browser-content-canary');
    const result = await runSetupTool(
      { type: 'browse-setup-folders', path: root },
      managed,
    );
    expect(result.kind).toBe('folders');
    expect(JSON.stringify(result)).not.toContain('folder-browser-content-canary');
    expect(JSON.stringify(result)).not.toContain('private.key');
    if (result.kind === 'folders')
      expect(result.entries.map((entry) => entry.name)).toEqual(['child', 'managed']);
  });
  it('previews repair without altering permissions', async () => {
    const { managed } = await fixture();
    const before = await lstat(managed);
    expect(
      await runSetupTool(
        {
          type: 'repair-setup-directory',
          path: join(managed, 'new.key'),
          mode: 'preview',
        },
        managed,
      ),
    ).toMatchObject({ kind: 'repair', mode: 'preview' });
    expect((await lstat(managed)).mode).toBe(before.mode);
  });
  it('refuses repair outside the managed directory before changing anything', async () => {
    const { root, managed } = await fixture();
    const before = await lstat(root);
    await expect(
      runSetupTool(
        { type: 'repair-setup-directory', path: join(root, 'new.key'), mode: 'apply' },
        managed,
      ),
    ).rejects.toThrow('outside');
    expect((await lstat(root)).mode).toBe(before.mode);
  });
  it('fails malformed actions before using their paths', async () => {
    await expect(
      runSetupTool({ type: 'browse-setup-folders', path: 'bad\0path' }, '/private'),
    ).rejects.toThrow();
  });
  it('applies owner-only permissions to the managed folder and makes a new destination usable', async () => {
    const { root, managed } = await fixture();
    const parentMode = (await lstat(root)).mode;
    const path = join(managed, 'new.key');
    const result = await runSetupTool(
      { type: 'repair-setup-directory', path, mode: 'apply' },
      managed,
    );
    expect(result).toMatchObject({ kind: 'repair', mode: 'apply' });
    await expect(validateSecureFileDestination(path)).resolves.toBeUndefined();
    expect((await lstat(root)).mode).toBe(parentMode);
    if (process.platform !== 'win32')
      expect((await lstat(managed)).mode & 0o777).toBe(0o700);
  });
  it('refuses a managed directory that is itself a symbolic link', async () => {
    const { root, managed } = await fixture();
    const alias = join(root, 'alias');
    await symlink(managed, alias, process.platform === 'win32' ? 'junction' : 'dir');
    await expect(
      runSetupTool(
        { type: 'repair-setup-directory', path: join(alias, 'new.key'), mode: 'apply' },
        alias,
      ),
    ).rejects.toThrow('limited');
  });
  it('limits browser entries and reports truncation', async () => {
    const { root, managed } = await fixture();
    await Promise.all(
      Array.from({ length: 105 }, (_, index) =>
        mkdir(join(root, `folder-${String(index)}`)),
      ),
    );
    const result = await runSetupTool(
      { type: 'browse-setup-folders', path: root },
      managed,
    );
    expect(result).toMatchObject({ kind: 'folders', truncated: true });
    if (result.kind === 'folders') expect(result.entries).toHaveLength(100);
  });
});
