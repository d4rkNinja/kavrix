import { mkdtemp, mkdir, writeFile, rm, symlink } from 'node:fs/promises';
import { realpathSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { afterEach, describe, expect, it, vi } from 'vitest';

import { LocalCliError } from '../src/cli-error.js';
import {
  comparePublishedVersions,
  createDefaultSelfUpdateDeps,
  detectInstallKind,
  executeSelfUpdate,
  fetchNpmDistTagVersion,
  formatNpmInstallCommand,
  parsePublishedVersion,
  resolveNpmInvoker,
  type SelfUpdateDeps,
} from '../src/self-update.js';
import { buildLocalCli } from '../src/local-vault-cli.js';

describe('published version compare', () => {
  it('orders stable patches and minors', () => {
    expect(comparePublishedVersions('0.2.14', '0.2.15')).toBe(-1);
    expect(comparePublishedVersions('0.2.15', '0.2.15')).toBe(0);
    expect(comparePublishedVersions('0.3.0', '0.2.99')).toBe(1);
  });

  it('treats stable as newer than matching-core beta', () => {
    expect(comparePublishedVersions('0.2.16-beta.1', '0.2.16')).toBe(-1);
    expect(comparePublishedVersions('0.2.16', '0.2.16-beta.9')).toBe(1);
    expect(comparePublishedVersions('0.2.16-beta.1', '0.2.16-beta.2')).toBe(-1);
  });

  it('rejects unsupported versions', () => {
    expect(() => parsePublishedVersion('1.0.0-rc.1')).toThrow(LocalCliError);
  });
});

describe('formatNpmInstallCommand', () => {
  it('formats the default registry command with shell-safe quoting', () => {
    expect(formatNpmInstallCommand('0.2.16', 'https://registry.npmjs.org')).toBe(
      "npm install --global 'kavrix@0.2.16'",
    );
  });

  it('includes a custom registry with quoted args', () => {
    expect(formatNpmInstallCommand('0.2.16', 'https://example.test/npm/')).toBe(
      "npm install --global 'kavrix@0.2.16' --registry 'https://example.test/npm'",
    );
  });
});

describe('detectInstallKind', () => {
  const roots: string[] = [];

  afterEach(async () => {
    await Promise.all(
      roots.splice(0).map((root) => rm(root, { recursive: true, force: true })),
    );
  });

  async function fakeUnixGlobal(prefixName = 'prefix'): Promise<{
    prefix: string;
    packageRoot: string;
    distBin: string;
    binLink: string;
  }> {
    const root = await mkdtemp(join(tmpdir(), 'kavrix-update-'));
    roots.push(root);
    const prefix = join(root, prefixName);
    const packageRoot = join(prefix, 'lib', 'node_modules', 'kavrix');
    await mkdir(join(packageRoot, 'dist'), { recursive: true });
    await mkdir(join(prefix, 'bin'), { recursive: true });
    await writeFile(
      join(packageRoot, 'package.json'),
      '{"name":"kavrix","version":"0.2.16"}\n',
    );
    const distBin = join(packageRoot, 'dist', 'bin.js');
    await writeFile(distBin, '');
    const binLink = join(prefix, 'bin', 'kavrix');
    await symlink(distBin, binLink);
    return { prefix, packageRoot, distBin, binLink };
  }

  it('accepts a Unix lib/node_modules/kavrix global layout', async () => {
    const { packageRoot, distBin } = await fakeUnixGlobal();
    expect(detectInstallKind(distBin)).toEqual({
      kind: 'npm-global',
      method: 'npm-global',
      packageRoot: realpathSync(packageRoot),
    });
  });

  it('accepts a $PREFIX/bin/kavrix symlink to the global package (realpath)', async () => {
    const { packageRoot, binLink } = await fakeUnixGlobal();
    expect(detectInstallKind(binLink)).toEqual({
      kind: 'npm-global',
      method: 'npm-global',
      packageRoot: realpathSync(packageRoot),
    });
  });

  it('accepts Homebrew-Node npm-global under /opt/homebrew/lib/node_modules', async () => {
    const root = await mkdtemp(join(tmpdir(), 'kavrix-update-'));
    roots.push(root);
    // Simulate .../opt/homebrew/lib/node_modules/kavrix without Cellar.
    const packageRoot = join(root, 'opt', 'homebrew', 'lib', 'node_modules', 'kavrix');
    await mkdir(join(packageRoot, 'dist'), { recursive: true });
    await writeFile(
      join(packageRoot, 'package.json'),
      '{"name":"kavrix","version":"0.2.16"}\n',
    );
    const bin = join(packageRoot, 'dist', 'bin.js');
    await writeFile(bin, '');
    expect(detectInstallKind(bin)).toEqual({
      kind: 'npm-global',
      method: 'npm-global',
      packageRoot: realpathSync(packageRoot),
    });
  });

  it('rejects project-local node_modules/kavrix (not a global prefix)', async () => {
    const root = await mkdtemp(join(tmpdir(), 'kavrix-update-'));
    roots.push(root);
    const packageRoot = join(root, 'my-app', 'node_modules', 'kavrix');
    await mkdir(join(packageRoot, 'dist'), { recursive: true });
    await writeFile(join(packageRoot, 'package.json'), '{"name":"kavrix"}\n');
    const bin = join(packageRoot, 'dist', 'bin.js');
    await writeFile(bin, '');
    expect(detectInstallKind(bin)).toMatchObject({
      kind: 'unsupported',
      method: 'unknown',
    });
  });

  it('does not treat directories named kavrix-* as dev-checkout', async () => {
    const { packageRoot, distBin } = await fakeUnixGlobal('kavrix-tools');
    expect(detectInstallKind(distBin)).toEqual({
      kind: 'npm-global',
      method: 'npm-global',
      packageRoot: realpathSync(packageRoot),
    });
  });

  it('rejects npx caches', () => {
    const result = detectInstallKind(
      '/home/user/.npm/_npx/abc123/node_modules/kavrix/dist/bin.js',
    );
    expect(result).toMatchObject({ kind: 'unsupported', method: 'npx' });
  });

  it('rejects Homebrew Cellar paths', () => {
    const result = detectInstallKind('/opt/homebrew/Cellar/kavrix/0.2.15/bin/kavrix');
    expect(result).toMatchObject({ kind: 'unsupported', method: 'homebrew' });
  });

  it('rejects pnpm global stores', () => {
    const result = detectInstallKind(
      '/home/user/.local/share/pnpm/global/5/.pnpm/kavrix@0.2.15/node_modules/kavrix/dist/bin.js',
    );
    expect(result).toMatchObject({ kind: 'unsupported', method: 'pnpm' });
  });

  it('rejects yarn global paths', () => {
    const result = detectInstallKind(
      '/home/user/.yarn/global/node_modules/kavrix/dist/bin.js',
    );
    expect(result).toMatchObject({ kind: 'unsupported', method: 'yarn' });
  });

  it('rejects apps/cli workspace trees', () => {
    const result = detectInstallKind('/workspace/kavrix/apps/cli/dist/bin.js');
    expect(result).toMatchObject({ kind: 'unsupported', method: 'dev-checkout' });
  });
});

describe('resolveNpmInvoker', () => {
  it('uses npm on non-Windows', () => {
    expect(resolveNpmInvoker('linux', '/usr/bin/node')).toEqual({
      command: 'npm',
      argsPrefix: [],
    });
  });
});

describe('fetchNpmDistTagVersion', () => {
  it('reads dist-tags.latest', async () => {
    const fetchImpl = vi.fn(async () =>
      Response.json({ 'dist-tags': { latest: '0.2.15', beta: '0.2.16-beta.1' } }),
    );
    await expect(
      fetchNpmDistTagVersion({
        packageName: 'kavrix',
        distTag: 'latest',
        registry: 'https://registry.npmjs.org',
        fetchImpl: fetchImpl as unknown as typeof fetch,
      }),
    ).resolves.toBe('0.2.15');
  });

  it('fails closed on missing tag', async () => {
    const fetchImpl = vi.fn(async () =>
      Response.json({ 'dist-tags': { latest: '0.2.15' } }),
    );
    await expect(
      fetchNpmDistTagVersion({
        packageName: 'kavrix',
        distTag: 'next',
        registry: 'https://registry.npmjs.org',
        fetchImpl: fetchImpl as unknown as typeof fetch,
      }),
    ).rejects.toThrow(/dist-tag/);
  });

  it('fails closed when the registry is unreachable', async () => {
    const fetchImpl = vi.fn(async () => {
      throw new TypeError('network down');
    });
    await expect(
      fetchNpmDistTagVersion({
        packageName: 'kavrix',
        distTag: 'latest',
        registry: 'https://registry.npmjs.org',
        fetchImpl: fetchImpl as unknown as typeof fetch,
      }),
    ).rejects.toThrow(/offline|blocked|reach/i);
  });
});

describe('executeSelfUpdate', () => {
  function deps(
    partial: Partial<SelfUpdateDeps> & Pick<SelfUpdateDeps, 'currentVersion'>,
  ): SelfUpdateDeps {
    return createDefaultSelfUpdateDeps({
      argv1: '/usr/lib/node_modules/kavrix/dist/bin.js',
      detectInstall: () => ({
        kind: 'npm-global',
        method: 'npm-global',
        packageRoot: '/usr/lib/node_modules/kavrix',
      }),
      fetchRegistry: async () => '0.2.16',
      resolveNpm: () => ({ command: 'npm', argsPrefix: [] }),
      runNpmInstall: async () => ({ status: 0, stdout: 'ok\n', stderr: '' }),
      stdoutIsTTY: false,
      writeStdout: () => undefined,
      writeStderr: () => undefined,
      readInstalledVersion: () => '0.2.16',
      ...partial,
    });
  }

  it('reports up-to-date without installing', async () => {
    const runNpmInstall = vi.fn(async () => ({ status: 0, stdout: '', stderr: '' }));
    const chunks: string[] = [];
    const report = await executeSelfUpdate(
      { check: true, json: true },
      deps({
        currentVersion: '0.2.16',
        fetchRegistry: async () => '0.2.16',
        runNpmInstall,
        writeStdout: (text) => {
          chunks.push(text);
        },
      }),
    );
    expect(report.updateAvailable).toBe(false);
    expect(report.action).toBe('check');
    expect(runNpmInstall).not.toHaveBeenCalled();
    expect(JSON.parse(chunks.join(''))).toEqual({
      installed: '0.2.16',
      latest: '0.2.16',
      updateAvailable: false,
      channel: 'latest',
      action: 'check',
    });
  });

  it('check mode reports available update without installing and stays exit-friendly', async () => {
    const runNpmInstall = vi.fn(async () => ({ status: 0, stdout: '', stderr: '' }));
    const report = await executeSelfUpdate(
      { check: true, json: true },
      deps({
        currentVersion: '0.2.15',
        fetchRegistry: async () => '0.2.16',
        runNpmInstall,
      }),
    );
    expect(report).toMatchObject({
      updateAvailable: true,
      action: 'check',
      installed: '0.2.15',
      latest: '0.2.16',
    });
    expect(runNpmInstall).not.toHaveBeenCalled();
  });

  it('prints old → new and installs when behind latest on an npm-global layout', async () => {
    const runNpmInstall = vi.fn(async (input) => {
      expect(input.version).toBe('0.2.16');
      return { status: 0, stdout: 'added 1\n', stderr: '' };
    });
    const report = await executeSelfUpdate(
      { json: true },
      deps({
        currentVersion: '0.2.15',
        runNpmInstall,
      }),
    );
    expect(report.action).toBe('updated');
    expect(report.message).toContain('0.2.15');
    expect(report.message).toContain('0.2.16');
    expect(runNpmInstall).toHaveBeenCalledOnce();
  });

  it('refuses unsupported installs with a method-specific error and exact npm command', async () => {
    const runNpmInstall = vi.fn(async () => ({ status: 0, stdout: '', stderr: '' }));
    const chunks: string[] = [];
    await expect(
      executeSelfUpdate(
        { json: true },
        deps({
          currentVersion: '0.2.15',
          detectInstall: () => ({
            kind: 'unsupported',
            method: 'npx',
            detail: 'This kavrix process was launched via npx.',
          }),
          runNpmInstall,
          writeStdout: (text) => {
            chunks.push(text);
          },
        }),
      ),
    ).rejects.toMatchObject({ name: 'CodedCliError', exitCode: 14 });
    expect(runNpmInstall).not.toHaveBeenCalled();
    expect(JSON.parse(chunks.join(''))).toMatchObject({
      action: 'refused',
      error: expect.stringMatching(/npx/),
    });
  });

  it('refuses unsupported installs even when already at/ahead of the registry', async () => {
    const runNpmInstall = vi.fn(async () => ({ status: 0, stdout: '', stderr: '' }));
    const chunks: string[] = [];
    await expect(
      executeSelfUpdate(
        { json: true },
        deps({
          currentVersion: '0.2.16',
          fetchRegistry: async () => '0.2.15',
          detectInstall: () => ({
            kind: 'unsupported',
            method: 'dev-checkout',
            detail: 'This kavrix binary looks like a workspace/dev checkout.',
          }),
          runNpmInstall,
          writeStdout: (text) => {
            chunks.push(text);
          },
        }),
      ),
    ).rejects.toMatchObject({ name: 'CodedCliError', exitCode: 14 });
    expect(runNpmInstall).not.toHaveBeenCalled();
    expect(JSON.parse(chunks.join('')).error).toMatch(/workspace\/dev checkout/);
  });

  it('check mode notes unsupported layouts instead of silent already-newest success', async () => {
    const chunks: string[] = [];
    const report = await executeSelfUpdate(
      { check: true, json: true },
      deps({
        currentVersion: '0.2.16',
        fetchRegistry: async () => '0.2.15',
        detectInstall: () => ({
          kind: 'unsupported',
          method: 'dev-checkout',
          detail: 'This kavrix binary looks like a workspace/dev checkout.',
        }),
        writeStdout: (text) => {
          chunks.push(text);
        },
      }),
    );
    expect(report.action).toBe('check');
    expect(report.updateAvailable).toBe(false);
    expect(report.installMethod).toBe('dev-checkout');
    expect(report.error).toMatch(/workspace\/dev checkout/);
    expect(JSON.parse(chunks.join('')).error).toMatch(/workspace\/dev checkout/);
  });

  it('surfaces npm install failures with the exact command and EACCES tip', async () => {
    const chunks: string[] = [];
    await expect(
      executeSelfUpdate(
        { json: true },
        deps({
          currentVersion: '0.2.15',
          runNpmInstall: async () => ({
            status: 1,
            stdout: '',
            stderr: 'npm ERR! code EACCES\nnpm ERR! permission denied\n',
          }),
          writeStdout: (text) => {
            chunks.push(text);
          },
        }),
      ),
    ).rejects.toBeInstanceOf(LocalCliError);
    expect(chunks.join('')).toMatch(
      /npm install --global 'kavrix@0\.2\.16'[\s\S]*EACCES[\s\S]*~\/\.local/,
    );
  });

  it('TTY check on unsupported layouts paints error status, not OK', async () => {
    const chunks: string[] = [];
    const report = await executeSelfUpdate(
      { check: true },
      deps({
        currentVersion: '0.2.16',
        fetchRegistry: async () => '0.2.15',
        detectInstall: () => ({
          kind: 'unsupported',
          method: 'dev-checkout',
          detail: 'This kavrix binary looks like a workspace/dev checkout.',
        }),
        stdoutIsTTY: true,
        writeStdout: (text) => {
          chunks.push(text);
        },
      }),
    );
    expect(report.error).toBeDefined();
    expect(chunks.join('')).toMatch(/\[X\]/);
    expect(chunks.join('')).not.toMatch(/\[OK\]/);
  });

  it('emits JSON on --json registry failures and exits 0 under --check', async () => {
    const chunks: string[] = [];
    const report = await executeSelfUpdate(
      { check: true, json: true },
      deps({
        currentVersion: '0.2.15',
        fetchRegistry: async () => {
          throw new LocalCliError('Could not reach the npm registry (offline).');
        },
        writeStdout: (text) => {
          chunks.push(text);
        },
      }),
    );
    expect(report.action).toBe('failed');
    expect(JSON.parse(chunks.join(''))).toMatchObject({
      action: 'failed',
      error: expect.stringMatching(/offline/),
    });
  });
});

describe('kavrix update command wiring', () => {
  it('registers update on the root program with Jr help/flags', () => {
    const program = buildLocalCli();
    const update = program.commands.find((command) => command.name() === 'update');
    expect(update).toBeDefined();
    expect(update?.description()).toMatch(/global npm install of kavrix/i);
    expect(update?.description()).toMatch(/Homebrew/i);
    const flags = new Set(
      (update?.options ?? [])
        .map((option) => option.long)
        .filter((flag): flag is string => flag !== undefined),
    );
    expect(flags.has('--check')).toBe(true);
    expect(flags.has('--json')).toBe(true);
    expect(flags.has('--tag')).toBe(true);
    expect(flags.has('--registry')).toBe(true);
    expect(flags.has('--force')).toBe(false);
  });
});
