import { mkdtemp, mkdir, writeFile, rm } from 'node:fs/promises';
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
  it('formats the default registry command', () => {
    expect(formatNpmInstallCommand('0.2.16', 'https://registry.npmjs.org')).toBe(
      'npm install --global kavrix@0.2.16',
    );
  });

  it('includes a custom registry', () => {
    expect(formatNpmInstallCommand('0.2.16', 'https://example.test/npm/')).toBe(
      'npm install --global kavrix@0.2.16 --registry https://example.test/npm',
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

  it('accepts a node_modules/kavrix layout', async () => {
    const root = await mkdtemp(join(tmpdir(), 'kavrix-update-'));
    roots.push(root);
    const packageRoot = join(root, 'node_modules', 'kavrix');
    await mkdir(join(packageRoot, 'dist'), { recursive: true });
    await writeFile(join(packageRoot, 'package.json'), '{"name":"kavrix"}\n');
    const bin = join(packageRoot, 'dist', 'bin.js');
    await writeFile(bin, '');
    expect(detectInstallKind(bin)).toEqual({
      kind: 'npm-global',
      method: 'npm-global',
      packageRoot,
    });
  });

  it('rejects npx caches', () => {
    const result = detectInstallKind(
      '/home/user/.npm/_npx/abc123/node_modules/kavrix/dist/bin.js',
    );
    expect(result).toMatchObject({ kind: 'unsupported', method: 'npx' });
  });

  it('rejects Homebrew Cellar paths', () => {
    const result = detectInstallKind(
      '/opt/homebrew/Cellar/kavrix/0.2.15/bin/kavrix',
    );
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

  it('rejects source trees outside node_modules/kavrix', () => {
    const result = detectInstallKind(
      '/workspace/kavrix-tui-dev/apps/cli/dist/bin.js',
    );
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
        }),
      ),
    ).rejects.toThrow(/npx/);
    expect(runNpmInstall).not.toHaveBeenCalled();
  });

  it('refuses unsupported installs even when already at/ahead of the registry', async () => {
    const runNpmInstall = vi.fn(async () => ({ status: 0, stdout: '', stderr: '' }));
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
        }),
      ),
    ).rejects.toThrow(/workspace\/dev checkout/);
    expect(runNpmInstall).not.toHaveBeenCalled();
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
        }),
      ),
    ).rejects.toThrow(/npm install --global kavrix@0\.2\.16[\s\S]*EACCES[\s\S]*~\/\.local/);
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
