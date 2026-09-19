import { mkdtemp, mkdir, writeFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { afterEach, describe, expect, it, vi } from 'vitest';

import { LocalCliError } from '../src/cli-error.js';
import { CodedCliError } from '../src/execution/exit-codes.js';
import { buildLocalCli } from '../src/local-vault-cli.js';
import {
  comparePublishedVersions,
  createDefaultSelfUpdateDeps,
  detectInstallKind,
  executeSelfUpdate,
  fetchNpmDistTagVersion,
  parsePublishedVersion,
  resolveNpmInvoker,
  type SelfUpdateDeps,
} from '../src/self-update.js';

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

  it('rejects source trees outside node_modules/kavrix', () => {
    expect(
      detectInstallKind('/workspace/kavrix-tui-dev/apps/cli/dist/bin.js').kind,
    ).toBe('unsupported');
  });

  it('classifies npx cache paths', () => {
    expect(
      detectInstallKind('/home/user/.npm/_npx/abc/node_modules/kavrix/dist/bin.js'),
    ).toMatchObject({ kind: 'unsupported', method: 'npx' });
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
    ).rejects.toThrow(/dist-tag/iu);
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
    expect(JSON.parse(chunks.join(''))).toMatchObject({
      installed: '0.2.16',
      latest: '0.2.16',
      updateAvailable: false,
    });
  });

  it('check mode reports available update without installing', async () => {
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
      latest: '0.2.16',
    });
    expect(runNpmInstall).not.toHaveBeenCalled();
  });

  it('installs when behind latest on an npm-global layout', async () => {
    const runNpmInstall = vi.fn(async (input) => {
      expect(input.version).toBe('0.2.16');
      return { status: 0, stdout: 'added 1\n', stderr: '' };
    });
    const report = await executeSelfUpdate(
      { json: true },
      deps({ currentVersion: '0.2.15', runNpmInstall }),
    );
    expect(report.action).toBe('updated');
    expect(runNpmInstall).toHaveBeenCalledOnce();
  });

  it('refuses unsupported installs', async () => {
    const runNpmInstall = vi.fn(async () => ({ status: 0, stdout: '', stderr: '' }));
    await expect(
      executeSelfUpdate(
        { json: true },
        deps({
          currentVersion: '0.2.15',
          detectInstall: () => ({
            kind: 'unsupported',
            method: 'unknown',
            detail: 'Not a global npm install.',
          }),
          runNpmInstall,
        }),
      ),
    ).rejects.toBeInstanceOf(CodedCliError);
    expect(runNpmInstall).not.toHaveBeenCalled();
  });

  it('surfaces npm install failures', async () => {
    await expect(
      executeSelfUpdate(
        { json: true },
        deps({
          currentVersion: '0.2.15',
          runNpmInstall: async () => ({
            status: 1,
            stdout: '',
            stderr: 'EACCES: permission denied\n',
          }),
        }),
      ),
    ).rejects.toThrow(/EACCES|npm install/iu);
  });
});

describe('kavrix update command wiring', () => {
  it('registers update on the root program', () => {
    const program = buildLocalCli();
    const update = program.commands.find((command) => command.name() === 'update');
    expect(update).toBeDefined();
    expect(update?.description().toLowerCase()).toMatch(/npm|upgrade|global/u);
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
