import { readdir, readFile } from 'node:fs/promises';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';

import { describe, expect, it } from 'vitest';

import {
  reachableProductionPackages,
  type WorkspaceManifest,
} from './dependency-graph.js';

const workspaceRoot = fileURLToPath(new URL('../../../', import.meta.url));

const allowedApiProductionPackages = [
  '@kavrix/api',
  '@kavrix/core',
  '@kavrix/schemas',
  '@kavrix/storage',
] as const;

const forbiddenApiProductionPackages = new Set([
  '@kavrix/client',
  '@kavrix/clipboard',
  '@kavrix/crypto',
  '@kavrix/import-export',
  '@kavrix/key-files',
  '@kavrix/keychain',
  '@kavrix/local-store',
  '@kavrix/runner',
  '@kavrix/sync',
  '@kavrix/tui',
]);

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

function parseDependencies(
  value: unknown,
  manifestPath: string,
): Readonly<Record<string, string>> {
  if (value === undefined) {
    return {};
  }
  if (!isRecord(value)) {
    throw new Error(`Invalid dependencies in ${manifestPath}`);
  }

  const dependencies: Record<string, string> = {};
  for (const [name, version] of Object.entries(value)) {
    if (typeof version !== 'string') {
      throw new Error(`Invalid dependency ${name} in ${manifestPath}`);
    }
    dependencies[name] = version;
  }
  return dependencies;
}

function parseManifest(contents: string, manifestPath: string): WorkspaceManifest {
  const value: unknown = JSON.parse(contents);
  if (!isRecord(value) || typeof value['name'] !== 'string') {
    throw new Error(`Invalid workspace manifest ${manifestPath}`);
  }
  return {
    name: value['name'],
    dependencies: parseDependencies(value['dependencies'], manifestPath),
  };
}

async function discoverWorkspaceManifests(): Promise<readonly WorkspaceManifest[]> {
  const manifests: WorkspaceManifest[] = [];
  for (const workspaceDirectory of ['apps', 'packages']) {
    const directory = join(workspaceRoot, workspaceDirectory);
    const entries = await readdir(directory, { withFileTypes: true });
    for (const entry of entries) {
      if (!entry.isDirectory()) {
        continue;
      }
      const manifestPath = join(directory, entry.name, 'package.json');
      manifests.push(parseManifest(await readFile(manifestPath, 'utf8'), manifestPath));
    }
  }
  return manifests;
}

describe('API production dependency graph', () => {
  it('reaches exactly the server-safe Kavrix packages in the live workspace', async () => {
    const manifests = await discoverWorkspaceManifests();

    const reachable = reachableProductionPackages(
      manifests,
      '@kavrix/api',
      forbiddenApiProductionPackages,
    );

    expect([...reachable].sort()).toEqual(allowedApiProductionPackages);
  });

  it('ignores development-only dependency fixtures', () => {
    const manifests: readonly WorkspaceManifest[] = [
      {
        name: '@kavrix/api',
        dependencies: { '@kavrix/storage': 'workspace:*' },
      },
      {
        name: '@kavrix/storage',
        dependencies: {},
        devDependencies: { '@kavrix/crypto': 'workspace:*' },
      },
      { name: '@kavrix/crypto', dependencies: {} },
    ];

    const reachable = reachableProductionPackages(
      manifests,
      '@kavrix/api',
      forbiddenApiProductionPackages,
    );

    expect([...reachable].sort()).toEqual(['@kavrix/api', '@kavrix/storage']);
  });

  it('reports the full path for an indirect forbidden production edge', () => {
    const manifests: readonly WorkspaceManifest[] = [
      {
        name: '@kavrix/api',
        dependencies: { '@kavrix/storage': 'workspace:*' },
      },
      {
        name: '@kavrix/storage',
        dependencies: { '@kavrix/crypto': 'workspace:*' },
      },
      { name: '@kavrix/crypto', dependencies: {} },
    ];

    expect(() =>
      reachableProductionPackages(
        manifests,
        '@kavrix/api',
        forbiddenApiProductionPackages,
      ),
    ).toThrow(
      'Forbidden Kavrix production dependency path: @kavrix/api -> @kavrix/storage -> @kavrix/crypto',
    );
  });

  it('resolves workspace aliases and reports the full forbidden target path', () => {
    const manifests: readonly WorkspaceManifest[] = [
      {
        name: '@kavrix/api',
        dependencies: { bridge: 'workspace:@kavrix/crypto@*' },
      },
      { name: '@kavrix/crypto', dependencies: {} },
    ];

    expect(() =>
      reachableProductionPackages(
        manifests,
        '@kavrix/api',
        forbiddenApiProductionPackages,
      ),
    ).toThrow(
      'Forbidden Kavrix production dependency path: @kavrix/api -> bridge -> @kavrix/crypto',
    );
  });

  it('traverses a server-safe workspace alias by its target package', () => {
    const manifests: readonly WorkspaceManifest[] = [
      {
        name: '@kavrix/api',
        dependencies: { bridge: 'workspace:@kavrix/core@*' },
      },
      {
        name: '@kavrix/core',
        dependencies: { '@kavrix/schemas': 'workspace:*' },
      },
      { name: '@kavrix/schemas', dependencies: {} },
    ];

    const reachable = reachableProductionPackages(
      manifests,
      '@kavrix/api',
      forbiddenApiProductionPackages,
    );

    expect([...reachable].sort()).toEqual([
      '@kavrix/api',
      '@kavrix/core',
      '@kavrix/schemas',
    ]);
  });

  it('fails closed on an unknown unscoped workspace dependency', () => {
    const manifests: readonly WorkspaceManifest[] = [
      {
        name: '@kavrix/api',
        dependencies: { bridge: 'workspace:*' },
      },
    ];

    expect(() =>
      reachableProductionPackages(
        manifests,
        '@kavrix/api',
        forbiddenApiProductionPackages,
      ),
    ).toThrow('Unknown workspace production dependency path: @kavrix/api -> bridge');
  });

  it('rejects npm aliases targeting a Kavrix secret capability', () => {
    const manifests: readonly WorkspaceManifest[] = [
      {
        name: '@kavrix/api',
        dependencies: { bridge: 'npm:@kavrix/crypto@0.1.0' },
      },
      { name: '@kavrix/crypto', dependencies: {} },
    ];

    expect(() =>
      reachableProductionPackages(
        manifests,
        '@kavrix/api',
        forbiddenApiProductionPackages,
      ),
    ).toThrow(
      'Forbidden Kavrix production dependency path: @kavrix/api -> bridge -> @kavrix/crypto',
    );
  });

  it('fails closed on an npm alias whose Kavrix production graph is unavailable', () => {
    const manifests: readonly WorkspaceManifest[] = [
      {
        name: '@kavrix/api',
        dependencies: { bridge: 'npm:@kavrix/core@0.1.0' },
      },
      { name: '@kavrix/core', dependencies: {} },
    ];

    expect(() =>
      reachableProductionPackages(
        manifests,
        '@kavrix/api',
        forbiddenApiProductionPackages,
      ),
    ).toThrow(
      'Unresolved package alias production dependency path: @kavrix/api -> bridge -> @kavrix/core (npm: alias)',
    );
  });

  it('fails closed on unresolved relative workspace dependencies', () => {
    const manifests: readonly WorkspaceManifest[] = [
      {
        name: '@kavrix/api',
        dependencies: { bridge: 'workspace:../packages/crypto' },
      },
      { name: '@kavrix/crypto', dependencies: {} },
    ];

    expect(() =>
      reachableProductionPackages(
        manifests,
        '@kavrix/api',
        forbiddenApiProductionPackages,
      ),
    ).toThrow(
      'Unresolved workspace production dependency path: @kavrix/api -> bridge (unresolved workspace specifier)',
    );
  });

  it.each([
    ['link:../packages/crypto', 'link: specifier'],
    ['file:../packages/crypto', 'file: specifier'],
    ['../packages/crypto', 'filesystem path'],
    ['crypto.tgz', 'local tarball'],
  ])(
    'fails closed on unresolved local production dependency %s',
    (specifier, description) => {
      const manifests: readonly WorkspaceManifest[] = [
        {
          name: '@kavrix/api',
          dependencies: { bridge: specifier },
        },
        { name: '@kavrix/crypto', dependencies: {} },
      ];

      expect(() =>
        reachableProductionPackages(
          manifests,
          '@kavrix/api',
          forbiddenApiProductionPackages,
        ),
      ).toThrow(
        `Unresolved local production dependency path: @kavrix/api -> bridge (${description})`,
      );
    },
  );
});
