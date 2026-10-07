import { mkdir, mkdtemp, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { describe, expect, it } from 'vitest';

import { isCodedCliError } from '../src/execution/coded-error.js';
import {
  environmentMappings,
  loadProjectConfig,
  discoverProjectConfig,
  projectPolicies,
} from '../src/execution/project-config.js';
import { createExecutionFixture, destroyFixture } from './execution-helpers.js';

let fixture: Awaited<ReturnType<typeof createExecutionFixture>>;

describe('project configuration discovery', () => {
  async function inDirectory(run: (directory: string) => Promise<void>): Promise<void> {
    const directory = await mkdtemp(join(tmpdir(), 'kavrix-config-discovery-'));
    try {
      await run(directory);
    } finally {
      await rm(directory, { recursive: true, force: true });
    }
  }

  it('returns null only when all default files are absent', async () => {
    await inDirectory(async (directory) => {
      expect(await discoverProjectConfig(undefined, directory)).toBeNull();
    });
  });

  it.each(['kavrix.yaml', 'kavrix.yml', 'kavrix.json'])(
    'loads a unique %s',
    async (filename) => {
      await inDirectory(async (directory) => {
        await writeFile(join(directory, filename), JSON.stringify({ version: 1 }));
        expect(await discoverProjectConfig(undefined, directory)).toEqual({
          document: { version: 1 },
        });
      });
    },
  );

  it('rejects ambiguous defaults, even when one is malformed', async () => {
    await inDirectory(async (directory) => {
      await writeFile(join(directory, 'kavrix.yaml'), 'broken: [');
      await writeFile(join(directory, 'kavrix.json'), JSON.stringify({ version: 1 }));
      await expect(discoverProjectConfig(undefined, directory)).rejects.toThrow(
        /Multiple.*--config/u,
      );
      expect(
        await discoverProjectConfig(join(directory, 'kavrix.json'), directory),
      ).toEqual({ document: { version: 1 } });
    });
  });

  it('does not hide invalid default documents or unreadable file types', async () => {
    await inDirectory(async (directory) => {
      await writeFile(join(directory, 'kavrix.yaml'), 'broken: [');
      await expect(discoverProjectConfig(undefined, directory)).rejects.toThrow(
        /valid YAML/u,
      );
      await rm(join(directory, 'kavrix.yaml'));
      await mkdir(join(directory, 'kavrix.json'));
      await expect(discoverProjectConfig(undefined, directory)).rejects.toThrow(
        /could not be read/u,
      );
    });
  });

  it('never falls back when an explicit path is missing', async () => {
    await inDirectory(async (directory) => {
      await writeFile(join(directory, 'kavrix.json'), JSON.stringify({ version: 1 }));
      await expect(
        discoverProjectConfig(join(directory, 'missing.json'), directory),
      ).rejects.toThrow(/could not be read/u);
    });
  });
});

describe('project configuration bounds', () => {
  it('rejects empty and oversized documents before parsing', async () => {
    fixture = await createExecutionFixture({});
    try {
      const empty = join(fixture.directory, 'empty.yaml');
      await writeFile(empty, '');
      await expect(loadProjectConfig(empty)).rejects.toThrow(/empty or exceeds/u);

      const huge = join(fixture.directory, 'huge.json');
      await writeFile(huge, `{"pad":"${'x'.repeat(130 * 1024)}"}`);
      await expect(loadProjectConfig(huge)).rejects.toThrow(/empty or exceeds/u);

      const brokenYaml = join(fixture.directory, 'broken.yaml');
      await writeFile(brokenYaml, 'version: 1\n  bad: [indentation:\n');
      await expect(loadProjectConfig(brokenYaml)).rejects.toThrow(/valid YAML/u);
    } finally {
      await destroyFixture(fixture);
    }
  });

  it('prefers root policies over environment duplicates when collecting', async () => {
    fixture = await createExecutionFixture({});
    try {
      const path = join(fixture.directory, 'config.json');
      await writeFile(
        path,
        JSON.stringify({
          version: 1,
          environments: {
            ci: {
              policies: {
                shared: { secret: 'env/secret', commands: ['env-tool'] },
                envOnly: { secret: 'env/secret', commands: ['env-tool'] },
                duplicated: { secret: 'first/secret', commands: ['first-tool'] },
              },
            },
            prod: {
              policies: {
                duplicated: { secret: 'second/secret', commands: ['second-tool'] },
              },
            },
          },
          policies: {
            shared: { secret: 'root/secret', commands: ['root-tool'] },
          },
        }),
      );
      const { document } = await loadProjectConfig(path);
      const policies = projectPolicies(document);
      expect(policies.get('shared')?.commands).toEqual(['root-tool']);
      expect(policies.get('duplicated')?.commands).toEqual(['first-tool']);
      expect(policies.has('envOnly')).toBe(true);
      expect(policies.size).toBe(3);
      expect(environmentMappings(document, 'ci')).toEqual([]);
    } finally {
      await destroyFixture(fixture);
    }
  });

  it('names a missing secrets map without dumping guessed credential values', async () => {
    const directory = await mkdtemp(join(tmpdir(), 'kavrix-project-config-'));
    try {
      const document = [
        'version: 1',
        'environments:',
        '  staging:',
        '    A: alpha',
        '',
      ].join('\n');
      for (const [label, body] of [
        ['lf', document],
        ['crlf', document.replace(/\n/gu, '\r\n')],
      ] as const) {
        const path = join(directory, `kavrix-${label}.yaml`);
        await writeFile(path, body, 'utf8');
        const error = await loadProjectConfig(path).catch((caught: unknown) => caught);
        expect(error, label).toBeInstanceOf(Error);
        expect(isCodedCliError(error), label).toBe(true);
        if (isCodedCliError(error)) {
          expect(error.errorCode, label).toBe('INVALID_CONFIGURATION');
          expect(error.exitCode, label).toBe(14);
        }
        expect(String(error), label).toMatch(/secrets/u);
        expect(String(error), label).toMatch(/environment/iu);
        expect(String(error), label).not.toMatch(
          /Only version 1 documents with credential references/u,
        );
        expect(String(error), label).not.toContain('alpha');
      }
    } finally {
      await rm(directory, { force: true, recursive: true });
    }
  });
});
