import { writeFile } from 'node:fs/promises';
import { join } from 'node:path';

import { describe, expect, it } from 'vitest';

import {
  environmentMappings,
  loadProjectConfig,
  projectPolicies,
} from '../src/execution/project-config.js';
import { createExecutionFixture, destroyFixture } from './execution-helpers.js';

let fixture: Awaited<ReturnType<typeof createExecutionFixture>>;

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
});
