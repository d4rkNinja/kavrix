import { readFile } from 'node:fs/promises';
import { describe, expect, it } from 'vitest';
import { parse } from 'yaml';

const source = await readFile(
  new URL('../../../.github/workflows/publish.yml', import.meta.url),
  'utf8',
);
const workflow = parse(source) as {
  on: { workflow_dispatch: { inputs: Record<string, unknown> } };
  jobs: {
    validate: {
      steps: readonly { name?: string; if?: unknown; run?: string }[];
    };
  };
};

describe('publication gates cannot be bypassed by a manual retry', () => {
  it('accepts only the release tag as a dispatch input', () => {
    expect(Object.keys(workflow.on.workflow_dispatch.inputs)).toEqual(['tag']);
    expect(source).not.toMatch(/skip_ci_gate/iu);
  });

  it('always checks both exact-commit workflows before packaging', () => {
    const gate = workflow.jobs.validate.steps.find((step) =>
      step.name?.includes('exact-SHA CI and CodeQL'),
    );
    expect(gate).toBeDefined();
    expect(gate?.if).toBeUndefined();
    expect(gate?.run).toContain('.github/workflows/ci.yml');
    expect(gate?.run).toContain('.github/workflows/codeql.yml');
    expect(gate?.run).not.toMatch(/\bif\b/u);
  });

  it('always smoke-tests the exact archive', () => {
    const smoke = workflow.jobs.validate.steps.find((step) =>
      step.name?.includes('Inspect and smoke-test'),
    );
    expect(smoke).toBeDefined();
    expect(smoke?.if).toBeUndefined();
    expect(smoke?.run?.split('\n').slice(0, 2)).toEqual([
      'set -euo pipefail',
      'node apps/cli/scripts/smoke-packed-package.js "$PACKAGE_ARCHIVE"',
    ]);
  });

  it('inspects the current pinned Zod version in both notices and the SBOM', async () => {
    const workspace = parse(
      await readFile(new URL('../../../pnpm-workspace.yaml', import.meta.url), 'utf8'),
    ) as { catalog: Record<string, string> };
    const version = workspace.catalog['zod'];
    expect(version).toMatch(/^\d+\.\d+\.\d+$/u);
    const smoke = workflow.jobs.validate.steps.find((step) =>
      step.name?.includes('Inspect and smoke-test'),
    );
    expect(smoke?.run).toContain(`'zod@${String(version)} (MIT)'`);
    expect(smoke?.run).toContain(`'pkg:npm/zod@${String(version)}'`);
  });
});
