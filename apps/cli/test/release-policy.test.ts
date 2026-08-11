import { readFileSync } from 'node:fs';

import { describe, expect, it } from 'vitest';

import {
  findExactSuccessfulPushRun,
  findSuccessfulCodeQlAnalysisJob,
  requireExactSuccessfulWorkflowRuns,
  resolveReleaseChannel,
  validateReleaseChannel,
  type WorkflowRunQuery,
} from '../scripts/require-workflow-runs.js';

const repositoryRoot = new URL('../../..', import.meta.url);
const publishWorkflow = readFileSync(
  new URL('.github/workflows/publish.yml', repositoryRoot),
  'utf8',
);
const ciWorkflow = readFileSync(
  new URL('.github/workflows/ci.yml', repositoryRoot),
  'utf8',
);
const codeQlWorkflow = readFileSync(
  new URL('.github/workflows/codeql.yml', repositoryRoot),
  'utf8',
);
const dependencyReviewWorkflow = readFileSync(
  new URL('.github/workflows/dependency-review.yml', repositoryRoot),
  'utf8',
);
const releaseGuide = readFileSync(new URL('docs/release.md', repositoryRoot), 'utf8');

const exactQuery = {
  repository: 'd4rkNinja/kavrix',
  sha: 'a'.repeat(40),
  workflowPath: '.github/workflows/ci.yml',
} satisfies WorkflowRunQuery;

function matchingRun(overrides: Record<string, unknown> = {}): Record<string, unknown> {
  return {
    id: 12345,
    event: 'push',
    status: 'completed',
    conclusion: 'success',
    head_sha: exactQuery.sha,
    head_branch: 'main',
    path: exactQuery.workflowPath,
    repository: { full_name: exactQuery.repository },
    head_repository: { full_name: exactQuery.repository },
    ...overrides,
  };
}

function matchingCodeQlJob(
  overrides: Record<string, unknown> = {},
): Record<string, unknown> {
  return {
    name: 'Analyze JavaScript and TypeScript',
    status: 'completed',
    conclusion: 'success',
    steps: [
      {
        name: 'Run github/codeql-action/init',
        status: 'completed',
        conclusion: 'success',
      },
      {
        name: 'Perform CodeQL Analysis',
        status: 'completed',
        conclusion: 'success',
      },
    ],
    ...overrides,
  };
}

function jobBlock(source: string, jobName: string): string {
  const lines = source.split('\n');
  const start = lines.findIndex((line) => line === `  ${jobName}:`);
  if (start < 0) {
    throw new Error(`Workflow job ${jobName} is missing.`);
  }
  const end = lines.findIndex(
    (line, index) => index > start && /^\x20{2}[a-zA-Z0-9_-]+:$/u.test(line),
  );
  return lines.slice(start, end < 0 ? undefined : end).join('\n');
}

function fetchInputUrl(input: Parameters<typeof fetch>[0]): string {
  if (typeof input === 'string') {
    return input;
  }
  return input instanceof URL ? input.href : input.url;
}

describe('release channel policy', () => {
  it('maps stable releases only to latest and beta prereleases only to beta', () => {
    expect(resolveReleaseChannel('1.2.3', false)).toBe('latest');
    expect(resolveReleaseChannel('1.2.3-beta.0', true)).toBe('beta');
    expect(resolveReleaseChannel('1.2.3-beta.27', true)).toBe('beta');
  });

  it('rejects release-flag mismatches and every unsupported prerelease shape', () => {
    for (const [version, prerelease] of [
      ['1.2.3', true],
      ['1.2.3-beta.1', false],
      ['1.2.3-beta', true],
      ['1.2.3-beta.', true],
      ['1.2.3-beta.01', true],
      ['01.2.3-beta.1', true],
      ['1.02.3-beta.1', true],
      ['1.2.03', false],
      ['1.2.3-alpha.1', true],
      ['1.2.3-rc.1', true],
      ['v1.2.3-beta.1', true],
      ['1.2.3+build.1', false],
    ] as const) {
      expect(() => resolveReleaseChannel(version, prerelease)).toThrow();
    }
  });

  it('rejects beta-to-latest and stable-to-beta channel substitution', () => {
    expect(() => {
      validateReleaseChannel('1.2.3-beta.1', true, 'latest');
    }).toThrow(/requires the npm beta dist-tag/u);
    expect(() => {
      validateReleaseChannel('1.2.3', false, 'beta');
    }).toThrow(/requires the npm latest dist-tag/u);
    expect(() => {
      validateReleaseChannel('1.2.3-beta.1', true, 'beta');
    }).not.toThrow();
    expect(() => {
      validateReleaseChannel('1.2.3', false, 'latest');
    }).not.toThrow();
  });
});

describe('exact-SHA workflow-run policy', () => {
  it('accepts only the matching same-repository main push run', () => {
    expect(
      findExactSuccessfulPushRun({ workflow_runs: [matchingRun()] }, exactQuery),
    ).toEqual(matchingRun());

    for (const invalidRun of [
      matchingRun({ event: 'pull_request' }),
      matchingRun({ status: 'queued' }),
      matchingRun({ conclusion: 'skipped' }),
      matchingRun({ conclusion: 'cancelled' }),
      matchingRun({ head_sha: 'b'.repeat(40) }),
      matchingRun({ head_branch: 'release' }),
      matchingRun({ path: '.github/workflows/codeql.yml' }),
      matchingRun({ repository: { full_name: 'someone/fork' } }),
      matchingRun({ head_repository: { full_name: 'someone/fork' } }),
    ]) {
      expect(() =>
        findExactSuccessfulPushRun({ workflow_runs: [invalidRun] }, exactQuery),
      ).toThrow(/No successful completed main push run/u);
    }
  });

  it('requires the CodeQL analysis job and analyze step to actually succeed', () => {
    expect(findSuccessfulCodeQlAnalysisJob({ jobs: [matchingCodeQlJob()] })).toEqual(
      matchingCodeQlJob(),
    );

    for (const invalidJob of [
      matchingCodeQlJob({ status: 'queued' }),
      matchingCodeQlJob({ conclusion: 'skipped' }),
      matchingCodeQlJob({ conclusion: 'cancelled' }),
      matchingCodeQlJob({ name: 'Unrelated successful job' }),
      matchingCodeQlJob({ steps: [] }),
      matchingCodeQlJob({
        steps: [
          {
            name: 'Perform CodeQL Analysis',
            status: 'completed',
            conclusion: 'skipped',
          },
        ],
      }),
    ]) {
      expect(() => findSuccessfulCodeQlAnalysisJob({ jobs: [invalidJob] })).toThrow(
        /CodeQL run did not complete/u,
      );
    }
  });

  it('fails closed on malformed CodeQL job responses', () => {
    for (const payload of [
      null,
      {},
      { jobs: null },
      { jobs: [{}] },
      { jobs: [matchingCodeQlJob(), null] },
      { jobs: [matchingCodeQlJob({ steps: [null] })] },
    ]) {
      expect(() => findSuccessfulCodeQlAnalysisJob(payload)).toThrow();
    }
  });

  it('fails closed on absent or malformed GitHub API payloads', () => {
    for (const payload of [
      null,
      {},
      { workflow_runs: null },
      { workflow_runs: [{}] },
      { workflow_runs: [matchingRun({ repository: null })] },
      { workflow_runs: [matchingRun(), null] },
    ]) {
      expect(() => findExactSuccessfulPushRun(payload, exactQuery)).toThrow();
    }
  });

  it('rejects repository, SHA, and workflow-path injection', () => {
    for (const query of [
      { ...exactQuery, repository: 'owner/repo?per_page=1' },
      { ...exactQuery, repository: 'owner/repo/extra' },
      { ...exactQuery, repository: '../repos/other' },
      { ...exactQuery, sha: `${'a'.repeat(39)}A` },
      { ...exactQuery, sha: `${'a'.repeat(40)}?event=pull_request` },
      { ...exactQuery, workflowPath: '.github/workflows/nested/ci.yml' },
      { ...exactQuery, workflowPath: '.github/workflows/ci.yml?event=pull_request' },
      { ...exactQuery, workflowPath: '.github/workflows/../ci.yml' },
    ]) {
      expect(() =>
        findExactSuccessfulPushRun({ workflow_runs: [matchingRun()] }, query),
      ).toThrow();
    }
  });

  it('queries CI and CodeQL for the same exact SHA', async () => {
    const requestedUrls: string[] = [];
    const fetchImplementation: typeof fetch = (input) => {
      const url = fetchInputUrl(input);
      requestedUrls.push(url);
      if (url.includes('/actions/runs/12345/jobs')) {
        return Promise.resolve(
          new Response(JSON.stringify({ jobs: [matchingCodeQlJob()] }), {
            status: 200,
          }),
        );
      }
      const workflowPath = url.includes('/codeql.yml/')
        ? '.github/workflows/codeql.yml'
        : '.github/workflows/ci.yml';
      return Promise.resolve(
        new Response(
          JSON.stringify({
            workflow_runs: [matchingRun({ path: workflowPath })],
          }),
          { status: 200 },
        ),
      );
    };

    await requireExactSuccessfulWorkflowRuns({
      apiUrl: 'https://api.github.test',
      fetchImplementation,
      repository: exactQuery.repository,
      sha: exactQuery.sha,
      token: 'github-token-fixture',
      workflowPaths: ['.github/workflows/ci.yml', '.github/workflows/codeql.yml'],
    });

    expect(requestedUrls).toHaveLength(3);
    for (const urlText of requestedUrls.filter((value) =>
      value.includes('/workflows/'),
    )) {
      const url = new URL(urlText);
      expect(url.origin).toBe('https://api.github.test');
      expect(url.pathname).toMatch(
        /^\/repos\/d4rkNinja\/kavrix\/actions\/workflows\/(?:ci|codeql)\.yml\/runs$/u,
      );
      expect(url.searchParams.get('event')).toBe('push');
      expect(url.searchParams.get('head_sha')).toBe(exactQuery.sha);
      expect(url.searchParams.get('status')).toBe('success');
    }
    const jobsUrl = new URL(
      requestedUrls.find((value) => value.includes('/actions/runs/')) ?? '',
    );
    expect(jobsUrl.pathname).toBe('/repos/d4rkNinja/kavrix/actions/runs/12345/jobs');
    expect(jobsUrl.searchParams.get('per_page')).toBe('100');
  });

  it('fails when a successful CodeQL run contains a skipped analysis job', async () => {
    const fetchImplementation: typeof fetch = (input) => {
      const url = fetchInputUrl(input);
      if (url.includes('/actions/runs/12345/jobs')) {
        return Promise.resolve(
          new Response(
            JSON.stringify({
              jobs: [matchingCodeQlJob({ conclusion: 'skipped' })],
            }),
            { status: 200 },
          ),
        );
      }
      const workflowPath = url.includes('/codeql.yml/')
        ? '.github/workflows/codeql.yml'
        : '.github/workflows/ci.yml';
      return Promise.resolve(
        new Response(
          JSON.stringify({ workflow_runs: [matchingRun({ path: workflowPath })] }),
          { status: 200 },
        ),
      );
    };

    await expect(
      requireExactSuccessfulWorkflowRuns({
        apiUrl: 'https://api.github.test',
        fetchImplementation,
        repository: exactQuery.repository,
        sha: exactQuery.sha,
        token: 'github-token-fixture',
        workflowPaths: ['.github/workflows/ci.yml', '.github/workflows/codeql.yml'],
      }),
    ).rejects.toThrow(/analysis job successfully/u);
  });

  it('rejects duplicate workflow requirements and GitHub API failures', async () => {
    const baseOptions = {
      apiUrl: 'https://api.github.test',
      fetchImplementation: () => Promise.resolve(new Response(null, { status: 503 })),
      repository: exactQuery.repository,
      sha: exactQuery.sha,
      token: 'github-token-fixture',
      workflowPaths: ['.github/workflows/ci.yml'],
    } as const;

    await expect(requireExactSuccessfulWorkflowRuns(baseOptions)).rejects.toThrow(
      /HTTP 503.*ci\.yml/u,
    );
    await expect(
      requireExactSuccessfulWorkflowRuns({
        ...baseOptions,
        workflowPaths: ['.github/workflows/ci.yml', '.github/workflows/ci.yml'],
      }),
    ).rejects.toThrow(/must be unique/u);
  });

  it('fails the combined gate when either required workflow is missing', async () => {
    const fetchImplementation: typeof fetch = (input) =>
      Promise.resolve(
        new Response(
          JSON.stringify({
            workflow_runs: fetchInputUrl(input).includes('/ci.yml/')
              ? [matchingRun()]
              : [],
          }),
          { status: 200 },
        ),
      );

    await expect(
      requireExactSuccessfulWorkflowRuns({
        apiUrl: 'https://api.github.test',
        fetchImplementation,
        repository: exactQuery.repository,
        sha: exactQuery.sha,
        token: 'github-token-fixture',
        workflowPaths: ['.github/workflows/ci.yml', '.github/workflows/codeql.yml'],
      }),
    ).rejects.toThrow(/codeql/u);
  });
});

describe('publish workflow policy', () => {
  it('isolates validation from the only OIDC-authorized job', () => {
    const validate = jobBlock(publishWorkflow, 'validate');
    const publish = jobBlock(publishWorkflow, 'publish');

    expect(validate).not.toContain('id-token: write');
    expect(validate).toContain('pnpm install --frozen-lockfile');
    expect(validate).toContain('pnpm verify');
    expect(validate).toContain('pnpm audit --audit-level high');
    expect(validate).toContain('pnpm --filter kavrix --fail-if-no-match pack');
    expect(validate).not.toContain('pnpm test:coverage');
    expect(validate).not.toContain('npm publish');

    expect(publish).toContain('needs: validate');
    expect(publish).toContain('environment: npm');
    expect(publish).toContain('id-token: write');
    expect(publish).not.toMatch(
      /actions\/checkout|pnpm\s|node apps\/|vitest|npm (?:run|test|pack)|\b(?:build|prepack|postpack)\b/u,
    );
    expect(publish).toContain('npm publish "$PACKAGE_ARCHIVE"');
    expect(publish).toContain('--ignore-scripts');
    expect(publish).toContain('--access public');
    expect(publish).toContain('--tag "$NPM_DIST_TAG"');
    expect(publish).toContain('--provenance');
    expect(publishWorkflow.match(/id-token: write/gu)).toHaveLength(1);
    expect(publishWorkflow).toContain('permissions: {}');
  });

  it('keeps beta away from latest and stable releases away from beta', () => {
    const validate = jobBlock(publishWorkflow, 'validate');
    const publish = jobBlock(publishWorkflow, 'publish');

    expect(validate).toContain('resolveReleaseChannel');
    expect(validate).toContain('RELEASE_PRERELEASE');
    expect(publish).toContain('test "$EXPECTED_NPM_DIST_TAG" = \'latest\'');
    expect(publish).toContain('test "$EXPECTED_NPM_DIST_TAG" = \'beta\'');
    expect(publish).toContain(
      'NPM_DIST_TAG: ${{ needs.validate.outputs.npm_dist_tag }}',
    );
    expect(publish).toContain('--tag "$NPM_DIST_TAG"');
    expect(publish).not.toContain('--tag latest');
    expect(publish).not.toContain('--tag beta');
  });

  it('hands exactly one validated archive and digest to publish', () => {
    const validate = jobBlock(publishWorkflow, 'validate');
    const publish = jobBlock(publishWorkflow, 'publish');

    expect(validate.match(/actions\/upload-artifact@/gu)).toHaveLength(1);
    expect(publish.match(/actions\/download-artifact@/gu)).toHaveLength(1);
    expect(validate).toContain('archive_sha256:');
    expect(validate).toContain('archive_name:');
    expect(validate).toContain('package_version:');
    expect(publish).toContain('needs.validate.outputs.archive_sha256');
    expect(publish).toContain('needs.validate.outputs.archive_name');
    expect(publish).toContain('needs.validate.outputs.package_version');
    expect(publish).toContain('sha256sum');
    expect(publish).toContain('[[ "$EXPECTED_ARCHIVE_SHA256" =~ ^[0-9a-f]{64}$ ]]');
    expect(publish).toContain("manifest.name !== 'kavrix'");
    expect(publish).toContain('manifest.version !== expectedVersion');
    expect(publish).toContain('manifest.private !== false');
    expect(publish).toContain("manifest.publishConfig?.access !== 'public'");
    expect(publish).toContain(
      "manifest.publishConfig?.registry !== 'https://registry.npmjs.org/'",
    );
    expect(publish).toContain('NODE_AUTH_TOKEN');
    expect(publish).toContain('NPM_TOKEN');
  });

  it('requires exact-SHA CI and CodeQL before the fresh audit and one pack', () => {
    expect(publishWorkflow).toContain('apps/cli/scripts/require-workflow-runs.js');
    expect(publishWorkflow).toContain('.github/workflows/ci.yml');
    expect(publishWorkflow).toContain('.github/workflows/codeql.yml');
    const auditIndex = publishWorkflow.indexOf('pnpm audit --audit-level high');
    const packIndex = publishWorkflow.indexOf(
      'pnpm --filter kavrix --fail-if-no-match pack',
    );
    expect(auditIndex).toBeGreaterThan(-1);
    expect(packIndex).toBeGreaterThan(auditIndex);
    expect(
      publishWorkflow.match(/pnpm --filter kavrix --fail-if-no-match pack/gu),
    ).toHaveLength(1);
  });

  it('pins the Mongo integration runner', () => {
    expect(jobBlock(ciWorkflow, 'mongo-integration')).toContain(
      'runs-on: ubuntu-24.04',
    );
    for (const workflow of [
      ciWorkflow,
      codeQlWorkflow,
      dependencyReviewWorkflow,
      publishWorkflow,
    ]) {
      expect(workflow).not.toContain('runs-on: ubuntu-latest');
      const actionReferences = [...workflow.matchAll(/^\s*- uses:\s+(\S+)/gmu)].map(
        (match) => match[1],
      );
      expect(actionReferences.length).toBeGreaterThan(0);
      for (const reference of actionReferences) {
        expect(reference).toMatch(/^[^@\s]+@[0-9a-f]{40}$/u);
      }
    }
  });

  it('preserves tag target checks while documenting the signer-policy STOP', () => {
    const validate = jobBlock(publishWorkflow, 'validate');
    expect(validate).toContain('git show-ref --verify --quiet');
    expect(validate).toContain('refs/tags/$RELEASE_TAG^{commit}');
    expect(validate).toContain('git merge-base --is-ancestor');
    expect(validate).not.toContain('git verify-tag');
    expect(publishWorkflow).toContain(
      'STOP: Do not add signature verification until the product decision names',
    );
    expect(releaseGuide).toContain(
      'STOP — signed release authorization is unresolved.',
    );
    expect(releaseGuide).toMatch(/exact allowed\s+signer fingerprint/u);
  });

  it('documents exact-SHA CI as the authoritative real-Mongo coverage gate', () => {
    expect(releaseGuide).toContain(
      'same-repository `main` push runs of both `.github/workflows/ci.yml` and',
    );
    expect(releaseGuide).toContain(
      'authoritative build, cross-platform, real-Mongo coverage, and package-smoke',
    );
    expect(releaseGuide).toContain('does not rerun the mismatched unit-only');
  });
});
