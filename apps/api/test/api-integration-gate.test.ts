import { mkdtemp, mkdir, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { afterEach, describe, expect, it, vi } from 'vitest';

import {
  API_INTEGRATION_TIMEOUT_MS,
  discoverApiIntegrationFiles,
  executeApiIntegrationGate,
  runApiIntegrationGate,
  runBoundedChild,
  validateVitestReport,
  type BoundedChildInvocation,
  type BoundedChildResult,
  type VitestJsonReport,
} from '../scripts/api-integration-gate.js';

const temporaryDirectories: string[] = [];

afterEach(async () => {
  await Promise.all(
    temporaryDirectories
      .splice(0)
      .map(async (directory) => rm(directory, { force: true, recursive: true })),
  );
});

describe('API integration gate', () => {
  it.each([undefined, '', ' \t\r\n '])(
    'fails before discovery when KAVRIX_MONGODB_URI is absent or blank',
    async (mongodbUri) => {
      const runChild = vi.fn();
      const environment =
        mongodbUri === undefined ? {} : { KAVRIX_MONGODB_URI: mongodbUri };

      await expect(
        runApiIntegrationGate({ environment, runChild, workspaceRoot: 'unused' }),
      ).rejects.toThrow('MongoDB integration environment is required.');
      expect(runChild).not.toHaveBeenCalled();
    },
  );

  it('never places or prints the MongoDB URI when the child fails', async () => {
    const workspaceRoot = await createWorkspaceWithIntegrationFiles([
      'apps/api/integration/mongo-api.integration.ts',
    ]);
    const secretUri =
      'mongodb://operator:malicious-uri-canary@db.invalid/?replicaSet=rs0';
    const stdout: string[] = [];
    const stderr: string[] = [];
    const runChild = vi.fn(
      (invocation: BoundedChildInvocation): Promise<BoundedChildResult> => {
        expect(invocation.args.join(' ')).not.toContain(secretUri);
        expect(invocation.environment['KAVRIX_MONGODB_URI']).toBe(secretUri);
        expect(invocation.shell).toBe(false);
        return Promise.resolve({
          exitCode: 17,
          outputLimitExceeded: false,
          signal: null,
          stderr: `driver failed for ${secretUri}`,
          stdout: JSON.stringify({ message: secretUri }),
          timedOut: false,
        });
      },
    );

    const exitCode = await executeApiIntegrationGate({
      environment: { KAVRIX_MONGODB_URI: secretUri },
      runChild,
      stderr: (message) => stderr.push(message),
      stdout: (message) => stdout.push(message),
      workspaceRoot,
    });

    expect(exitCode).toBe(1);
    expect(stdout).toEqual([]);
    expect(stderr).toEqual(['API integration tests failed.']);
    expect(JSON.stringify({ stderr, stdout })).not.toContain(secretUri);
  });

  it('recursively discovers every API integration file in stable order', async () => {
    const workspaceRoot = await createWorkspaceWithIntegrationFiles([
      'apps/api/integration/z-last.integration.ts',
      'apps/api/integration/nested/a-first.integration.ts',
      'apps/api/integration/not-an-integration.test.ts',
    ]);

    await expect(discoverApiIntegrationFiles(workspaceRoot)).resolves.toEqual([
      'apps/api/integration/nested/a-first.integration.ts',
      'apps/api/integration/z-last.integration.ts',
    ]);
  });

  it('rejects no-test, skipped-test, and discovery-drift reports', () => {
    const files = [
      'apps/api/integration/mongo-api.integration.ts',
      'apps/api/integration/mongo-service.integration.ts',
    ];

    expect(() =>
      validateVitestReport(createReport({ numTotalTests: 0 }), files),
    ).toThrow('API integration tests failed.');
    expect(() =>
      validateVitestReport(createReport({ numPendingTests: 1 }), files),
    ).toThrow('API integration tests failed.');
    expect(() =>
      validateVitestReport(
        createReport({
          testResults: [createTestResult(files[0] ?? '')],
        }),
        files,
      ),
    ).toThrow('API integration tests failed.');
  });

  it('accepts a report only when every discovered file passed without skips', () => {
    const files = [
      'apps/api/integration/mongo-api.integration.ts',
      'apps/api/integration/mongo-service.integration.ts',
    ];
    const report = createReport({
      numPassedTests: 2,
      numTotalTests: 2,
      testResults: files.map(createTestResult),
    });

    expect(validateVitestReport(report, files)).toEqual({ files: 2, tests: 2 });
  });

  it('reports a nonzero child exit without exposing child output', async () => {
    const result = await runBoundedChild({
      args: ['-e', "process.stderr.write('private child detail'); process.exit(9)"],
      command: process.execPath,
      environment: process.env,
      maxOutputBytes: 1_024,
      timeoutMs: 2_000,
      workspaceRoot: process.cwd(),
    });

    expect(result).toMatchObject({ exitCode: 9, timedOut: false });
    expect(result.stderr).toBe('private child detail');
  });

  it('terminates a child that exceeds the configured bound', async () => {
    const startedAt = Date.now();
    const result = await runBoundedChild({
      args: ['-e', 'setInterval(() => {}, 1_000)'],
      command: process.execPath,
      environment: process.env,
      maxOutputBytes: 1_024,
      timeoutMs: 50,
      workspaceRoot: process.cwd(),
    });

    expect(result.timedOut).toBe(true);
    expect(Date.now() - startedAt).toBeLessThan(2_000);
    expect(API_INTEGRATION_TIMEOUT_MS).toBeGreaterThanOrEqual(60_000);
  });
});

async function createWorkspaceWithIntegrationFiles(
  files: readonly string[],
): Promise<string> {
  const workspaceRoot = await mkdtemp(join(tmpdir(), 'kavrix-api-gate-'));
  temporaryDirectories.push(workspaceRoot);
  await Promise.all(
    files.map(async (file) => {
      const absolutePath = join(workspaceRoot, ...file.split('/'));
      await mkdir(join(absolutePath, '..'), { recursive: true });
      await writeFile(absolutePath, '// test fixture\n', 'utf8');
    }),
  );
  return workspaceRoot;
}

function createReport(overrides: Partial<VitestJsonReport> = {}): VitestJsonReport {
  return {
    numFailedTests: 0,
    numPassedTests: 1,
    numPendingTests: 0,
    numTodoTests: 0,
    numTotalTests: 1,
    success: true,
    testResults: [createTestResult('apps/api/integration/mongo-api.integration.ts')],
    ...overrides,
  };
}

function createTestResult(name: string): VitestJsonReport['testResults'][number] {
  return { name, status: 'passed' };
}
