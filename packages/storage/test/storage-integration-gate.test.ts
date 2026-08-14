import { mkdtemp, mkdir, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';

import { afterEach, describe, expect, it, vi } from 'vitest';

import {
  STORAGE_INTEGRATION_TIMEOUT_MS,
  discoverStorageIntegrationFiles,
  executeStorageIntegrationGate,
  runBoundedChild,
  runStorageIntegrationGate,
  validateVitestReport,
  type BoundedChildInvocation,
  type BoundedChildResult,
  type VitestJsonReport,
} from '../scripts/storage-integration-gate.js';

const temporaryDirectories: string[] = [];

afterEach(async () => {
  await Promise.all(
    temporaryDirectories
      .splice(0)
      .map(async (directory) => rm(directory, { force: true, recursive: true })),
  );
});

describe('storage Mongo integration gate', () => {
  it.each([undefined, '', ' \t\r\n '])(
    'fails before discovery when KAVRIX_MONGODB_URI is absent or blank',
    async (mongodbUri) => {
      const runChild = vi.fn();
      const environment =
        mongodbUri === undefined ? {} : { KAVRIX_MONGODB_URI: mongodbUri };

      await expect(
        runStorageIntegrationGate({ environment, runChild, workspaceRoot: 'unused' }),
      ).rejects.toThrow('MongoDB integration environment is required.');
      expect(runChild).not.toHaveBeenCalled();
    },
  );

  it('discovers every storage integration file and never exposes a URI on child failure', async () => {
    const workspaceRoot = await createWorkspaceWithIntegrationFiles([
      'packages/storage/integration/z-last.integration.ts',
      'packages/storage/integration/nested/a-first.integration.ts',
      'packages/storage/integration/not-an-integration.test.ts',
    ]);
    const secretUri =
      'mongodb://operator:storage-uri-canary@db.invalid/?replicaSet=rs0';
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

    await expect(discoverStorageIntegrationFiles(workspaceRoot)).resolves.toEqual([
      'packages/storage/integration/nested/a-first.integration.ts',
      'packages/storage/integration/z-last.integration.ts',
    ]);
    const exitCode = await executeStorageIntegrationGate({
      environment: { KAVRIX_MONGODB_URI: secretUri },
      runChild,
      stderr: (message) => stderr.push(message),
      stdout: (message) => stdout.push(message),
      workspaceRoot,
    });

    expect(exitCode).toBe(1);
    expect(stdout).toEqual([]);
    expect(stderr).toEqual(['Storage integration tests failed.']);
    expect(JSON.stringify({ stderr, stdout })).not.toContain(secretUri);
  });

  it('rejects empty, skipped, failed, malformed, and discovery-drift reports', async () => {
    const files = [
      'packages/storage/integration/mongo.integration.ts',
      'packages/storage/integration/mongo-backup-source.integration.ts',
    ];

    expect(() =>
      validateVitestReport(createReport({ numTotalTests: 0 }), files),
    ).toThrow('Storage integration tests failed.');
    expect(() =>
      validateVitestReport(createReport({ numPendingTests: 1 }), files),
    ).toThrow('Storage integration tests failed.');
    expect(() =>
      validateVitestReport(
        createReport({ testResults: [createTestResult(files[0] ?? '')] }),
        files,
      ),
    ).toThrow('Storage integration tests failed.');
    expect(() =>
      validateVitestReport(
        createReport({
          testResults: files.map((file) => ({
            ...createTestResult(file),
            status: 'failed',
          })),
        }),
        files,
      ),
    ).toThrow('Storage integration tests failed.');

    const workspaceRoot = await createWorkspaceWithIntegrationFiles(files);
    await expect(
      runStorageIntegrationGate({
        environment: { KAVRIX_MONGODB_URI: 'mongodb://invalid-canary' },
        runChild: vi.fn(() =>
          Promise.resolve({
            exitCode: 0,
            outputLimitExceeded: false,
            signal: null,
            stderr: '',
            stdout: 'not json',
            timedOut: false,
          }),
        ),
        workspaceRoot,
      }),
    ).rejects.toThrow('Storage integration tests failed.');
  });

  it('accepts a report only when every discovered file passed without skips', () => {
    const files = [
      'packages/storage/integration/mongo.integration.ts',
      'packages/storage/integration/mongo-backup-source.integration.ts',
    ];
    const report = createReport({
      numPassedTests: 2,
      numTotalTests: 2,
      testResults: files.map(createTestResult),
    });

    expect(validateVitestReport(report, files)).toEqual({ files: 2, tests: 2 });
  });

  it('bounds child output and terminates a child that exceeds its timeout', async () => {
    const result = await runBoundedChild({
      args: ['-e', 'setInterval(() => {}, 1_000)'],
      command: process.execPath,
      environment: process.env,
      maxOutputBytes: 1_024,
      timeoutMs: 50,
      workspaceRoot: process.cwd(),
    });

    expect(result.timedOut).toBe(true);
    expect(result.outputLimitExceeded).toBe(false);
    expect(STORAGE_INTEGRATION_TIMEOUT_MS).toBeGreaterThanOrEqual(60_000);
  });
});

async function createWorkspaceWithIntegrationFiles(
  files: readonly string[],
): Promise<string> {
  const workspaceRoot = await mkdtemp(join(tmpdir(), 'kavrix-storage-gate-'));
  temporaryDirectories.push(workspaceRoot);
  await Promise.all(
    files.map(async (file) => {
      const absolutePath = join(workspaceRoot, ...file.split('/'));
      await mkdir(dirname(absolutePath), { recursive: true });
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
    testResults: [
      createTestResult('packages/storage/integration/mongo.integration.ts'),
    ],
    ...overrides,
  };
}

function createTestResult(name: string): VitestJsonReport['testResults'][number] {
  return { name, status: 'passed' };
}
