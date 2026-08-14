import { describe, expect, it, vi } from 'vitest';

import {
  executeOperationalAcceptance,
  runOperationalAcceptance,
  type OperationalChildInvocation,
  type OperationalChildResult,
} from './operational-acceptance.js';

const operationalFile = 'apps/api/operational/operational-acceptance.integration.ts';
const workspaceRoot = process.cwd();

describe('operational acceptance gate', () => {
  it.each([undefined, '', ' \t\r\n '])(
    'fails before child execution when the Mongo URI is absent or blank',
    async (mongodbUri) => {
      const runChild = vi.fn();
      const environment =
        mongodbUri === undefined ? {} : { KAVRIX_MONGODB_URI: mongodbUri };

      await expect(
        runOperationalAcceptance({ environment, runChild, workspaceRoot: 'unused' }),
      ).rejects.toThrow('MongoDB operational acceptance environment is required.');
      expect(runChild).not.toHaveBeenCalled();
    },
  );

  it('runs migration and the exact operational file without putting the URI in args', async () => {
    const secretUri =
      'mongodb://operator:operational-uri-canary@db.invalid/?replicaSet=rs0';
    const invocations: OperationalChildInvocation[] = [];
    const runChild = vi.fn(
      (invocation: OperationalChildInvocation): Promise<OperationalChildResult> => {
        invocations.push(invocation);
        if (invocations.length === 1) return Promise.resolve(successResult());
        return Promise.resolve({
          ...successResult(),
          stdout: JSON.stringify(successReport()),
        });
      },
    );

    await expect(
      runOperationalAcceptance({
        environment: { KAVRIX_MONGODB_URI: secretUri },
        runChild,
        workspaceRoot,
      }),
    ).resolves.toEqual({ files: 1, tests: 1 });

    expect(invocations).toHaveLength(2);
    for (const invocation of invocations) {
      expect(invocation.command).toBe(process.execPath);
      expect(invocation.shell).toBe(false);
      expect(invocation.environment['KAVRIX_MONGODB_URI']).toBe(secretUri);
      expect(invocation.args.join(' ')).not.toContain(secretUri);
      expect(invocation.maxOutputBytes).toBe(4 * 1024 * 1024);
    }
    expect(invocations[0]?.args.join(' ')).toContain('mongo-migrate.ts');
    expect(invocations[1]?.args).toContain(operationalFile);
  });

  it('hides migration and child output on failure', async () => {
    const secretUri = 'mongodb://operator:operational-uri-canary@db.invalid';
    const stderr: string[] = [];
    const stdout: string[] = [];
    const runChild = vi.fn(() =>
      Promise.resolve({
        ...successResult(),
        exitCode: 17,
        stderr: `child leaked ${secretUri}`,
      }),
    );

    await expect(
      executeOperationalAcceptance({
        environment: { KAVRIX_MONGODB_URI: secretUri },
        runChild,
        stderr: (message) => stderr.push(message),
        stdout: (message) => stdout.push(message),
        workspaceRoot,
      }),
    ).resolves.toBe(1);
    expect(stderr).toEqual(['Operational acceptance failed.']);
    expect(stdout).toEqual([]);
    expect(JSON.stringify({ stderr, stdout })).not.toContain(secretUri);
  });

  it.each([
    { numTotalTests: 0 },
    { numPendingTests: 1 },
    { outputLimitExceeded: true },
    { timedOut: true },
  ])('rejects unsafe child/report result %j', async (overrides) => {
    const runChild = vi
      .fn<(invocation: OperationalChildInvocation) => Promise<OperationalChildResult>>()
      .mockResolvedValueOnce(successResult())
      .mockResolvedValueOnce({
        ...successResult(),
        ...overrides,
        stdout: JSON.stringify(successReport(overrides)),
      });

    await expect(
      runOperationalAcceptance({
        environment: { KAVRIX_MONGODB_URI: 'mongodb://127.0.0.1:27017' },
        runChild,
        workspaceRoot,
      }),
    ).rejects.toThrow('Operational acceptance failed.');
  });
});

function successResult(): OperationalChildResult {
  return {
    exitCode: 0,
    outputLimitExceeded: false,
    signal: null,
    stderr: '',
    stdout: '',
    timedOut: false,
  };
}

function successReport(
  overrides: Partial<{
    numFailedTests: number;
    numPassedTests: number;
    numPendingTests: number;
    numTodoTests: number;
    numTotalTests: number;
    success: boolean;
  }> = {},
): Record<string, unknown> {
  return {
    numFailedTests: 0,
    numPassedTests: 1,
    numPendingTests: 0,
    numTodoTests: 0,
    numTotalTests: 1,
    success: true,
    testResults: [{ name: operationalFile, status: 'passed' }],
    ...overrides,
  };
}
