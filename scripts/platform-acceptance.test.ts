import { afterEach, describe, expect, it, vi } from 'vitest';

import {
  PLATFORM_INTEGRATION_FILES,
  PLATFORM_INTEGRATION_TIMEOUT_MS,
  executePlatformAcceptance,
  runBoundedChild,
  runPlatformAcceptance,
  validateVitestReport,
  type BoundedChildInvocation,
  type BoundedChildResult,
  type VitestJsonReport,
} from './platform-acceptance.js';

const allFlags = {
  KAVRIX_KEYCHAIN_INTEGRATION: '1',
  KAVRIX_KEY_FILE_INTEGRATION: '1',
  KAVRIX_CLIPBOARD_INTEGRATION: '1',
  KAVRIX_CLIPBOARD_EXCLUSIVE_SESSION: '1',
};

describe('native platform acceptance gate', () => {
  afterEach(() => {
    vi.restoreAllMocks();
  });

  it.each([
    'KAVRIX_KEYCHAIN_INTEGRATION',
    'KAVRIX_KEY_FILE_INTEGRATION',
    'KAVRIX_CLIPBOARD_INTEGRATION',
    'KAVRIX_CLIPBOARD_EXCLUSIVE_SESSION',
  ])('fails before child execution when %s is absent', async (missingFlag) => {
    const environment = Object.fromEntries(
      Object.entries(allFlags).filter(([flag]) => flag !== missingFlag),
    );
    const runChild = vi.fn();

    await expect(
      runPlatformAcceptance({
        environment,
        runChild,
        workspaceRoot: process.cwd(),
      }),
    ).rejects.toThrow('Platform acceptance prerequisites are required.');
    expect(runChild).not.toHaveBeenCalled();
  });

  it.each([
    'KAVRIX_KEYCHAIN_INTEGRATION',
    'KAVRIX_KEY_FILE_INTEGRATION',
    'KAVRIX_CLIPBOARD_INTEGRATION',
    'KAVRIX_CLIPBOARD_EXCLUSIVE_SESSION',
  ])('fails before child execution when %s is blank', async (blankFlag) => {
    const environment = { ...allFlags, [blankFlag]: '' };
    const runChild = vi.fn();

    await expect(
      runPlatformAcceptance({
        environment,
        runChild,
        workspaceRoot: process.cwd(),
      }),
    ).rejects.toThrow('Platform acceptance prerequisites are required.');
    expect(runChild).not.toHaveBeenCalled();
  });

  it('keeps flags in the environment, invokes exact files without a shell, and hides child output', async () => {
    const canary = 'native-platform-child-secret-canary';
    const stdout: string[] = [];
    const stderr: string[] = [];
    const runChild = vi.fn(
      (invocation: BoundedChildInvocation): Promise<BoundedChildResult> => {
        expect(invocation.args).toEqual([
          expect.stringContaining('vitest.mjs'),
          'run',
          '--root',
          process.cwd(),
          '--config',
          'vitest.platform.config.ts',
          '--reporter=json',
          '--passWithNoTests=false',
          ...PLATFORM_INTEGRATION_FILES,
        ]);
        expect(invocation.environment).toMatchObject(allFlags);
        expect(invocation.shell).toBe(false);
        return Promise.resolve({
          exitCode: 9,
          outputLimitExceeded: false,
          signal: null,
          stderr: canary,
          stdout: JSON.stringify({ message: canary }),
          timedOut: false,
        });
      },
    );

    expect(
      await executePlatformAcceptance({
        environment: allFlags,
        runChild,
        stderr: (message) => stderr.push(message),
        stdout: (message) => stdout.push(message),
        workspaceRoot: process.cwd(),
      }),
    ).toBe(1);
    expect(stdout).toEqual([]);
    expect(stderr).toEqual(['Platform acceptance failed.']);
    expect(JSON.stringify({ stderr, stdout })).not.toContain(canary);
  });

  it('rejects incomplete platform reports and accepts only exact all-passed coverage', async () => {
    const files = PLATFORM_INTEGRATION_FILES;
    expect(() =>
      validateVitestReport(createReport({ numTotalTests: 0 }), files),
    ).toThrow('Platform acceptance failed.');
    expect(() =>
      validateVitestReport(createReport({ numPendingTests: 1 }), files),
    ).toThrow('Platform acceptance failed.');
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
    ).toThrow('Platform acceptance failed.');
    expect(() =>
      validateVitestReport(
        createReport({ testResults: [createTestResult(files[0])] }),
        files,
      ),
    ).toThrow('Platform acceptance failed.');

    const runChild = vi.fn(() =>
      Promise.resolve({
        exitCode: 0,
        outputLimitExceeded: false,
        signal: null,
        stderr: '',
        stdout: 'not-json',
        timedOut: false,
      }),
    );
    await expect(
      runPlatformAcceptance({
        environment: allFlags,
        runChild,
        workspaceRoot: process.cwd(),
      }),
    ).rejects.toThrow('Platform acceptance failed.');

    const report = createReport({
      numPassedTests: files.length,
      numTotalTests: files.length,
      testResults: files.map(createTestResult),
    });
    const successRunner = vi.fn(() =>
      Promise.resolve({
        exitCode: 0,
        outputLimitExceeded: false,
        signal: null,
        stderr: '',
        stdout: JSON.stringify(report),
        timedOut: false,
      }),
    );
    await expect(
      runPlatformAcceptance({
        environment: allFlags,
        runChild: successRunner,
        workspaceRoot: process.cwd(),
      }),
    ).resolves.toEqual({ files: files.length, tests: files.length });
  });

  it('bounds child output and terminates children at the configured timeout', async () => {
    const output = await runBoundedChild({
      args: ['-e', "process.stdout.write('x'.repeat(2048))"],
      command: process.execPath,
      environment: process.env,
      maxOutputBytes: 1_024,
      timeoutMs: 2_000,
      workspaceRoot: process.cwd(),
    });
    expect(output.outputLimitExceeded).toBe(true);

    const timeout = await runBoundedChild({
      args: ['-e', 'setInterval(() => {}, 1_000)'],
      command: process.execPath,
      environment: process.env,
      maxOutputBytes: 1_024,
      timeoutMs: 50,
      workspaceRoot: process.cwd(),
    });
    expect(timeout.timedOut).toBe(true);
    expect(PLATFORM_INTEGRATION_TIMEOUT_MS).toBeGreaterThanOrEqual(60_000);
  });
});

function createReport(overrides: Partial<VitestJsonReport> = {}): VitestJsonReport {
  return {
    numFailedTests: 0,
    numPassedTests: 1,
    numPendingTests: 0,
    numTodoTests: 0,
    numTotalTests: 1,
    success: true,
    testResults: [createTestResult(PLATFORM_INTEGRATION_FILES[0])],
    ...overrides,
  };
}

function createTestResult(name: string): VitestJsonReport['testResults'][number] {
  return { name, status: 'passed' };
}
