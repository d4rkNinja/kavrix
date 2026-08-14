import { spawn } from 'node:child_process';
import { access } from 'node:fs/promises';
import { dirname, join, resolve, sep } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';

export const PLATFORM_INTEGRATION_FILES = [
  'packages/keychain/test/native-keychain.integration.test.ts',
  'packages/key-files/integration/platform-key-file.integration.ts',
  'packages/clipboard/integration/system-clipboard.integration.ts',
] as const;
export const PLATFORM_REQUIRED_FLAGS = [
  'KAVRIX_KEYCHAIN_INTEGRATION',
  'KAVRIX_KEY_FILE_INTEGRATION',
  'KAVRIX_CLIPBOARD_INTEGRATION',
  'KAVRIX_CLIPBOARD_EXCLUSIVE_SESSION',
] as const;
export const PLATFORM_INTEGRATION_TIMEOUT_MS = 10 * 60_000;

const MAX_CAPTURED_OUTPUT_BYTES = 4 * 1024 * 1024;
const genericPrerequisiteError = 'Platform acceptance prerequisites are required.';
const genericGateError = 'Platform acceptance failed.';

export interface BoundedChildInvocation {
  readonly args: readonly string[];
  readonly command: string;
  readonly environment: NodeJS.ProcessEnv;
  readonly maxOutputBytes: number;
  readonly shell?: false;
  readonly timeoutMs: number;
  readonly workspaceRoot: string;
}

export interface BoundedChildResult {
  readonly exitCode: number | null;
  readonly outputLimitExceeded: boolean;
  readonly signal: NodeJS.Signals | null;
  readonly stderr: string;
  readonly stdout: string;
  readonly timedOut: boolean;
}

export interface VitestJsonReport {
  readonly numFailedTests: number;
  readonly numPassedTests: number;
  readonly numPendingTests: number;
  readonly numTodoTests: number;
  readonly numTotalTests: number;
  readonly success: boolean;
  readonly testResults: readonly {
    readonly name: string;
    readonly status: string;
  }[];
}

export interface PlatformAcceptanceOptions {
  readonly environment?: NodeJS.ProcessEnv;
  readonly runChild?: RunChild;
  readonly timeoutMs?: number;
  readonly workspaceRoot?: string;
}

export interface ExecutePlatformAcceptanceOptions extends PlatformAcceptanceOptions {
  readonly stderr?: (message: string) => void;
  readonly stdout?: (message: string) => void;
}

export interface PlatformAcceptanceSummary {
  readonly files: number;
  readonly tests: number;
}

export type RunChild = (
  invocation: BoundedChildInvocation,
) => Promise<BoundedChildResult>;

export async function runBoundedChild(
  invocation: BoundedChildInvocation,
): Promise<BoundedChildResult> {
  return new Promise((resolveResult) => {
    const child = spawn(invocation.command, [...invocation.args], {
      cwd: invocation.workspaceRoot,
      env: invocation.environment,
      shell: false,
      stdio: ['ignore', 'pipe', 'pipe'],
      windowsHide: true,
    });
    const stdoutChunks: Buffer[] = [];
    const stderrChunks: Buffer[] = [];
    let capturedBytes = 0;
    let outputLimitExceeded = false;
    let settled = false;
    let timedOut = false;
    let forceKillTimeout: NodeJS.Timeout | undefined;

    const stopChild = (): void => {
      if (child.exitCode !== null || child.signalCode !== null) return;
      child.kill();
      forceKillTimeout ??= setTimeout(() => {
        if (child.exitCode === null && child.signalCode === null) {
          child.kill('SIGKILL');
        }
      }, 1_000);
    };
    const capture = (chunk: Buffer, target: Buffer[]): void => {
      if (outputLimitExceeded) return;
      capturedBytes += chunk.byteLength;
      if (capturedBytes > invocation.maxOutputBytes) {
        outputLimitExceeded = true;
        stopChild();
        return;
      }
      target.push(chunk);
    };
    const finish = (result: BoundedChildResult): void => {
      if (settled) return;
      settled = true;
      clearTimeout(timeout);
      if (forceKillTimeout !== undefined) clearTimeout(forceKillTimeout);
      resolveResult(result);
    };
    const timeout = setTimeout(() => {
      timedOut = true;
      stopChild();
    }, invocation.timeoutMs);

    child.stdout.on('data', (chunk: Buffer) => {
      capture(chunk, stdoutChunks);
    });
    child.stderr.on('data', (chunk: Buffer) => {
      capture(chunk, stderrChunks);
    });
    child.once('error', () => {
      finish({
        exitCode: null,
        outputLimitExceeded,
        signal: null,
        stderr: '',
        stdout: '',
        timedOut,
      });
    });
    child.once('close', (exitCode, signal) => {
      finish({
        exitCode,
        outputLimitExceeded,
        signal,
        stderr: Buffer.concat(stderrChunks).toString('utf8'),
        stdout: Buffer.concat(stdoutChunks).toString('utf8'),
        timedOut,
      });
    });
  });
}

export async function runPlatformAcceptance(
  options: PlatformAcceptanceOptions = {},
): Promise<PlatformAcceptanceSummary> {
  const environment = options.environment ?? process.env;
  requirePlatformFlags(environment);
  const workspaceRoot = options.workspaceRoot ?? defaultWorkspaceRoot();
  try {
    await Promise.all(
      PLATFORM_INTEGRATION_FILES.map((file) => access(resolve(workspaceRoot, file))),
    );
  } catch {
    throw new Error(genericGateError);
  }

  const invocation: BoundedChildInvocation = {
    args: [
      resolveVitestEntry(),
      'run',
      '--root',
      workspaceRoot,
      '--config',
      'vitest.platform.config.ts',
      '--reporter=json',
      '--passWithNoTests=false',
      ...PLATFORM_INTEGRATION_FILES,
    ],
    command: process.execPath,
    environment,
    maxOutputBytes: MAX_CAPTURED_OUTPUT_BYTES,
    shell: false,
    timeoutMs: options.timeoutMs ?? PLATFORM_INTEGRATION_TIMEOUT_MS,
    workspaceRoot,
  };
  const result = await (options.runChild ?? runBoundedChild)(invocation);
  if (
    result.exitCode !== 0 ||
    result.signal !== null ||
    result.timedOut ||
    result.outputLimitExceeded
  ) {
    throw new Error(genericGateError);
  }

  return validateVitestReport(parseVitestReport(result.stdout));
}

export async function executePlatformAcceptance(
  options: ExecutePlatformAcceptanceOptions = {},
): Promise<number> {
  const writeError = options.stderr ?? console.error;
  const writeOutput = options.stdout ?? console.log;
  try {
    const summary = await runPlatformAcceptance(options);
    writeOutput(
      `Platform acceptance passed (${String(summary.files)} files, ${String(summary.tests)} tests).`,
    );
    return 0;
  } catch (error) {
    writeError(
      error instanceof Error && error.message === genericPrerequisiteError
        ? genericPrerequisiteError
        : genericGateError,
    );
    return 1;
  }
}

export function validateVitestReport(
  report: VitestJsonReport,
  integrationFiles: readonly string[] = PLATFORM_INTEGRATION_FILES,
): PlatformAcceptanceSummary {
  const expectedFiles = new Set(integrationFiles.map(normalizePath));
  const reportedFiles = new Set(
    report.testResults.map((result) =>
      normalizeReportedFile(result.name, expectedFiles),
    ),
  );
  const allFilesPassed = report.testResults.every(
    (result) => result.status === 'passed',
  );
  const everyFileReported =
    reportedFiles.size === expectedFiles.size &&
    [...expectedFiles].every((file) => reportedFiles.has(file));

  if (
    !report.success ||
    report.numTotalTests === 0 ||
    report.numPassedTests !== report.numTotalTests ||
    report.numFailedTests !== 0 ||
    report.numPendingTests !== 0 ||
    report.numTodoTests !== 0 ||
    !allFilesPassed ||
    !everyFileReported
  ) {
    throw new Error(genericGateError);
  }

  return { files: expectedFiles.size, tests: report.numTotalTests };
}

function requirePlatformFlags(environment: NodeJS.ProcessEnv): void {
  if (PLATFORM_REQUIRED_FLAGS.some((flag) => environment[flag] !== '1')) {
    throw new Error(genericPrerequisiteError);
  }
}

function parseVitestReport(serializedReport: string): VitestJsonReport {
  try {
    const report: unknown = JSON.parse(serializedReport);
    if (!isVitestJsonReport(report)) throw new Error(genericGateError);
    return report;
  } catch {
    throw new Error(genericGateError);
  }
}

function isVitestJsonReport(value: unknown): value is VitestJsonReport {
  if (typeof value !== 'object' || value === null) return false;
  const report = value as Record<string, unknown>;
  return (
    typeof report['numFailedTests'] === 'number' &&
    typeof report['numPassedTests'] === 'number' &&
    typeof report['numPendingTests'] === 'number' &&
    typeof report['numTodoTests'] === 'number' &&
    typeof report['numTotalTests'] === 'number' &&
    typeof report['success'] === 'boolean' &&
    Array.isArray(report['testResults']) &&
    report['testResults'].every(
      (result) =>
        typeof result === 'object' &&
        result !== null &&
        typeof (result as Record<string, unknown>)['name'] === 'string' &&
        typeof (result as Record<string, unknown>)['status'] === 'string',
    )
  );
}

function normalizeReportedFile(
  name: string,
  expectedFiles: ReadonlySet<string>,
): string {
  const normalizedName = normalizePath(name);
  for (const expectedFile of expectedFiles) {
    if (
      normalizedName === expectedFile ||
      normalizedName.endsWith(`/${expectedFile}`)
    ) {
      return expectedFile;
    }
  }
  return normalizedName;
}

function normalizePath(path: string): string {
  return sep === '/' ? path : path.replaceAll(sep, '/');
}

function resolveVitestEntry(): string {
  const packageJson = fileURLToPath(import.meta.resolve('vitest/package.json'));
  return join(dirname(packageJson), 'vitest.mjs');
}

function defaultWorkspaceRoot(): string {
  return resolve(dirname(fileURLToPath(import.meta.url)), '..');
}

const invokedScript = process.argv[1];
if (
  invokedScript !== undefined &&
  import.meta.url === pathToFileURL(resolve(invokedScript)).href
) {
  process.exitCode = await executePlatformAcceptance();
}
