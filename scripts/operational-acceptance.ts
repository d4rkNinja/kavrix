import { randomUUID } from 'node:crypto';
import { access } from 'node:fs/promises';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';

import {
  runBoundedChild,
  validateVitestReport,
  type BoundedChildInvocation,
  type BoundedChildResult,
  type VitestJsonReport,
} from '../apps/api/scripts/api-integration-gate.js';

export const OPERATIONAL_ACCEPTANCE_TIMEOUT_MS = 10 * 60_000;
export const OPERATIONAL_ACCEPTANCE_FILE =
  'apps/api/operational/operational-acceptance.integration.ts';

const MAX_CAPTURED_OUTPUT_BYTES = 4 * 1024 * 1024;
const genericEnvironmentError =
  'MongoDB operational acceptance environment is required.';
const genericGateError = 'Operational acceptance failed.';

export type OperationalChildInvocation = BoundedChildInvocation;

export type OperationalChildResult = BoundedChildResult;

export interface OperationalAcceptanceOptions {
  readonly environment?: NodeJS.ProcessEnv;
  readonly runChild?: (
    invocation: OperationalChildInvocation,
  ) => Promise<OperationalChildResult>;
  readonly timeoutMs?: number;
  readonly workspaceRoot?: string;
}

export interface ExecuteOperationalAcceptanceOptions extends OperationalAcceptanceOptions {
  readonly stderr?: (message: string) => void;
  readonly stdout?: (message: string) => void;
}

export interface OperationalAcceptanceSummary {
  readonly files: number;
  readonly tests: number;
}

export async function runOperationalAcceptance(
  options: OperationalAcceptanceOptions = {},
): Promise<OperationalAcceptanceSummary> {
  const environment = options.environment ?? process.env;
  requireMongoEnvironment(environment);
  const workspaceRoot = options.workspaceRoot ?? defaultWorkspaceRoot();
  await requireOperationalFile(workspaceRoot);

  const databaseName = `kavrix_ops_${randomUUID().replaceAll('-', '')}`;
  const childEnvironment = {
    ...environment,
    KAVRIX_DATABASE_NAME: databaseName,
  } satisfies NodeJS.ProcessEnv;
  const runChild = options.runChild ?? runBoundedChild;
  const timeoutMs = options.timeoutMs ?? OPERATIONAL_ACCEPTANCE_TIMEOUT_MS;

  const migration = await runChild({
    args: [resolveTsxEntry(), 'apps/api/scripts/mongo-migrate.ts'],
    command: process.execPath,
    environment: childEnvironment,
    maxOutputBytes: MAX_CAPTURED_OUTPUT_BYTES,
    shell: false,
    timeoutMs,
    workspaceRoot,
  });
  if (!successfulChild(migration)) throw new Error(genericGateError);

  const operational = await runChild({
    args: [
      resolveVitestEntry(),
      'run',
      '--root',
      workspaceRoot,
      '--config',
      'apps/api/vitest.operational.config.ts',
      '--reporter=json',
      '--passWithNoTests=false',
      OPERATIONAL_ACCEPTANCE_FILE,
    ],
    command: process.execPath,
    environment: childEnvironment,
    maxOutputBytes: MAX_CAPTURED_OUTPUT_BYTES,
    shell: false,
    timeoutMs,
    workspaceRoot,
  });
  if (!successfulChild(operational)) throw new Error(genericGateError);

  try {
    return validateVitestReport(parseVitestReport(operational.stdout), [
      OPERATIONAL_ACCEPTANCE_FILE,
    ]);
  } catch {
    throw new Error(genericGateError);
  }
}

export async function executeOperationalAcceptance(
  options: ExecuteOperationalAcceptanceOptions = {},
): Promise<number> {
  const writeError = options.stderr ?? console.error;
  const writeOutput = options.stdout ?? console.log;
  try {
    const summary = await runOperationalAcceptance(options);
    writeOutput(
      `Operational acceptance passed (${String(summary.files)} files, ${String(summary.tests)} tests).`,
    );
    return 0;
  } catch (error) {
    writeError(
      error instanceof Error && error.message === genericEnvironmentError
        ? genericEnvironmentError
        : genericGateError,
    );
    return 1;
  }
}

function successfulChild(result: OperationalChildResult): boolean {
  return (
    result.exitCode === 0 &&
    result.signal === null &&
    !result.timedOut &&
    !result.outputLimitExceeded
  );
}

function requireMongoEnvironment(environment: NodeJS.ProcessEnv): void {
  const mongodbUri = environment['KAVRIX_MONGODB_URI'];
  if (mongodbUri === undefined || mongodbUri.trim().length === 0) {
    throw new Error(genericEnvironmentError);
  }
}

async function requireOperationalFile(workspaceRoot: string): Promise<void> {
  try {
    await access(resolve(workspaceRoot, OPERATIONAL_ACCEPTANCE_FILE));
  } catch {
    throw new Error(genericGateError);
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

function resolveTsxEntry(): string {
  return fileURLToPath(import.meta.resolve('tsx/cli'));
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
  process.exitCode = await executeOperationalAcceptance();
}
