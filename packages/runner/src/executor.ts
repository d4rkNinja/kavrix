import { realpath, stat } from 'node:fs/promises';
import { isAbsolute } from 'node:path';
import { spawn, type ChildProcess } from 'node:child_process';

import { RunnerError } from './errors.js';
import { prepareEnvironment, type PreparedEnvironment } from './environment.js';
import type {
  RunTermination,
  RunnerOutputPolicy,
  SecureRunRequest,
  SecureRunResult,
} from './types.js';

const DEFAULT_CAPTURE_BYTES = 64 * 1_024;
const MAX_CAPTURE_BYTES = 16 * 1_024 * 1_024;
const DEFAULT_TERMINATION_GRACE_MS = 1_000;
const MAX_TIMEOUT_MS = 24 * 60 * 60 * 1_000;
const MAX_ARGUMENTS = 1_024;
const MAX_ARGUMENT_BYTES = 128 * 1_024;

interface CaptureState {
  readonly chunks: Buffer[];
  bytes: number;
  truncated: boolean;
}

function assertRequest(request: SecureRunRequest): readonly string[] {
  const argumentInput: unknown = request.arguments ?? [];
  if (
    typeof request.executable !== 'string' ||
    request.executable.length === 0 ||
    request.executable.includes('\0') ||
    !Array.isArray(argumentInput) ||
    argumentInput.length > MAX_ARGUMENTS ||
    request.cwd.includes('\0')
  ) {
    throw new RunnerError('RUNNER_INVALID_REQUEST');
  }

  let argumentBytes = Buffer.byteLength(request.executable, 'utf8');
  const argumentsList: string[] = [];
  for (const argument of argumentInput) {
    if (typeof argument !== 'string' || argument.includes('\0')) {
      throw new RunnerError('RUNNER_INVALID_REQUEST');
    }
    argumentsList.push(argument);
    argumentBytes += Buffer.byteLength(argument, 'utf8') + 1;
  }
  if (argumentBytes > MAX_ARGUMENT_BYTES) {
    throw new RunnerError('RUNNER_INVALID_REQUEST');
  }

  if (
    request.timeoutMs !== undefined &&
    (!Number.isSafeInteger(request.timeoutMs) ||
      request.timeoutMs <= 0 ||
      request.timeoutMs > MAX_TIMEOUT_MS)
  ) {
    throw new RunnerError('RUNNER_INVALID_REQUEST');
  }
  if (
    request.terminationGraceMs !== undefined &&
    (!Number.isSafeInteger(request.terminationGraceMs) ||
      request.terminationGraceMs < 0 ||
      request.terminationGraceMs > 60_000)
  ) {
    throw new RunnerError('RUNNER_INVALID_REQUEST');
  }

  return argumentsList;
}

async function validatedWorkingDirectory(cwd: string): Promise<string> {
  if (!isAbsolute(cwd)) {
    throw new RunnerError('RUNNER_INVALID_CWD');
  }
  try {
    const canonicalPath = await realpath(cwd);
    const metadata = await stat(canonicalPath);
    if (!metadata.isDirectory()) {
      throw new RunnerError('RUNNER_INVALID_CWD');
    }
    return canonicalPath;
  } catch (error) {
    if (error instanceof RunnerError) throw error;
    throw new RunnerError('RUNNER_INVALID_CWD');
  }
}

function outputPolicy(policy: RunnerOutputPolicy | undefined): Readonly<{
  maxBytes: number;
}> {
  const requestedMode: unknown = policy?.mode;
  if (policy !== undefined && requestedMode !== 'capture') {
    throw new RunnerError('RUNNER_INVALID_REQUEST');
  }
  const maxBytes = policy?.maxBytes ?? DEFAULT_CAPTURE_BYTES;
  if (!Number.isSafeInteger(maxBytes) || maxBytes < 1 || maxBytes > MAX_CAPTURE_BYTES) {
    throw new RunnerError('RUNNER_INVALID_REQUEST');
  }
  return { maxBytes };
}

function assertSecretsAbsentFromArguments(
  executable: string,
  argumentsList: readonly string[],
  secretValues: readonly string[],
): void {
  for (const secret of secretValues) {
    if (
      secret.length > 0 &&
      (executable.includes(secret) ||
        argumentsList.some((argument) => argument.includes(secret)))
    ) {
      throw new RunnerError('RUNNER_SECRET_IN_ARGUMENTS');
    }
  }
}

function appendBounded(state: CaptureState, chunk: Buffer, maxBytes: number): boolean {
  const available = maxBytes - state.bytes;
  if (available > 0) {
    const kept = Buffer.from(
      chunk.length <= available ? chunk : chunk.subarray(0, available),
    );
    state.chunks.push(kept);
    state.bytes += kept.length;
  }
  if (chunk.length > available) {
    state.truncated = true;
  }
  return state.truncated;
}

function redactSecrets(
  input: Buffer,
  secrets: readonly Buffer[],
  truncated: boolean,
): Buffer {
  const redacted = Buffer.from(input);
  for (const secret of secrets) {
    if (secret.length === 0) continue;
    let offset = input.indexOf(secret);
    while (offset >= 0) {
      redacted.fill(0x2a, offset, offset + secret.length);
      offset = input.indexOf(secret, offset + 1);
    }
    if (!truncated) continue;
    for (
      let prefixBytes = Math.min(secret.length - 1, input.length);
      prefixBytes > 0;
      prefixBytes -= 1
    ) {
      const capturedOffset = input.length - prefixBytes;
      if (input.subarray(capturedOffset).equals(secret.subarray(0, prefixBytes))) {
        redacted.fill(0x2a, capturedOffset);
        break;
      }
    }
  }
  return redacted;
}

function finishCapture(
  state: CaptureState,
  secrets: readonly Buffer[],
  boundaryMayTruncate: boolean,
): Buffer {
  const combined = Buffer.concat(state.chunks, state.bytes);
  const redacted = redactSecrets(combined, secrets, boundaryMayTruncate);
  combined.fill(0);
  for (const chunk of state.chunks) chunk.fill(0);
  state.chunks.length = 0;
  state.bytes = 0;
  return redacted;
}

function clearCapture(state: CaptureState): void {
  for (const chunk of state.chunks) chunk.fill(0);
  state.chunks.length = 0;
  state.bytes = 0;
}

function spawnChild(
  request: SecureRunRequest,
  argumentsList: readonly string[],
  cwd: string,
  environment: PreparedEnvironment,
): ChildProcess {
  try {
    return spawn(request.executable, argumentsList, {
      cwd,
      env: environment.childEnvironment,
      shell: false,
      windowsHide: true,
      stdio: ['ignore', 'pipe', 'pipe'],
    });
  } catch {
    throw new RunnerError('RUNNER_SPAWN_FAILED');
  }
}

/**
 * Runs one executable directly with a minimal environment and bounded output.
 * This is process hygiene, not a sandbox: the selected executable can read its
 * injected environment and intentionally disclose it or pass it to descendants.
 */
export async function runSecureCommand(
  request: SecureRunRequest,
): Promise<SecureRunResult> {
  if (request.signal?.aborted === true) {
    throw new RunnerError('RUNNER_ABORTED');
  }

  const argumentsList = assertRequest(request);
  const cwd = await validatedWorkingDirectory(request.cwd);
  const policy = outputPolicy(request.output);
  const environment = prepareEnvironment(
    request.environment ?? [],
    request.inheritEnvironment ?? [],
  );

  try {
    assertSecretsAbsentFromArguments(
      request.executable,
      argumentsList,
      environment.secretValues,
    );

    const child = spawnChild(request, argumentsList, cwd, environment);
    const stdout: CaptureState = { chunks: [], bytes: 0, truncated: false };
    const stderr: CaptureState = { chunks: [], bytes: 0, truncated: false };

    return await new Promise<SecureRunResult>((resolve, reject) => {
      let requestedTermination: Exclude<RunTermination, 'exit' | 'signal'> | null =
        null;
      let timeout: NodeJS.Timeout | undefined;
      let forceKillTimeout: NodeJS.Timeout | undefined;
      let settled = false;

      const clearLifecycle = (): void => {
        if (timeout !== undefined) clearTimeout(timeout);
        if (forceKillTimeout !== undefined) clearTimeout(forceKillTimeout);
        request.signal?.removeEventListener('abort', abort);
      };

      const terminate = (reason: Exclude<RunTermination, 'exit' | 'signal'>): void => {
        if (requestedTermination !== null || settled) return;
        requestedTermination = reason;
        child.kill('SIGTERM');
        const grace = request.terminationGraceMs ?? DEFAULT_TERMINATION_GRACE_MS;
        forceKillTimeout = setTimeout(() => {
          if (!settled) child.kill('SIGKILL');
        }, grace);
      };

      const abort = (): void => {
        terminate('aborted');
      };

      child.stdout?.on('data', (chunk: Buffer) => {
        try {
          if (appendBounded(stdout, chunk, policy.maxBytes)) {
            terminate('output-limit');
          }
        } finally {
          chunk.fill(0);
        }
      });
      child.stderr?.on('data', (chunk: Buffer) => {
        try {
          if (appendBounded(stderr, chunk, policy.maxBytes)) {
            terminate('output-limit');
          }
        } finally {
          chunk.fill(0);
        }
      });

      child.once('error', () => {
        if (settled) return;
        settled = true;
        clearLifecycle();
        clearCapture(stdout);
        clearCapture(stderr);
        reject(new RunnerError('RUNNER_SPAWN_FAILED'));
      });

      child.once('close', (exitCode, signal) => {
        if (settled) return;
        settled = true;
        clearLifecycle();
        const termination =
          requestedTermination ?? (signal === null ? 'exit' : 'signal');
        const outputTruncated = stdout.truncated || stderr.truncated;
        const boundaryMayTruncate = outputTruncated || termination !== 'exit';
        resolve({
          exitCode,
          signal,
          termination,
          outputTruncated,
          stdout: finishCapture(stdout, environment.secretBuffers, boundaryMayTruncate),
          stderr: finishCapture(stderr, environment.secretBuffers, boundaryMayTruncate),
        });
      });

      if (request.timeoutMs !== undefined) {
        timeout = setTimeout(() => {
          terminate('timeout');
        }, request.timeoutMs);
      }
      request.signal?.addEventListener('abort', abort, { once: true });
      if (request.signal?.aborted === true) abort();
    });
  } finally {
    environment.clear();
  }
}
