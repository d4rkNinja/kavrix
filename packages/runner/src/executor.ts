import { realpath, stat } from 'node:fs/promises';
import { isAbsolute } from 'node:path';
import { spawn, type ChildProcess } from 'node:child_process';

import { RunnerError } from './errors.js';
import { prepareEnvironment, type PreparedEnvironment } from './environment.js';
import {
  RUNNER_LIMITS,
  type RunTermination,
  type RunnerInputPolicy,
  type RunnerOutputCapturePolicy,
  type RunnerOutputPolicy,
  type SecureRunRequest,
  type SecureRunResult,
} from './types.js';

const {
  defaultCaptureBytes: DEFAULT_CAPTURE_BYTES,
  maxCaptureBytes: MAX_CAPTURE_BYTES,
  defaultTerminationGraceMs: DEFAULT_TERMINATION_GRACE_MS,
  maxTerminationGraceMs: MAX_TERMINATION_GRACE_MS,
  maxTimeoutMs: MAX_TIMEOUT_MS,
  maxArguments: MAX_ARGUMENTS,
  maxArgumentBytes: MAX_ARGUMENT_BYTES,
} = RUNNER_LIMITS;

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
    typeof request.cwd !== 'string' ||
    request.cwd.includes('\0') ||
    !Array.isArray(argumentInput) ||
    argumentInput.length > MAX_ARGUMENTS
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
      request.terminationGraceMs > MAX_TERMINATION_GRACE_MS)
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
  mode: 'capture' | 'inherit' | 'pipe';
  maxBytes: number;
}> {
  if (policy === undefined) return { mode: 'capture', maxBytes: DEFAULT_CAPTURE_BYTES };
  switch (policy.mode) {
    case 'inherit': {
      // Typed callers cannot set maxBytes here; untyped callers may try. Any
      // non-integer extra field fails closed instead of being ignored.
      const extra = policy as unknown as Pick<RunnerOutputCapturePolicy, 'maxBytes'>;
      if (extra.maxBytes !== undefined && !Number.isSafeInteger(extra.maxBytes)) {
        throw new RunnerError('RUNNER_INVALID_REQUEST');
      }
      return { mode: 'inherit', maxBytes: 0 };
    }
    case 'pipe':
      return { mode: 'pipe', maxBytes: 0 };
    case 'capture': {
      const maxBytes = policy.maxBytes ?? DEFAULT_CAPTURE_BYTES;
      if (
        !Number.isSafeInteger(maxBytes) ||
        maxBytes < 1 ||
        maxBytes > MAX_CAPTURE_BYTES
      ) {
        throw new RunnerError('RUNNER_INVALID_REQUEST');
      }
      return { mode: 'capture', maxBytes };
    }
    default:
      throw new RunnerError('RUNNER_INVALID_REQUEST');
  }
}

function inputStdio(inputPolicy: RunnerInputPolicy): 'ignore' | 'inherit' | 'pipe' {
  switch (inputPolicy) {
    case 'ignore':
      return 'ignore';
    case 'inherit':
      return 'inherit';
    case 'pipe':
      return 'pipe';
    default:
      throw new RunnerError('RUNNER_INVALID_REQUEST');
  }
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
  stdio: readonly ('ignore' | 'inherit' | 'pipe')[],
): ChildProcess {
  // Directory validation yields to the event loop. Cancellation during that
  // work must prevent execution, even if the initial signal check passed.
  if (request.signal?.aborted === true) {
    throw new RunnerError('RUNNER_ABORTED');
  }
  try {
    return spawn(request.executable, argumentsList, {
      cwd,
      env: environment.childEnvironment,
      shell: false,
      windowsHide: true,
      // POSIX: the child leads its own process group, so tree termination can
      // signal every descendant (see requestTreeTermination). Windows is
      // excluded because console-group assignment there would change
      // terminal signal delivery, and Windows tree termination uses taskkill.
      detached: process.platform !== 'win32',
      stdio: [...stdio],
    });
  } catch {
    throw new RunnerError('RUNNER_SPAWN_FAILED');
  }
}

const IS_POSIX = process.platform !== 'win32';

/**
 * Signals the POSIX process group led by the child. Detached spawning makes
 * the child a group leader, so the negative pid reaches every descendant.
 * ESRCH only reports that the group is already gone.
 */
function killChildProcessGroup(child: ChildProcess, signal: NodeJS.Signals): boolean {
  const pid = child.pid;
  if (pid === undefined) return false;
  try {
    process.kill(-pid, signal);
    return true;
  } catch {
    return false;
  }
}

/**
 * Requests the first-phase termination of the child's whole tree. POSIX
 * signals the process group with the requested signal (catchable, honoring
 * the grace period) and falls back to the direct child when the group no
 * longer exists. Windows has no signalable group here and its direct-child
 * signal mapping (TerminateProcess) would land within the same tick and turn
 * a later sweep into a no-op against an exited pid, so the tree sweep is the
 * termination request itself: taskkill /T /F walks the parent chain while the
 * tree is still alive and force-terminates descendants and the direct child.
 */
function requestTreeTermination(child: ChildProcess, signal: NodeJS.Signals): void {
  if (IS_POSIX) {
    if (!killChildProcessGroup(child, signal)) {
      child.kill(signal);
    }
    return;
  }
  const pid = child.pid;
  if (pid === undefined) {
    // The spawn itself failed; keep the harmless direct kill.
    child.kill(signal);
    return;
  }
  try {
    const taskkill = spawn('taskkill', ['/pid', String(pid), '/t', '/f'], {
      shell: false,
      windowsHide: true,
      stdio: 'ignore',
    });
    taskkill.once('error', () => {
      // Absorbed by contract: a sweep that cannot run (taskkill missing, or a
      // tree that already exited) is the desired end state, not an error. The
      // grace escalation still force-kills the direct child if it survived.
    });
  } catch {
    // spawn rejects only on invalid arguments; guard the timer callback so a
    // termination request can never throw into the event loop. The grace
    // escalation below remains the terminator of last resort.
  }
}

/**
 * Grace-period escalation. POSIX signals the group with SIGKILL, falling back
 * to the direct child when the group is gone. Windows ends the direct child
 * through the SIGKILL-to-TerminateProcess mapping; the tree was already swept
 * when termination was requested, and a descendant that escaped that sweep is
 * out of reach for a pid-scoped kill (a second taskkill would see the direct
 * child die first and become a no-op for the rest of the tree).
 */
function forceTreeTermination(child: ChildProcess): void {
  if (IS_POSIX && killChildProcessGroup(child, 'SIGKILL')) {
    return;
  }
  child.kill('SIGKILL');
}

/**
 * Attributes a child close to this runner's own termination request. A direct
 * child.kill reports the requested signal on every platform, but the Windows
 * tree sweep is an external taskkill: the close event then carries the raw
 * TerminateProcess artifact (exit code 1, no signal) instead of the signal a
 * caller would observe for the same requested SIGTERM-equivalent kill. When
 * this runner requested termination and the child closed with that artifact,
 * report the requested signal so requested terminations keep one observable
 * shape across platforms and across direct and tree kills. A child that
 * exited on its own with another code keeps its real exit code.
 */
function attributeRequestedClose(
  exitCode: number | null,
  signal: NodeJS.Signals | null,
): { exitCode: number | null; signal: NodeJS.Signals | null } {
  if (IS_POSIX || signal !== null || exitCode !== 1) {
    return { exitCode, signal };
  }
  return { exitCode: null, signal: 'SIGTERM' };
}

/**
 * Runs one executable directly with a minimal environment and bounded output.
 * This is process hygiene, not a sandbox: the selected executable can read its
 * injected environment and intentionally disclose it or pass it to descendants.
 *
 * Output defaults to bounded capture with secret redaction. Inherit mode hands
 * this process's streams to the child directly: nothing is captured, so no
 * redaction is possible and callers accept that child output reaches the
 * terminal unfiltered.
 *
 * Two limits are imposed by the platform rather than by this module. Windows
 * copies a fixed set of shell variables (including PATH, SYSTEMROOT, TEMP, and
 * the USER* family) into every child regardless of the environment supplied
 * here, so a child there always observes more names than were mapped or
 * inherited; none of them carry a released value.
 *
 * Termination reaches the spawned tree, not only the direct child. POSIX
 * children lead their own process group (spawned detached), so a timeout, an
 * abort, or an output-limit kill signals every group member, honoring the
 * grace period, with the direct child as the fallback once the group is gone.
 * Because of that group, terminal-generated signals such as Ctrl+C are not
 * delivered to the child implicitly; callers that need them must forward
 * signals through the onSpawn handle. Windows has no signalable group here:
 * the termination request is a taskkill /T /F sweep over the live parent
 * chain, and the grace-timeout escalation ends a surviving direct child
 * through TerminateProcess. Requested terminations are reported with the
 * requested signal on every platform, whatever mechanism landed the kill, so
 * callers observe one result shape. A descendant that escapes both (for
 * example one re-parented between the sweep and the escalation) can still
 * outlive the run; tree termination is best-effort process hygiene, not a
 * sandbox.
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
  const requestedInput: unknown = request.input ?? 'ignore';
  if (
    requestedInput !== 'ignore' &&
    requestedInput !== 'inherit' &&
    requestedInput !== 'pipe'
  ) {
    throw new RunnerError('RUNNER_INVALID_REQUEST');
  }
  const inputStdioMode = inputStdio(requestedInput);
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

    if (policy.mode === 'inherit') {
      return await runStreamingChild(request, argumentsList, cwd, environment, [
        inputStdioMode === 'pipe' ? 'ignore' : inputStdioMode,
        'inherit',
        'inherit',
      ]);
    }

    if (policy.mode === 'pipe') {
      return await runStreamingChild(request, argumentsList, cwd, environment, [
        inputStdioMode,
        'pipe',
        'pipe',
      ]);
    }

    const child = spawnChild(request, argumentsList, cwd, environment, [
      inputStdioMode,
      'pipe',
      'pipe',
    ]);
    const stdout: CaptureState = { chunks: [], bytes: 0, truncated: false };
    const stderr: CaptureState = { chunks: [], bytes: 0, truncated: false };

    return await new Promise<SecureRunResult>((resolve, reject) => {
      let requestedTermination: Exclude<RunTermination, 'exit' | 'signal'> | null =
        null;
      let timeout: NodeJS.Timeout | undefined;
      let forceKillTimeout: NodeJS.Timeout | undefined;
      let settled = false;
      let observerFailed = false;

      const clearLifecycle = (): void => {
        if (timeout !== undefined) clearTimeout(timeout);
        if (forceKillTimeout !== undefined) clearTimeout(forceKillTimeout);
        request.signal?.removeEventListener('abort', abort);
      };

      const terminate = (reason: Exclude<RunTermination, 'exit' | 'signal'>): void => {
        if (requestedTermination !== null || settled) return;
        requestedTermination = reason;
        requestTreeTermination(child, 'SIGTERM');
        const grace = request.terminationGraceMs ?? DEFAULT_TERMINATION_GRACE_MS;
        forceKillTimeout = setTimeout(() => {
          if (!settled) forceTreeTermination(child);
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
        if (observerFailed) {
          clearCapture(stdout);
          clearCapture(stderr);
          reject(new RunnerError('RUNNER_SPAWN_FAILED'));
          return;
        }
        const observed =
          requestedTermination === null
            ? { exitCode, signal }
            : attributeRequestedClose(exitCode, signal);
        const termination =
          requestedTermination ?? (observed.signal === null ? 'exit' : 'signal');
        const outputTruncated = stdout.truncated || stderr.truncated;
        const boundaryMayTruncate = outputTruncated || termination !== 'exit';
        resolve({
          exitCode: observed.exitCode,
          signal: observed.signal,
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
      // Install supervision before exposing the handle. A callback may throw
      // or cancel; never let it orphan a child or disclose its error message.
      try {
        request.onSpawn?.(child);
      } catch {
        observerFailed = true;
        forceTreeTermination(child);
      }
    });
  } finally {
    environment.clear();
  }
}

/**
 * Runs one child whose streams are handed through directly (inherit) or to
 * the caller via onSpawn (pipe). Nothing is captured, buffered, or redacted
 * in these modes; timeouts and aborts still terminate the tree. With
 * `input: 'pipe'` the caller owns the child's stdin: it must be written and
 * ended through the onSpawn handle, since nothing closes it automatically.
 */
async function runStreamingChild(
  request: SecureRunRequest,
  argumentsList: readonly string[],
  cwd: string,
  environment: PreparedEnvironment,
  stdio: readonly ('ignore' | 'inherit' | 'pipe')[],
): Promise<SecureRunResult> {
  const child = spawnChild(request, argumentsList, cwd, environment, stdio);
  return await new Promise<SecureRunResult>((resolve, reject) => {
    let requestedTermination: Exclude<RunTermination, 'exit' | 'signal'> | null = null;
    let timeout: NodeJS.Timeout | undefined;
    let forceKillTimeout: NodeJS.Timeout | undefined;
    let settled = false;
    let observerFailed = false;

    const clearLifecycle = (): void => {
      if (timeout !== undefined) clearTimeout(timeout);
      if (forceKillTimeout !== undefined) clearTimeout(forceKillTimeout);
      request.signal?.removeEventListener('abort', abort);
    };

    const terminate = (reason: Exclude<RunTermination, 'exit' | 'signal'>): void => {
      if (requestedTermination !== null || settled) return;
      requestedTermination = reason;
      requestTreeTermination(child, 'SIGTERM');
      const grace = request.terminationGraceMs ?? DEFAULT_TERMINATION_GRACE_MS;
      forceKillTimeout = setTimeout(() => {
        if (!settled) forceTreeTermination(child);
      }, grace);
    };

    const abort = (): void => {
      terminate('aborted');
    };

    child.once('error', () => {
      if (settled) return;
      settled = true;
      clearLifecycle();
      reject(new RunnerError('RUNNER_SPAWN_FAILED'));
    });

    child.once('close', (exitCode, signal) => {
      if (settled) return;
      settled = true;
      clearLifecycle();
      if (observerFailed) {
        reject(new RunnerError('RUNNER_SPAWN_FAILED'));
        return;
      }
      const observed =
        requestedTermination === null
          ? { exitCode, signal }
          : attributeRequestedClose(exitCode, signal);
      resolve({
        exitCode: observed.exitCode,
        signal: observed.signal,
        termination:
          requestedTermination ?? (observed.signal === null ? 'exit' : 'signal'),
        outputTruncated: false,
      });
    });

    if (request.timeoutMs !== undefined) {
      timeout = setTimeout(() => {
        terminate('timeout');
      }, request.timeoutMs);
    }
    request.signal?.addEventListener('abort', abort, { once: true });
    if (request.signal?.aborted === true) abort();
    try {
      request.onSpawn?.(child);
    } catch {
      observerFailed = true;
      forceTreeTermination(child);
    }
  });
}
