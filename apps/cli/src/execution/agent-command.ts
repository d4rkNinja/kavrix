import { randomBytes, randomUUID } from 'node:crypto';
import type { ChildProcess } from 'node:child_process';
import { chmod, unlink } from 'node:fs/promises';
import {
  createServer,
  connect as netConnect,
  type Server,
  type Socket,
} from 'node:net';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import {
  agentBrokerClientFrameSchema,
  agentBrokerRequestSchema,
  agentBrokerServerFrameSchema,
  authorizationReasonSchema,
  secretValueSchema,
  type AgentBrokerClientFrame,
  type AgentBrokerRequest,
  type AgentBrokerServerFrame,
  type AuthorizationReason,
  type PermissionEntry,
} from '@kavrix/schemas';
import { RunnerError, runSecureCommand, type EnvironmentMapping } from '@kavrix/runner';

import {
  closeDatabaseFlatVault,
  openDatabaseFlatVault,
  readDatabaseFlatSecrets,
  usesDatabaseContainer,
  type DatabaseFlatCommandOptions,
} from '../database-flat-commands.js';
import { AuthorizationState, nowIso } from './authorization-state.js';
import { requestApproval } from './confirm.js';
import { CodedCliError, invalidConfiguration } from './exit-codes.js';
import { resolveExecutable } from './executable.js';
import {
  canonicalizeDirectory,
  evaluatePermission,
  executionWindowMs,
  type EvaluationContext,
} from './engine.js';
import {
  NdjsonDecoder,
  boundedPreview,
  safeCommandName,
  streamOutputFrames,
  tokensMatch,
} from './broker-protocol.js';
import { loadProjectConfig } from './project-config.js';
import { forwardableSignals, signalExitCode } from './signals.js';

export const AGENT_BROKER_ENV = 'KAVRIX_AGENT_BROKER';
export const AGENT_TOKEN_ENV = 'KAVRIX_AGENT_TOKEN';

/** @internal Test-only broker access; production callers use executeAgentRun. */
export async function startAgentBrokerForTest(
  session: BrokerSession,
): Promise<ReturnType<typeof startBroker>> {
  return await startBroker(session);
}

const CONNECT_TIMEOUT_MS = 10_000;

export interface AgentRunOptions extends DatabaseFlatCommandOptions {
  readonly agentName: string;
  readonly config?: string | undefined;
  readonly json?: boolean | undefined;
  readonly executableAndArgs: readonly string[];
}

export interface AgentExecOptions {
  readonly permission: string;
  readonly executableAndArgs: readonly string[];
}

/**
 * Runs one AI-agent process under the credential firewall. The agent receives
 * no credential material â€” only a local broker endpoint and a one-session
 * token â€” and every credential-backed operation must be requested through
 * `kavrix agent exec`, where Kavrix authorizes the operation against the
 * agent's permission entries and supplies the secret directly to the
 * authorized child only.
 *
 * Residual boundary: any descendant of the agent inherits the endpoint and
 * token environment variables, so broker access is available to the whole
 * agent process tree; policy still gates every individual request. Secrets
 * live in broker memory for the session lifetime, which same-user process
 * inspection can read â€” identical to the documented unlocked-vault limit.
 */
export async function executeAgentRun(options: AgentRunOptions): Promise<unknown> {
  const argv = options.executableAndArgs;
  if (argv.length === 0 || (argv[0] ?? '').length === 0) {
    throw invalidConfiguration('An agent command is required after `--`.');
  }

  const configDocument =
    options.config !== undefined ? await loadProjectConfig(options.config) : null;
  if (configDocument === null) {
    throw invalidConfiguration(
      'Agent permissions live in a project file; pass --config or create kavrix.yaml.',
    );
  }
  const agentDefinition = configDocument.document.agents?.[options.agentName];
  if (agentDefinition === undefined) {
    throw invalidConfiguration(
      `Agent '${options.agentName}' is not defined in the project file.`,
    );
  }
  const permissions: Readonly<Record<string, PermissionEntry>> =
    agentDefinition.permissions;

  if (!(await usesDatabaseContainer(options))) {
    throw invalidConfiguration(
      'kavrix agent run requires a database profile; create one with `kavrix db profile add`.',
    );
  }

  const secretNames = new Set<string>();
  for (const entry of Object.values(permissions)) {
    if (entry.deny !== true && entry.secret !== undefined)
      secretNames.add(entry.secret);
  }

  const flatSecrets = await readDatabaseFlatSecrets(options, []);
  const handle = await openDatabaseFlatVault(options, flatSecrets);
  let secrets: Map<string, string>;
  let authzKey: Uint8Array;
  let keyFile: string;
  try {
    secrets = new Map<string, string>();
    await handle.session.inspectVault(handle.vaultId, (payload) => {
      for (const name of secretNames) {
        const record = payload.records[name];
        if (record !== undefined) secrets.set(name, record.value);
      }
    });
    authzKey = handle.session.authorizationStateKey();
    keyFile = handle.profile.keyFile;
  } finally {
    await closeDatabaseFlatVault(handle).catch(() => undefined);
  }
  const scopeId = handle.session.databaseId;

  const state = await openAgentState(keyFile, authzKey, scopeId);

  const session: BrokerSession = {
    token: randomBytes(32).toString('base64url'),
    permissions,
    secrets,
    state,
    platform: process.platform,
    counters: { allowed: 0, denied: 0 },
    queue: Promise.resolve(),
  };

  const broker = await startBroker(session);

  const resolution = await resolveExecutable(argv[0] ?? '');
  if (resolution.status !== 'resolved') {
    await broker.cleanup();
    state.close();
    throw invalidConfiguration('The agent executable could not be resolved.');
  }

  const childRef: { current: ChildProcess | null } = { current: null };
  const handlers = installSignalForwarding(childRef);

  let result;
  try {
    result = await runSecureCommand({
      executable: resolution.absolutePath,
      arguments: argv.slice(1),
      cwd: process.cwd(),
      environment: [
        [AGENT_BROKER_ENV, { kind: 'text', value: broker.endpoint }],
        [
          AGENT_TOKEN_ENV,
          { kind: 'secret', value: secretValueSchema.parse(session.token) },
        ],
      ] satisfies readonly EnvironmentMapping[],
      inheritEnvironment: INHERITED_ENVIRONMENT,
      input: 'inherit',
      output: { mode: 'inherit' },
      onSpawn(child) {
        childRef.current = child;
      },
    });
  } catch (error) {
    if (error instanceof RunnerError && error.code === 'RUNNER_SPAWN_FAILED') {
      throw new CodedCliError(
        'USAGE_ERROR',
        'The agent executable could not be started.',
      );
    }
    throw error;
  } finally {
    for (const [signalName, handler] of handlers) {
      process.off(signalName, handler);
    }
    await session.queue.catch(() => undefined);
    await broker.cleanup();
    session.secrets = new Map();
    state.close();
  }

  return {
    ran: true,
    agent: options.agentName,
    allowedRequests: session.counters.allowed,
    deniedRequests: session.counters.denied,
    exitCode: result.exitCode ?? signalExitCode(result.signal),
    signal: result.signal,
    termination: result.termination,
  };
}

/** Client half executed inside the agent session for one authorized operation. */
export async function executeAgentExec(options: AgentExecOptions): Promise<unknown> {
  const endpoint = process.env[AGENT_BROKER_ENV];
  const token = process.env[AGENT_TOKEN_ENV];
  if (
    endpoint === undefined ||
    endpoint.length === 0 ||
    token === undefined ||
    token.length === 0
  ) {
    throw invalidConfiguration(
      'kavrix agent exec must run inside a Kavrix agent session started with `kavrix agent run`.',
    );
  }
  const argv = options.executableAndArgs;
  if (argv.length === 0 || (argv[0] ?? '').length === 0) {
    throw invalidConfiguration('A command is required after `--`.');
  }

  const request: AgentBrokerRequest = {
    v: 1,
    token,
    op: 'exec',
    permission: validatedPermission(options.permission),
    argv: [...argv],
  };

  const socket = netConnect(endpoint);
  await waitForConnect(socket);

  return await new Promise<unknown>((resolvePromise, rejectPromise) => {
    let denialReason: AuthorizationReason | undefined;
    let finalExit: { exitCode: number | null; signal: string | null } | undefined;
    const decoder = new NdjsonDecoder();
    let settled = false;

    const finishSuccess = (): void => {
      if (settled) return;
      settled = true;
      if (finalExit === undefined) {
        socket.destroy();
        process.exitCode = 1;
        resolvePromise({
          decision:
            denialReason === undefined
              ? { outcome: 'allow', reason: 'policy-allowed' }
              : { outcome: 'deny', reason: denialReason },
          exitCode: 1,
          signal: null,
        });
        return;
      }
      const mappedExit =
        finalExit.exitCode ?? signalExitCode(finalExit.signal as NodeJS.Signals | null);
      socket.destroy();
      process.exitCode = mappedExit;
      resolvePromise({
        decision:
          denialReason === undefined
            ? { outcome: 'allow', reason: 'policy-allowed' }
            : { outcome: 'deny', reason: denialReason },
        exitCode: mappedExit,
        signal: finalExit.signal,
      });
    };

    socket.on('data', (chunk: Buffer) => {
      for (const line of decoder.push(chunk)) {
        let parsedFrame: unknown;
        try {
          parsedFrame = JSON.parse(line) as unknown;
        } catch {
          continue;
        }
        const frame = agentBrokerServerFrameSchema.safeParse(parsedFrame);
        if (!frame.success) continue;
        switch (frame.data.event) {
          case 'decision': {
            if (frame.data.outcome === 'deny') {
              denialReason = frame.data.reason;
              process.stderr.write(`kavrix agent: denied (${frame.data.reason})\n`);
            }
            break;
          }
          case 'stdout':
            process.stdout.write(Buffer.from(frame.data.data, 'base64'));
            break;
          case 'stderr':
            process.stderr.write(Buffer.from(frame.data.data, 'base64'));
            break;
          case 'exit':
            finalExit = { exitCode: frame.data.exitCode, signal: frame.data.signal };
            finishSuccess();
            break;
        }
      }
    });
    socket.on('error', () => {
      if (!settled) {
        settled = true;
        rejectPromise(
          new CodedCliError('USAGE_ERROR', 'The Kavrix agent broker failed.'),
        );
      }
    });
    socket.on('close', () => {
      if (!settled) {
        settled = true;
        rejectPromise(
          new CodedCliError(
            'USAGE_ERROR',
            'The Kavrix agent broker closed unexpectedly.',
          ),
        );
      }
    });

    socket.write(`${JSON.stringify(request)}\n`);
    process.stdin.on('data', (chunk: Buffer | string) => {
      const bytes = typeof chunk === 'string' ? Buffer.from(chunk, 'utf8') : chunk;
      sendClientFrame(socket, { v: 1, event: 'stdin', data: bytes.toString('base64') });
    });
    process.stdin.on('end', () => {
      sendClientFrame(socket, { v: 1, event: 'close-stdin' });
    });
    process.stdin.resume();
  });
}

// ---- shared spawn environment ---------------------------------------------

const INHERITED_ENVIRONMENT = [
  'PATH',
  'PATHEXT',
  'SystemRoot',
  'WINDIR',
  'COMSPEC',
  'TEMP',
  'TMP',
  'HOME',
  'USERPROFILE',
] as const;

function validatedPermission(value: string): string {
  if (!/^[A-Za-z0-9][A-Za-z0-9._~-]*$/u.test(value)) {
    throw invalidConfiguration('Permission names must be opaque identifiers.');
  }
  return value;
}

async function openAgentState(
  keyFile: string,
  authzKey: Uint8Array,
  scopeId: string,
): Promise<AuthorizationState> {
  try {
    return await AuthorizationState.open(keyFile, authzKey, {
      scopeKind: 'database',
      scopeId,
    });
  } catch (error) {
    authzKey.fill(0);
    throw error;
  }
}

function installSignalForwarding(childRef: {
  current: ChildProcess | null;
}): ReadonlyMap<NodeJS.Signals, () => void> {
  const handlers = new Map<NodeJS.Signals, () => void>();
  for (const signalName of forwardableSignals(process.platform)) {
    const handler = (): void => {
      childRef.current?.kill(signalName);
    };
    handlers.set(signalName, handler);
    process.on(signalName, handler);
  }
  return handlers;
}

// ---- broker ----------------------------------------------------------------

interface BrokerSession {
  token: string;
  permissions: Readonly<Record<string, PermissionEntry>>;
  secrets: Map<string, string>;
  state: AuthorizationState;
  platform: NodeJS.Platform;
  counters: { allowed: number; denied: number };
  queue: Promise<void>;
}

interface ConnectionContext {
  readonly session: BrokerSession;
  requestSeen: boolean;
  stdinSink: ((frame: AgentBrokerClientFrame) => void) | undefined;
  /** Frames that arrive before the authorized child owns its stdin. */
  readonly pendingClientFrames: AgentBrokerClientFrame[];
}

interface BrokerListener {
  endpoint: string;
  cleanup: () => Promise<void>;
}

function startBroker(session: BrokerSession): Promise<BrokerListener> {
  const isWindows = session.platform === 'win32';
  const endpoint = isWindows
    ? `\\\\.\\pipe\\kavrix-agent-${randomUUID()}`
    : join(tmpdir(), `kavrix-agent-${randomUUID()}.sock`);
  return new Promise<BrokerListener>((resolveListener, rejectListener) => {
    const server: Server = createServer((socket) => {
      void handleConnection(socket, session).catch(() => socket.destroy());
    });
    server.on('error', (error) => {
      rejectListener(new CodedCliError('DATASTORE_FAILURE', describeError(error)));
    });
    server.listen(endpoint, () => {
      const ready = isWindows
        ? Promise.resolve()
        : chmod(endpoint, 0o600).catch((error: unknown) => {
            throw new CodedCliError('DATASTORE_FAILURE', describeError(error));
          });
      void ready.then(() => {
        resolveListener({
          endpoint,
          cleanup: async () => {
            await new Promise<void>((resolveClose) => {
              server.close(() => {
                resolveClose();
              });
            });
            if (!isWindows) await unlink(endpoint).catch(() => undefined);
          },
        });
      }, rejectListener);
    });
  });
}

async function handleConnection(socket: Socket, session: BrokerSession): Promise<void> {
  const context: ConnectionContext = {
    session,
    requestSeen: false,
    stdinSink: undefined,
    pendingClientFrames: [],
  };
  const decoder = new NdjsonDecoder();
  await new Promise<void>((resolveConnection) => {
    socket.setNoDelay(true);
    socket.on('data', (chunk: Buffer) => {
      for (const line of decoder.push(chunk)) {
        if (!context.requestSeen) {
          context.requestSeen = true;
          void dispatchRequest(line, socket, context)
            .catch(() => socket.destroy())
            .finally(() => {
              resolveConnection();
            });
          continue;
        }
        handleRelayLine(line, context);
      }
    });
    socket.on('error', () => {
      resolveConnection();
    });
    socket.on('close', () => {
      context.stdinSink = undefined;
      resolveConnection();
    });
  });
}

function handleRelayLine(line: string, context: ConnectionContext): void {
  let parsedFrame: unknown;
  try {
    parsedFrame = JSON.parse(line) as unknown;
  } catch {
    return;
  }
  const frame = agentBrokerClientFrameSchema.safeParse(parsedFrame);
  if (!frame.success) return;
  if (context.stdinSink === undefined) {
    // The child is still starting; retain the frame so an early end-of-input
    // is never lost.
    context.pendingClientFrames.push(frame.data);
    return;
  }
  context.stdinSink(frame.data);
}

async function dispatchRequest(
  line: string,
  socket: Socket,
  context: ConnectionContext,
): Promise<void> {
  const { session } = context;
  let parsedRequest: unknown;
  try {
    parsedRequest = JSON.parse(line) as unknown;
  } catch {
    socket.destroy();
    return;
  }
  const parsed = agentBrokerRequestSchema.safeParse(parsedRequest);
  if (!parsed.success || !tokensMatch(parsed.data.token, session.token)) {
    socket.destroy();
    return;
  }
  // Serialize authorized executions so stdio frames never interleave.
  const previous = session.queue;
  const current = previous.then(
    () => handleAuthorizedExec(socket, context, parsed.data),
    () => handleAuthorizedExec(socket, context, parsed.data),
  );
  session.queue = current.catch(() => undefined);
  await current;
}

async function handleAuthorizedExec(
  socket: Socket,
  context: ConnectionContext,
  request: AgentBrokerRequest,
): Promise<void> {
  const { session } = context;
  const deny = async (reason: AuthorizationReason): Promise<void> => {
    session.counters.denied += 1;
    sendServerFrame(socket, { v: 1, event: 'decision', outcome: 'deny', reason });
    // Every request terminates with exactly one exit frame so clients can
    // distinguish a denial from a broken connection.
    sendServerFrame(socket, { v: 1, event: 'exit', exitCode: 1, signal: null });
    await auditBestEffort(session.state, {
      actor: 'agent',
      action: 'authorization-denied',
      permissionKey: request.permission,
      ...(request.argv.length > 0
        ? { command: safeCommandName(request.argv[0] ?? '') }
        : {}),
      ...(auditReasonOrUndefined(reason) === undefined
        ? {}
        : { reason: auditReasonOrUndefined(reason) }),
    });
  };

  const entry = session.permissions[request.permission];
  if (entry === undefined) {
    await deny('policy-denied');
    return;
  }

  const resolution = await resolveExecutable(request.argv[0] ?? '');
  if (resolution.status === 'unresolved') {
    await deny('executable-unresolved');
    return;
  }
  if (resolution.status === 'refused') {
    await deny('executable-refused');
    return;
  }

  const evaluationContext: EvaluationContext = {
    platform: session.platform,
    facts: {
      displayName: resolution.displayName,
      sha256: resolution.sha256,
      firstArgument: request.argv[1],
    },
    nowIso: nowIso(),
    cwdRealPath: canonicalizeDirectory(process.cwd()),
  };

  const decision = evaluatePermission(entry, evaluationContext);
  if (decision.outcome === 'deny') {
    await deny(decision.reason);
    return;
  }
  if (decision.outcome === 'confirm') {
    const approval = await requestApproval({
      actor: 'agent',
      ...(entry.secret === undefined ? {} : { secret: entry.secret }),
      executable: resolution.displayName,
      argumentsPreview: boundedPreview(request.argv.slice(1)),
    });
    await auditBestEffort(session.state, {
      actor: 'agent',
      action:
        approval === 'granted'
          ? 'confirmation-granted'
          : approval === 'declined'
            ? 'confirmation-declined'
            : 'confirmation-requested',
      permissionKey: request.permission,
      command: resolution.displayName,
    });
    if (approval !== 'granted') {
      await deny(
        approval === 'declined' ? 'confirmation-declined' : 'confirmation-unavailable',
      );
      return;
    }
  }

  if (entry.env === undefined || entry.secret === undefined) {
    await deny('no-injection-mapping');
    return;
  }
  const value = session.secrets.get(entry.secret);
  if (value === undefined) {
    await deny('no-injection-mapping');
    return;
  }

  const window = executionWindowMs(entry);
  if (window === 'invalid') {
    await deny('invalid-request');
    return;
  }

  sendServerFrame(socket, {
    v: 1,
    event: 'decision',
    outcome: 'allow',
    reason: decision.reason,
  });
  session.counters.allowed += 1;
  await auditBestEffort(session.state, {
    actor: 'agent',
    action: 'authorization-allowed',
    permissionKey: request.permission,
    secret: entry.secret,
    command: resolution.displayName,
    ...(request.argv.length > 1
      ? { argvPreview: boundedPreview(request.argv.slice(1)) }
      : {}),
  });

  let result;
  try {
    result = await runSecureCommand({
      executable: resolution.absolutePath,
      arguments: request.argv.slice(1),
      cwd: process.cwd(),
      environment: [
        [entry.env, { kind: 'secret', value: secretValueSchema.parse(value) }],
      ] satisfies readonly EnvironmentMapping[],
      inheritEnvironment: INHERITED_ENVIRONMENT,
      input: 'pipe',
      output: { mode: 'pipe' },
      onSpawn(child) {
        wireChildRelay(socket, context, child);
      },
      ...(window === undefined ? {} : { timeoutMs: window }),
    });
  } catch {
    await deny('invalid-request');
    return;
  }

  sendServerFrame(socket, {
    v: 1,
    event: 'exit',
    exitCode: result.exitCode,
    signal: result.signal ?? null,
  });
  await auditBestEffort(session.state, {
    actor: 'agent',
    action: 'execution-completed',
    permissionKey: request.permission,
    command: resolution.displayName,
    ...(result.exitCode === null ? {} : { exitCode: result.exitCode }),
  });
}

function wireChildRelay(
  socket: Socket,
  context: ConnectionContext,
  child: ChildProcess,
): void {
  const pump = async (
    readable: NodeJS.ReadableStream | null,
    event: 'stdout' | 'stderr',
  ): Promise<void> => {
    if (readable === null) return;
    for await (const chunk of readable) {
      streamOutput(socket, event, chunk as Buffer);
    }
  };
  void pump(child.stdout, 'stdout')
    .then(() => pump(child.stderr, 'stderr'))
    .catch(() => undefined);
  const sink = (frame: AgentBrokerClientFrame): void => {
    if (child.stdin === null || child.stdin.writableEnded) {
      return;
    }
    if (frame.event === 'stdin') {
      child.stdin.write(Buffer.from(frame.data, 'base64'));
      return;
    }
    child.stdin.end();
  };
  for (const pending of context.pendingClientFrames) {
    sink(pending);
  }
  context.pendingClientFrames.length = 0;
  context.stdinSink = sink;
  child.once('close', () => {
    context.stdinSink = undefined;
  });
}

function sendServerFrame(socket: Socket, frame: AgentBrokerServerFrame): void {
  if (socket.destroyed || socket.writableEnded) return;
  socket.write(`${JSON.stringify(frame)}\n`);
}

function sendClientFrame(socket: Socket, frame: AgentBrokerClientFrame): void {
  if (socket.destroyed || socket.writableEnded) return;
  socket.write(`${JSON.stringify(frame)}\n`);
}

function streamOutput(socket: Socket, event: 'stdout' | 'stderr', chunk: Buffer): void {
  streamOutputFrames(socket, event, chunk, sendServerFrame);
}

const authorizationReasonValues: readonly string[] = authorizationReasonSchema.options;

function auditReasonOrUndefined(reason: string): AuthorizationReason | undefined {
  return authorizationReasonValues.includes(reason)
    ? (reason as AuthorizationReason)
    : undefined;
}

function waitForConnect(socket: Socket): Promise<void> {
  return new Promise((resolvePromise, rejectPromise) => {
    const timer = setTimeout(() => {
      socket.destroy();
      rejectPromise(invalidConfiguration('The Kavrix agent broker is not responding.'));
    }, CONNECT_TIMEOUT_MS);
    socket.once('connect', () => {
      clearTimeout(timer);
      resolvePromise();
    });
    socket.once('error', (error: Error) => {
      clearTimeout(timer);
      rejectPromise(
        invalidConfiguration('No Kavrix agent session is listening for this endpoint.'),
      );
      void error;
    });
  });
}

async function auditBestEffort(
  state: AuthorizationState,
  event: Parameters<AuthorizationState['recordEvent']>[0],
): Promise<void> {
  await state.recordEvent(event);
}

function describeError(error: unknown): string {
  return error instanceof Error ? error.message : String(error);
}
