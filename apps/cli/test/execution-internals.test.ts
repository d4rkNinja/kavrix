import { randomUUID } from 'node:crypto';
import { access as accessPath, mkdtemp, rm, writeFile } from 'node:fs/promises';
import { connect as netConnect } from 'node:net';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { PassThrough, Readable } from 'node:stream';

import { Command } from 'commander';
import { deriveAuthorizationStateKey } from '@kavrix/crypto';
import {
  databaseIdSchema,
  permissionEntrySchema,
  type AgentBrokerClientFrame,
  type AgentBrokerRequest,
  type AgentBrokerServerFrame,
} from '@kavrix/schemas';
import { createSecureTestDirectory } from '../../../packages/key-files/test/secure-temporary-directory.js';
import { afterAll, afterEach, describe, expect, it, vi } from 'vitest';

import {
  AGENT_BROKER_ENV,
  AGENT_TOKEN_ENV,
  executeAgentExec,
  startAgentBrokerForTest,
} from '../src/execution/agent-command.js';
import { MAX_FRAME_BYTES } from '../src/execution/broker-protocol.js';
import * as databaseFlatCommands from '../src/database-flat-commands.js';
import {
  AuthorizationState,
  parsePolicyId,
} from '../src/execution/authorization-state.js';
import { withAuthorizationSnapshot } from '../src/execution/authorization-session.js';
import {
  addExecutionRoutingOptions,
  executionFlatOptions,
  extractMergedOptions,
} from '../src/execution/cli-options.js';
import { buildLocalCli, runLocalCli } from '../src/local-vault-cli.js';

const directories: string[] = [];

afterEach(() => {
  vi.restoreAllMocks();
});

interface RawBrokerClient {
  readonly frames: AgentBrokerServerFrame[];
  readonly done: Promise<readonly AgentBrokerServerFrame[]>;
  readonly waitForFrame: (
    predicate: (frame: AgentBrokerServerFrame) => boolean,
  ) => Promise<AgentBrokerServerFrame>;
  readonly sendFrames: (frames: readonly AgentBrokerClientFrame[]) => void;
  readonly sendRaw: (value: string | Buffer) => void;
}

async function openRawBrokerRequest(
  endpoint: string,
  request: AgentBrokerRequest,
  onFrame: (frame: AgentBrokerServerFrame) => void = () => undefined,
): Promise<RawBrokerClient> {
  const socket = netConnect(endpoint);
  await new Promise<void>((resolveConnect, rejectConnect) => {
    socket.once('connect', resolveConnect);
    socket.once('error', rejectConnect);
  });

  const frames: AgentBrokerServerFrame[] = [];
  const waiters: Array<{
    readonly predicate: (frame: AgentBrokerServerFrame) => boolean;
    readonly resolve: (frame: AgentBrokerServerFrame) => void;
  }> = [];
  let buffer = '';
  let resolveDone = (_frames: readonly AgentBrokerServerFrame[]): void => undefined;
  let settled = false;
  const done = new Promise<readonly AgentBrokerServerFrame[]>((resolvePromise) => {
    resolveDone = resolvePromise;
  });
  const finish = (): void => {
    if (settled) return;
    settled = true;
    resolveDone(frames);
  };

  socket.on('data', (chunk: Buffer) => {
    buffer += chunk.toString('utf8');
    let newline = buffer.indexOf('\n');
    while (newline >= 0) {
      const frame = JSON.parse(buffer.slice(0, newline)) as AgentBrokerServerFrame;
      buffer = buffer.slice(newline + 1);
      frames.push(frame);
      onFrame(frame);
      for (let index = waiters.length - 1; index >= 0; index -= 1) {
        const waiter = waiters[index];
        if (waiter !== undefined && waiter.predicate(frame)) {
          waiters.splice(index, 1);
          waiter.resolve(frame);
        }
      }
      if (frame.event === 'exit') {
        socket.end();
        finish();
      }
      newline = buffer.indexOf('\n');
    }
  });
  socket.on('close', finish);
  socket.on('error', finish);
  socket.write(`${JSON.stringify(request)}\n`);

  return {
    frames,
    done,
    waitForFrame(predicate) {
      const existing = frames.find(predicate);
      if (existing !== undefined) return Promise.resolve(existing);
      return new Promise<AgentBrokerServerFrame>((resolveFrame) => {
        waiters.push({ predicate, resolve: resolveFrame });
      });
    },
    sendFrames(clientFrames) {
      for (const frame of clientFrames) {
        socket.write(`${JSON.stringify(frame)}\n`);
      }
    },
    sendRaw(value) {
      socket.write(value);
    },
  };
}

function execBrokerRequest(token: string, script: string): AgentBrokerRequest {
  return {
    v: 1,
    token,
    op: 'exec',
    permission: 'gh',
    argv: [process.execPath, '-e', script],
  };
}

function decodedStderr(frames: readonly AgentBrokerServerFrame[]): string {
  return frames
    .filter(
      (frame): frame is Extract<AgentBrokerServerFrame, { event: 'stderr' }> =>
        frame.event === 'stderr',
    )
    .map((frame) => Buffer.from(frame.data, 'base64').toString('utf8'))
    .join('');
}

afterAll(async () => {
  vi.unstubAllEnvs();
  await Promise.all(
    directories.map((directory) => rm(directory, { force: true, recursive: true })),
  );
});

describe('cli option extraction', () => {
  it('defaults and overrides every routing field', () => {
    const everything = executionFlatOptions({
      profile: 'p',
      profileConfigDir: 'd',
      vault: 'vault_v',
      datastore: 'file',
      dataFile: 'f',
      database: 'db',
      collection: 'c',
      keyFile: 'k',
      databaseUrlStdin: true,
      passphraseStdin: true,
    });
    expect(everything).toEqual({
      profile: 'p',
      profileConfigDir: 'd',
      vault: 'vault_v',
      datastore: 'file',
      dataFile: 'f',
      database: 'db',
      collection: 'c',
      keyFile: 'k',
      databaseUrlStdin: true,
      passphraseStdin: true,
      allowInsecureTransport: false,
    });
    const nothing = executionFlatOptions({});
    expect(nothing.vault).toBe('default');
    expect(nothing.profile).toBeUndefined();
    expect(nothing.profileConfigDir).toBeUndefined();
    expect(nothing.datastore).toBeUndefined();
    expect(nothing.dataFile).toBeUndefined();
    expect(nothing.database).toBeUndefined();
    expect(nothing.collection).toBeUndefined();
    expect(nothing.keyFile).toBeUndefined();
    expect(nothing.databaseUrlStdin).toBe(false);
    expect(nothing.passphraseStdin).toBe(false);
  });

  it('preserves omitted-versus-explicit vault source evidence across hierarchy', () => {
    const parseRun = (args: readonly string[]): Command => {
      const program = new Command().exitOverride();
      addExecutionRoutingOptions(program);
      const run = program.command('run');
      program.parse(['node', 'kavrix', ...args]);
      return run;
    };

    const omitted = executionFlatOptions(extractMergedOptions(parseRun(['run'])));
    expect(omitted.vault).toBe('default');
    expect(omitted.vaultWasDefaulted).toBe(true);

    const explicit = executionFlatOptions(
      extractMergedOptions(parseRun(['--vault', 'vault_explicit', 'run'])),
    );
    expect(explicit.vault).toBe('vault_explicit');
    expect(explicit.vaultWasDefaulted).toBeUndefined();
  });
});

async function runHelpContractCli(
  args: readonly string[],
  options: Readonly<{ rejectStdinRead?: boolean }> = {},
): Promise<
  Readonly<{ exitCode: number; stdout: string; stderr: string; reads: number }>
> {
  const stdout: string[] = [];
  const stderr: string[] = [];
  let reads = 0;
  const originalExitCode = process.exitCode;
  const originalStdin = process.stdin;
  const guardedStdin = new Readable({
    read() {
      reads += 1;
      this.destroy(new Error('Malformed policy syntax must not read stdin.'));
    },
  });
  const writeOut = vi.spyOn(process.stdout, 'write').mockImplementation((chunk) => {
    stdout.push(String(chunk));
    return true;
  });
  const writeErr = vi.spyOn(process.stderr, 'write').mockImplementation((chunk) => {
    stderr.push(String(chunk));
    return true;
  });
  if (options.rejectStdinRead === true) {
    Object.defineProperty(process, 'stdin', {
      configurable: true,
      value: guardedStdin,
    });
  }
  try {
    process.exitCode = undefined;
    await runLocalCli(['node', 'kavrix', ...args]);
    return {
      exitCode: process.exitCode ?? 0,
      stdout: stdout.join(''),
      stderr: stderr.join(''),
      reads,
    };
  } finally {
    writeOut.mockRestore();
    writeErr.mockRestore();
    process.exitCode = originalExitCode;
    if (options.rejectStdinRead === true) {
      Object.defineProperty(process, 'stdin', {
        configurable: true,
        value: originalStdin,
      });
    }
  }
}

describe('execution command help contracts', () => {
  it('shows every effective grant creation option from the parent command', async () => {
    const program = buildLocalCli();
    const grant = program.commands.find((command) => command.name() === 'grant');
    expect(grant).toBeDefined();
    const effectiveFlags = grant?.options
      .map((option) => option.long)
      .filter((flag): flag is string => flag !== undefined);

    const result = await runHelpContractCli(['grant', 'create', '--help']);

    expect(result.exitCode).toBe(0);
    expect(result.stderr).toBe('');
    expect(result.stdout).toContain(
      'Place these options before or after `create <secret>`.',
    );
    for (const flag of effectiveFlags ?? []) {
      expect(result.stdout).toContain(flag);
    }
  });

  it.each(['check', 'explain'] as const)(
    'documents policy %s executable pass-through syntax',
    async (command) => {
      const result = await runHelpContractCli(['policy', command, '--help']);

      expect(result.exitCode).toBe(0);
      expect(result.stderr).toBe('');
      expect(result.stdout).toContain(
        `Usage: kavrix policy ${command} [options] <id> -- <executable> [args...]`,
      );
    },
  );

  it.each(['check', 'explain'] as const)(
    'accepts the documented policy %s separator before entering the action',
    async (commandName) => {
      const program = buildLocalCli();
      const policy = program.commands.find((command) => command.name() === 'policy');
      const command = policy?.commands.find(
        (candidate) => candidate.name() === commandName,
      );
      expect(command).toBeDefined();
      const reachedActionBoundary = new Error('reached action boundary');
      command?.hook('preAction', () => {
        throw reachedActionBoundary;
      });

      await expect(
        program.parseAsync([
          'node',
          'kavrix',
          'policy',
          commandName,
          'deploy',
          '--',
          'terraform',
          'plan',
        ]),
      ).rejects.toBe(reachedActionBoundary);
    },
  );

  it.each([
    ['check', ['terraform', 'plan']],
    ['check', ['--']],
    ['check', ['terraform', '--', 'plan']],
    ['explain', ['terraform', 'plan']],
    ['explain', ['--']],
    ['explain', ['terraform', '--', 'plan']],
  ] as const)(
    'rejects malformed policy %s pass-through before reading secrets',
    async (command, trailing) => {
      const result = await runHelpContractCli(
        ['policy', command, 'deploy', '--passphrase-stdin', ...trailing],
        { rejectStdinRead: true },
      );

      expect(result.exitCode).toBe(2);
      expect(result.stdout).toBe('');
      expect(result.stderr).toContain('error:');
      expect(result.stderr.match(/^error:/gmu)).toHaveLength(1);
      expect(result.stderr).toContain(
        `Usage: kavrix policy ${command} [options] <id> -- <executable> [args...]`,
      );
      expect(result.stderr).not.toContain('Kavrix command failed.');
      expect(result.reads).toBe(0);
    },
  );
});

describe('authorization state wrappers', () => {
  it('creates, replaces, removes, and audits through the sealed store', async () => {
    const directory = await createSecureTestDirectory(
      join(tmpdir(), `kavrix-authz-wrap-`),
    );
    directories.push(directory);
    const keyFile = join(directory, 'owner.key');
    const rootKey = new Uint8Array(32).fill(7);
    const scope = { scopeKind: 'database' as const, scopeId: 'db_wraptest' };
    const state = await AuthorizationState.open(
      keyFile,
      deriveAuthorizationStateKey(rootKey, scope),
      scope,
    );
    try {
      expect(() => parsePolicyId('not an id')).toThrowError(/invalid/u);

      const entry = permissionEntrySchema.parse({
        secret: 'a/b',
        commands: ['node'],
      });
      const first = await state.putPolicy('wrap-policy', entry);
      const replaced = await state.putPolicy('wrap-policy', entry);
      expect(replaced.createdAt >= first.createdAt).toBe(true);
      await state.removePolicy('wrap-policy');
      await expect(state.removePolicy('wrap-policy')).rejects.toMatchObject({
        errorCode: 'GRANT_INVALID',
      });

      const seq = await state.recordEvent({ actor: 'user', action: 'unlock' });
      const next = await state.recordEvent({ actor: 'user', action: 'unlock' });
      expect(next).toBe(seq + 1);
      const snapshot = await state.read();
      expect(snapshot.audit.at(-1)?.action).toBe('unlock');
      expect(snapshot.policies['wrap-policy']).toBeUndefined();
    } finally {
      state.close();
    }
  }, 30_000);

  it('maps a vanished sealed sidecar to the stable datastore-failure code', async () => {
    const directory = await createSecureTestDirectory(
      join(tmpdir(), 'kavrix-authz-vanish-'),
    );
    directories.push(directory);
    const keyFile = join(directory, 'owner.key');
    const rootKey = new Uint8Array(32).fill(13);
    const scope = { scopeKind: 'database' as const, scopeId: 'db_vanish' };
    const state = await AuthorizationState.open(
      keyFile,
      deriveAuthorizationStateKey(rootKey, scope),
      scope,
    );
    try {
      const { rm } = await import('node:fs/promises');
      await rm(`${keyFile}.authorization`, { force: true });
      await expect(state.mutate(() => undefined)).rejects.toMatchObject({
        errorCode: 'DATASTORE_FAILURE',
      });
    } finally {
      state.close();
    }
  }, 30_000);
});

describe('authorization snapshot wrapper', () => {
  it('zeroizes the derived key before the callback and does not create a sidecar', async () => {
    const directory = await mkdtemp(join(tmpdir(), 'kavrix-authz-snapshot-lifetime-'));
    directories.push(directory);
    const keyFile = join(directory, 'owner.key');
    const authorizationStateKey = new Uint8Array(32).fill(0xa5);

    vi.spyOn(databaseFlatCommands, 'usesDatabaseContainer').mockResolvedValue(true);
    vi.spyOn(databaseFlatCommands, 'readDatabaseFlatSecrets').mockResolvedValue({
      passphrase: 'unused',
      extras: [],
    });
    vi.spyOn(
      databaseFlatCommands,
      'openDatabaseAuthorizationStateAccess',
    ).mockResolvedValue({
      databaseId: databaseIdSchema.parse('db_snapshot_lifetime'),
      keyFile,
      authorizationStateKey,
    });

    const result = await withAuthorizationSnapshot(
      { profileConfigDir: directory, vault: 'vault_snapshot' },
      (snapshot) => {
        expect(snapshot).toEqual({ policies: {}, grants: {}, audit: [] });
        expect(authorizationStateKey).toEqual(new Uint8Array(32));
        return 'snapshot-result';
      },
    );

    expect(result).toBe('snapshot-result');
    await expect(accessPath(`${keyFile}.authorization`)).rejects.toMatchObject({
      code: 'ENOENT',
    });
  });

  it('zeroizes the derived key when reading a malformed sidecar fails', async () => {
    const directory = await mkdtemp(join(tmpdir(), 'kavrix-authz-snapshot-failure-'));
    directories.push(directory);
    const keyFile = join(directory, 'owner.key');
    const authorizationStateKey = new Uint8Array(32).fill(0x5a);
    await writeFile(`${keyFile}.authorization`, 'malformed authorization state');

    vi.spyOn(databaseFlatCommands, 'usesDatabaseContainer').mockResolvedValue(true);
    vi.spyOn(databaseFlatCommands, 'readDatabaseFlatSecrets').mockResolvedValue({
      passphrase: 'unused',
      extras: [],
    });
    vi.spyOn(
      databaseFlatCommands,
      'openDatabaseAuthorizationStateAccess',
    ).mockResolvedValue({
      databaseId: databaseIdSchema.parse('db_snapshot_failure'),
      keyFile,
      authorizationStateKey,
    });

    await expect(
      withAuthorizationSnapshot(
        { profileConfigDir: directory, vault: 'vault_snapshot' },
        () => 'unreachable',
      ),
    ).rejects.toThrow();
    expect(authorizationStateKey).toEqual(new Uint8Array(32));
  });
});

describe('agent exec client guards', () => {
  it('fails closed when no broker environment is present', async () => {
    process.env[AGENT_BROKER_ENV] = '';
    process.env[AGENT_TOKEN_ENV] = '';
    await expect(
      executeAgentExec({ permission: 'gh', executableAndArgs: ['node'] }),
    ).rejects.toMatchObject({ errorCode: 'INVALID_CONFIGURATION' });
    delete process.env[AGENT_BROKER_ENV];
    delete process.env[AGENT_TOKEN_ENV];
  }, 15_000);

  it('rejects malformed permissions and empty commands before connecting', async () => {
    process.env[AGENT_BROKER_ENV] = 'endpoint-placeholder';
    process.env[AGENT_TOKEN_ENV] = 't'.repeat(43);
    await expect(
      executeAgentExec({
        permission: 'bad permission!',
        executableAndArgs: ['node'],
      }),
    ).rejects.toMatchObject({ errorCode: 'INVALID_CONFIGURATION' });
    await expect(
      executeAgentExec({ permission: 'gh', executableAndArgs: [] }),
    ).rejects.toMatchObject({ errorCode: 'INVALID_CONFIGURATION' });
    delete process.env[AGENT_BROKER_ENV];
    delete process.env[AGENT_TOKEN_ENV];
  }, 15_000);
});

describe('in-process broker and client round trip', () => {
  it('authorizes, streams, denies, and rejects tokens through the real client', async () => {
    const directory = await createSecureTestDirectory(
      join(tmpdir(), 'kavrix-broker-rt-'),
    );
    directories.push(directory);
    const rootKey = new Uint8Array(32).fill(9);
    const scope = { scopeKind: 'database' as const, scopeId: 'db_broker_rt' };
    const state = await AuthorizationState.open(
      join(directory, 'owner.key'),
      deriveAuthorizationStateKey(rootKey, scope),
      scope,
    );
    const token = randomUUID().replaceAll('-', '') + randomUUID().replaceAll('-', '');
    const secretValue = 'round-trip-canary';
    const session = {
      token,
      permissions: {
        gh: permissionEntrySchema.parse({
          secret: 'x/y',
          commands: ['node'],
          env: 'ROUND_TRIP_TOKEN',
        }),
        'prod-db': permissionEntrySchema.parse({ deny: true }),
      } as Record<string, ReturnType<typeof permissionEntrySchema.parse>>,
      secrets: new Map([['x/y', secretValue]]),
      state,
      platform: process.platform,
      counters: { allowed: 0, denied: 0 },
      queue: Promise.resolve(),
    };
    const broker = await startAgentBrokerForTest(session);
    process.env[AGENT_BROKER_ENV] = broker.endpoint;
    process.env[AGENT_TOKEN_ENV] = token;

    const stdoutChunks: string[] = [];
    const stderrChunks: string[] = [];
    const stdoutWrite = vi
      .spyOn(process.stdout, 'write')
      .mockImplementation((chunk) => {
        stdoutChunks.push(String(chunk));
        return true;
      });
    const stderrWrite = vi
      .spyOn(process.stderr, 'write')
      .mockImplementation((chunk) => {
        stderrChunks.push(String(chunk));
        return true;
      });

    try {
      // Authorized round trip through the full client path.
      await executeAgentExec({
        permission: 'gh',
        executableAndArgs: [
          process.execPath,
          '-e',
          'console.log("RT:" + (process.env.ROUND_TRIP_TOKEN ?? "")); process.exit(0)',
        ],
      });
      expect(process.exitCode).toBe(0);
      const combined = stdoutChunks.join('');
      expect(combined).toContain(`RT:${secretValue}`);
      expect(combined).not.toContain(secretValue.repeat(2));

      // Denied by a deny entry: decision frame, stderr note, exit code 1.
      // Arguments ride along into the audit argvPreview.
      await executeAgentExec({
        permission: 'prod-db',
        executableAndArgs: [process.execPath, '-e', 'process.exit(0)', '--flag'],
      });
      expect(process.exitCode).toBe(1);
      expect(stderrChunks.join('')).toContain('denied (policy-denied)');

      // Confirmation granted through an interactive terminal stub.
      session.permissions['confirm-gate'] = permissionEntrySchema.parse({
        secret: 'x/y',
        commands: ['node'],
        env: 'ROUND_TRIP_TOKEN',
        requireConfirmation: true,
      });
      const originalStdin = process.stdin;
      const approvalStream = new PassThrough();
      Object.defineProperty(process, 'stdin', {
        configurable: true,
        value: Object.assign(approvalStream, { isTTY: true }),
      });
      approvalStream.on('data', (d) =>
        console.error('STREAM', 'data', JSON.stringify(String(d))),
      );
      setTimeout(() => {
        console.error('STREAM', 'writing');
        approvalStream.write('y\n');
      }, 4000);
      const originalStderrIsTty = process.stderr.isTTY;
      Object.defineProperty(process.stderr, 'isTTY', {
        configurable: true,
        value: true,
      });
      try {
        await executeAgentExec({
          permission: 'confirm-gate',
          executableAndArgs: [process.execPath, '-e', 'process.exit(0)'],
        });
      } finally {
        Object.defineProperty(process.stderr, 'isTTY', {
          configurable: true,
          value: originalStderrIsTty,
        });
        Object.defineProperty(process, 'stdin', {
          configurable: true,
          value: originalStdin,
        });
      }
      expect(process.exitCode).toBe(0);
    } finally {
      stdoutWrite.mockRestore();
      stderrWrite.mockRestore();
      delete process.env[AGENT_BROKER_ENV];
      delete process.env[AGENT_TOKEN_ENV];
      session.secrets = new Map();
      await broker.cleanup().catch(() => undefined);
      process.exitCode = undefined;
    }

    // The first broker is gone after cleanup; the raw wrong-token probe
    // starts its own broker instance against the same sealed state.
    const secondSession = {
      token,
      permissions: session.permissions,
      secrets: new Map([['x/y', secretValue]]),
      state,
      platform: process.platform,
      counters: { allowed: 0, denied: 0 },
      queue: Promise.resolve(),
    };
    const secondBroker = await startAgentBrokerForTest(secondSession);
    try {
      const raw = netConnect(secondBroker.endpoint);
      await new Promise<void>((resolveConnect) => {
        raw.once('connect', () => resolveConnect());
        raw.once('error', () => resolveConnect());
      });
      const frames = await new Promise<string[]>((resolveFrames) => {
        let buffer = '';
        const collected: string[] = [];
        raw.on('data', (chunk: Buffer) => {
          buffer += chunk.toString('utf8');
          let index = buffer.indexOf('\n');
          while (index >= 0) {
            collected.push(buffer.slice(0, index));
            buffer = buffer.slice(index + 1);
            index = buffer.indexOf('\n');
          }
        });
        raw.on('close', () => resolveFrames(collected));
        raw.write(
          `${JSON.stringify({
            v: 1,
            token: 'wrong-token-value',
            op: 'exec',
            permission: 'gh',
            argv: ['node'],
          })}\n`,
        );
      });
      expect(frames).toEqual([]);
    } finally {
      await secondBroker.cleanup();
    }
    state.close();
  }, 60_000);

  it('serializes concurrent authorized broker requests without interleaving', async () => {
    const directory = await createSecureTestDirectory(
      join(tmpdir(), 'kavrix-broker-serialize-'),
    );
    directories.push(directory);
    const scope = { scopeKind: 'database' as const, scopeId: 'db_broker_serialize' };
    const state = await AuthorizationState.open(
      join(directory, 'owner.key'),
      deriveAuthorizationStateKey(new Uint8Array(32).fill(17), scope),
      scope,
    );
    const token = randomUUID().replaceAll('-', '') + randomUUID().replaceAll('-', '');
    const session = {
      token,
      permissions: {
        gh: permissionEntrySchema.parse({
          secret: 'x/y',
          commands: ['node'],
          env: 'SERIALIZE_TOKEN',
        }),
      },
      secrets: new Map([['x/y', 'serialize-canary']]),
      state,
      platform: process.platform,
      counters: { allowed: 0, denied: 0 },
      queue: Promise.resolve(),
    };
    const broker = await startAgentBrokerForTest(session);
    const order: string[] = [];
    try {
      const first = await openRawBrokerRequest(
        broker.endpoint,
        execBrokerRequest(token, 'setTimeout(() => process.exit(0), 200)'),
        (frame) => order.push(`first:${frame.event}`),
      );
      await first.waitForFrame(
        (frame) => frame.event === 'decision' && frame.outcome === 'allow',
      );
      const second = await openRawBrokerRequest(
        broker.endpoint,
        execBrokerRequest(token, 'process.exit(0)'),
        (frame) => order.push(`second:${frame.event}`),
      );
      await Promise.all([first.done, second.done]);

      expect(order.indexOf('first:exit')).toBeLessThan(
        order.indexOf('second:decision'),
      );
      expect(session.counters).toEqual({ allowed: 2, denied: 0 });
    } finally {
      session.secrets = new Map();
      await broker.cleanup();
      state.close();
    }
  }, 30_000);

  it('returns the stable busy error for queue timeout and queue-depth overload', async () => {
    const directory = await createSecureTestDirectory(
      join(tmpdir(), 'kavrix-broker-busy-'),
    );
    directories.push(directory);
    const scope = { scopeKind: 'database' as const, scopeId: 'db_broker_busy' };
    const state = await AuthorizationState.open(
      join(directory, 'owner.key'),
      deriveAuthorizationStateKey(new Uint8Array(32).fill(19), scope),
      scope,
    );
    const recordEvent = state.recordEvent.bind(state);
    let releaseFirstAudit = (): void => undefined;
    let markFirstAuditStarted = (): void => undefined;
    const firstAuditGate = new Promise<void>((resolvePromise) => {
      releaseFirstAudit = resolvePromise;
    });
    const firstAuditStarted = new Promise<void>((resolvePromise) => {
      markFirstAuditStarted = resolvePromise;
    });
    let firstAudit = true;
    let auditInFlight = false;
    let overlappingAuditObserved = false;
    vi.spyOn(state, 'recordEvent').mockImplementation(async (event) => {
      if (auditInFlight) {
        overlappingAuditObserved = true;
        throw new Error('concurrent broker audit');
      }
      auditInFlight = true;
      try {
        if (firstAudit) {
          firstAudit = false;
          markFirstAuditStarted();
          await firstAuditGate;
        }
        return await recordEvent(event);
      } finally {
        auditInFlight = false;
      }
    });
    const token = randomUUID().replaceAll('-', '') + randomUUID().replaceAll('-', '');
    const session = {
      token,
      permissions: {
        gh: permissionEntrySchema.parse({
          secret: 'x/y',
          commands: ['node'],
          env: 'BUSY_TOKEN',
        }),
      },
      secrets: new Map([['x/y', 'busy-canary']]),
      state,
      platform: process.platform,
      counters: { allowed: 0, denied: 0 },
      queue: Promise.resolve(),
    };
    const broker = await startAgentBrokerForTest(session, {
      queueWaitTimeoutMs: 120,
      maxQueuedRequests: 1,
      maxPendingAuditOperations: 2,
      hardTeardownGraceMs: 25,
    });
    let brokerCleaned = false;
    try {
      const active = await openRawBrokerRequest(
        broker.endpoint,
        execBrokerRequest(token, 'setTimeout(() => process.exit(0), 500)'),
      );
      await active.waitForFrame(
        (frame) => frame.event === 'decision' && frame.outcome === 'allow',
      );
      await firstAuditStarted;
      const timedOut = await openRawBrokerRequest(
        broker.endpoint,
        execBrokerRequest(token, 'process.exit(0)'),
      );
      await vi.waitFor(() => {
        expect(broker.queuedRequestsForTest()).toBe(1);
      });
      const overloaded = await openRawBrokerRequest(
        broker.endpoint,
        execBrokerRequest(token, 'process.exit(0)'),
      );
      const [timedOutFrames, overloadedFrames] = await Promise.all([
        timedOut.done,
        overloaded.done,
      ]);
      for (const frames of [timedOutFrames, overloadedFrames]) {
        expect(frames).toContainEqual({
          v: 1,
          event: 'decision',
          outcome: 'deny',
          reason: 'invalid-request',
        });
        expect(decodedStderr(frames)).toBe(
          'kavrix agent: broker busy; retry the request.\n',
        );
        expect(frames).toContainEqual({
          v: 1,
          event: 'exit',
          exitCode: 1,
          signal: null,
        });
      }
      expect(session.counters).toEqual({ allowed: 1, denied: 2 });
      expect(overlappingAuditObserved).toBe(false);
      releaseFirstAudit();
      const activeFrames = await active.done;
      expect(activeFrames.some((frame) => frame.event === 'exit')).toBe(true);
      await broker.cleanup();
      brokerCleaned = true;
      expect(session.secrets.size).toBe(0);
      expect(state.recordEvent).toHaveBeenCalledTimes(3);
    } finally {
      releaseFirstAudit();
      session.secrets = new Map();
      if (!brokerCleaned) await broker.cleanup();
      state.close();
    }
  }, 30_000);

  it('flushes the terminal exit frame when completion auditing fails', async () => {
    const directory = await createSecureTestDirectory(
      join(tmpdir(), 'kavrix-broker-audit-failure-'),
    );
    directories.push(directory);
    const scope = {
      scopeKind: 'database' as const,
      scopeId: 'db_broker_audit_failure',
    };
    const state = await AuthorizationState.open(
      join(directory, 'owner.key'),
      deriveAuthorizationStateKey(new Uint8Array(32).fill(23), scope),
      scope,
    );
    const recordEvent = state.recordEvent.bind(state);
    vi.spyOn(state, 'recordEvent').mockImplementation(async (event) => {
      if (event.action === 'execution-completed') {
        throw new Error('forced completion audit failure');
      }
      return await recordEvent(event);
    });
    const token = randomUUID().replaceAll('-', '') + randomUUID().replaceAll('-', '');
    const session = {
      token,
      permissions: {
        gh: permissionEntrySchema.parse({
          secret: 'x/y',
          commands: ['node'],
          env: 'AUDIT_FAILURE_TOKEN',
        }),
      },
      secrets: new Map([['x/y', 'audit-failure-canary']]),
      state,
      platform: process.platform,
      counters: { allowed: 0, denied: 0 },
      queue: Promise.resolve(),
    };
    const broker = await startAgentBrokerForTest(session, {
      hardTeardownGraceMs: 25,
    });
    try {
      const client = await openRawBrokerRequest(
        broker.endpoint,
        execBrokerRequest(token, 'process.exit(0)'),
      );
      const frames = await client.done;

      expect(frames).toContainEqual({
        v: 1,
        event: 'decision',
        outcome: 'allow',
        reason: 'policy-allowed',
      });
      expect(frames).toContainEqual({
        v: 1,
        event: 'exit',
        exitCode: 0,
        signal: null,
      });
      expect(session.counters).toEqual({ allowed: 1, denied: 0 });
    } finally {
      session.secrets = new Map();
      await broker.cleanup();
      state.close();
    }
  }, 30_000);

  it('tears down authenticated clients that exceed relay rate or size', async () => {
    const directory = await createSecureTestDirectory(
      join(tmpdir(), 'kavrix-broker-flood-'),
    );
    directories.push(directory);
    const scope = { scopeKind: 'database' as const, scopeId: 'db_broker_flood' };
    const state = await AuthorizationState.open(
      join(directory, 'owner.key'),
      deriveAuthorizationStateKey(new Uint8Array(32).fill(23), scope),
      scope,
    );
    const token = randomUUID().replaceAll('-', '') + randomUUID().replaceAll('-', '');
    const session = {
      token,
      permissions: {
        gh: permissionEntrySchema.parse({
          secret: 'x/y',
          commands: ['node'],
          env: 'FLOOD_TOKEN',
        }),
      },
      secrets: new Map([['x/y', 'flood-canary']]),
      state,
      platform: process.platform,
      counters: { allowed: 0, denied: 0 },
      queue: Promise.resolve(),
    };
    const broker = await startAgentBrokerForTest(session, {
      frameRateWindowMs: 1_000,
      maxClientFramesPerWindow: 4,
      hardTeardownGraceMs: 25,
    });
    try {
      const client = await openRawBrokerRequest(
        broker.endpoint,
        execBrokerRequest(
          token,
          'process.stdout.write("ready\\n"); setTimeout(() => process.exit(0), 5000)',
        ),
      );
      await client.waitForFrame((frame) => frame.event === 'stdout');
      const startedAt = Date.now();
      client.sendFrames(
        Array.from({ length: 5 }, () => ({
          v: 1 as const,
          event: 'stdin' as const,
          data: Buffer.from('x').toString('base64'),
        })),
      );
      const frames = await client.done;

      expect(Date.now() - startedAt).toBeLessThan(1_000);
      expect(decodedStderr(frames)).toBe(
        'kavrix agent: broker resource limit exceeded.\n',
      );
      expect(frames.filter((frame) => frame.event === 'exit')).toEqual([
        { v: 1, event: 'exit', exitCode: 1, signal: null },
      ]);

      const oversized = await openRawBrokerRequest(
        broker.endpoint,
        execBrokerRequest(
          token,
          'process.stdout.write("ready\\n"); setTimeout(() => process.exit(0), 5000)',
        ),
      );
      await oversized.waitForFrame((frame) => frame.event === 'stdout');
      oversized.sendRaw(Buffer.alloc(MAX_FRAME_BYTES + 1, 0x61));
      const oversizedFrames = await oversized.done;
      expect(decodedStderr(oversizedFrames)).toBe(
        'kavrix agent: broker resource limit exceeded.\n',
      );
      expect(oversizedFrames.filter((frame) => frame.event === 'exit')).toEqual([
        { v: 1, event: 'exit', exitCode: 1, signal: null },
      ]);
    } finally {
      session.secrets = new Map();
      await broker.cleanup();
      state.close();
    }
  }, 30_000);

  it('destroys connections that send malformed protocol lines', async () => {
    const directory = await createSecureTestDirectory(
      join(tmpdir(), 'kavrix-broker-mf-'),
    );
    directories.push(directory);
    const rootKey = new Uint8Array(32).fill(11);
    const scope = { scopeKind: 'database' as const, scopeId: 'db_broker_mf' };
    const state = await AuthorizationState.open(
      join(directory, 'owner.key'),
      deriveAuthorizationStateKey(rootKey, scope),
      scope,
    );
    const session = {
      token: `${'a'.repeat(64)}`,
      permissions: {},
      secrets: new Map<string, string>(),
      state,
      platform: process.platform,
      counters: { allowed: 0, denied: 0 },
      queue: Promise.resolve(),
    };
    const broker = await startAgentBrokerForTest(session);
    try {
      const raw = netConnect(broker.endpoint);
      await new Promise<void>((resolveConnect) => {
        raw.once('connect', () => resolveConnect());
        raw.once('error', () => resolveConnect());
      });
      const outcome = await new Promise<string>((resolveOutcome) => {
        raw.on('close', () => resolveOutcome('destroyed'));
        raw.setTimeout(4000, () => resolveOutcome('timeout'));
        raw.write('{not json at all}\n');
      });
      expect(outcome).toBe('destroyed');
    } finally {
      await broker.cleanup();
      state.close();
    }
  }, 30_000);
});
