import { randomUUID } from 'node:crypto';
import { rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { PassThrough } from 'node:stream';

import { deriveAuthorizationStateKey } from '@kavrix/crypto';
import { permissionEntrySchema } from '@kavrix/schemas';
import { createSecureTestDirectory } from '../../../packages/key-files/test/secure-temporary-directory.js';
import { afterAll, describe, expect, it, vi } from 'vitest';

import {
  AGENT_BROKER_ENV,
  AGENT_TOKEN_ENV,
  executeAgentExec,
  startAgentBrokerForTest,
} from '../src/execution/agent-command.js';
import { connect as netConnect } from 'node:net';
import {
  AuthorizationState,
  parsePolicyId,
} from '../src/execution/authorization-state.js';
import { executionFlatOptions } from '../src/execution/cli-options.js';

const directories: string[] = [];

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
