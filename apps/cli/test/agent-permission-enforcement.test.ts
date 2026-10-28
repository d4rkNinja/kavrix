import { randomBytes } from 'node:crypto';
import { rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { describe, expect, it, vi } from 'vitest';
import { permissionEntrySchema } from '@kavrix/schemas';
import { createSecureTestDirectory } from '../../../packages/key-files/test/secure-temporary-directory.js';
import { AuthorizationState } from '../src/execution/authorization-state.js';
import {
  AGENT_BROKER_ENV,
  AGENT_TOKEN_ENV,
  executeAgentExec,
  startAgentBrokerForTest,
} from '../src/execution/agent-command.js';

describe('agent permission enforcement', () => {
  it('atomically limits uses, enforces stored denies, and denies extra arguments before spawn', async () => {
    const directory = await createSecureTestDirectory(
      join(tmpdir(), 'kavrix-agent-permission-'),
    );
    const key = randomBytes(32);
    const state = await AuthorizationState.open(join(directory, 'owner.key'), key, {
      scopeKind: 'database',
      scopeId: 'db_permissions',
    });
    key.fill(0);
    const args = ['-e', 'process.exit(process.env.REVIEW_PROBE === undefined ? 2 : 0)'];
    const session = {
      token: randomBytes(32).toString('base64url'),
      permissions: {
        once: permissionEntrySchema.parse({
          secret: 'review/once',
          commands: ['node'],
          env: 'REVIEW_PROBE',
          maxUses: 1,
          operations: [{ command: 'node', args }],
        }),
        blocked: permissionEntrySchema.parse({
          secret: 'review/blocked',
          commands: ['node'],
          env: 'REVIEW_PROBE',
        }),
      },
      secrets: new Map([
        ['review/once', 'agent-test-canary'],
        ['review/blocked', 'agent-test-canary'],
      ]),
      state,
      platform: process.platform,
      counters: { allowed: 0, denied: 0 },
      queue: Promise.resolve(),
    };
    const broker = await startAgentBrokerForTest(session);
    vi.stubEnv(AGENT_BROKER_ENV, broker.endpoint);
    vi.stubEnv(AGENT_TOKEN_ENV, session.token);
    const stderr: string[] = [];
    const write = vi.spyOn(process.stderr, 'write').mockImplementation((chunk) => {
      stderr.push(String(chunk));
      return true;
    });
    try {
      await state.putPolicy(
        'deny-blocked',
        permissionEntrySchema.parse({ secret: 'review/blocked', deny: true }),
      );
      await executeAgentExec({
        permission: 'blocked',
        executableAndArgs: [process.execPath, ...args],
      });
      await session.queue;
      expect(session.counters).toEqual({ allowed: 0, denied: 1 });
      await executeAgentExec({
        permission: 'once',
        executableAndArgs: [process.execPath, ...args, 'extra'],
      });
      await session.queue;
      expect(session.counters).toEqual({ allowed: 0, denied: 2 });
      await Promise.all(
        [0, 1].map(() =>
          executeAgentExec({
            permission: 'once',
            executableAndArgs: [process.execPath, ...args],
          }),
        ),
      );
      await session.queue;
      expect(session.counters).toEqual({ allowed: 1, denied: 3 });
      const snapshot = await state.read();
      expect(
        snapshot.audit
          .filter((event) => event.action === 'authorization-denied')
          .map((event) => event.reason),
      ).toEqual(
        expect.arrayContaining(['policy-denied', 'operation-not-allowed', 'exhausted']),
      );
      expect(stderr.join('')).not.toContain('agent-test-canary');
      // A live policy edit must also take effect without restarting the broker.
      await state.putPolicy(
        'deny-once',
        permissionEntrySchema.parse({ secret: 'review/once', deny: true }),
      );
      await executeAgentExec({
        permission: 'once',
        executableAndArgs: [process.execPath, ...args],
      });
      await session.queue;
      expect(
        (await state.read()).audit
          .filter((event) => event.action === 'authorization-denied')
          .at(-1)?.reason,
      ).toBe('policy-denied');
    } finally {
      write.mockRestore();
      vi.unstubAllEnvs();
      await broker.cleanup();
      state.close();
      process.exitCode = undefined;
      await rm(directory, { force: true, recursive: true });
    }
  });
});
