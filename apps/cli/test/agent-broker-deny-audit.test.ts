import { randomUUID } from 'node:crypto';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { describe, expect, it, vi } from 'vitest';

import { deriveAuthorizationStateKey } from '@kavrix/crypto';
import { permissionEntrySchema } from '@kavrix/schemas';

import { createSecureTestDirectory } from '../../../packages/key-files/test/secure-temporary-directory.js';
import {
  AGENT_BROKER_ENV,
  AGENT_TOKEN_ENV,
  executeAgentExec,
  startAgentBrokerForTest,
} from '../src/execution/agent-command.js';
import { AuthorizationState } from '../src/execution/authorization-state.js';

/**
 * Regression (0.2.23): denial events were silently dropped from the sealed
 * audit trail whenever argv[0] was a full executable path — the audit schema
 * rejects full paths as `command`, and the schema failure swallowed the whole
 * event. Windows agents always pass absolute paths (`process.execPath`), so
 * every denial was lost exactly where agents run. The denial must be recorded
 * with a bare, schema-valid command name (or none), never skipped.
 */
describe('agent broker denial audit', () => {
  it('records a denial whose argv[0] is a full executable path', async () => {
    const directory = await createSecureTestDirectory(
      join(tmpdir(), 'kavrix-deny-audit-'),
    );
    const scope = { scopeKind: 'database' as const, scopeId: 'db_deny_audit' };
    const state = await AuthorizationState.open(
      join(directory, 'owner.key'),
      deriveAuthorizationStateKey(new Uint8Array(32).fill(7), scope),
      scope,
    );
    const token = randomUUID().replaceAll('-', '') + randomUUID().replaceAll('-', '');
    const session = {
      token,
      permissions: {
        'prod-db': permissionEntrySchema.parse({ deny: true }),
      },
      secrets: new Map(),
      state,
      platform: process.platform,
      counters: { allowed: 0, denied: 0 },
      queue: Promise.resolve(),
    };
    const broker = await startAgentBrokerForTest(session);
    process.env[AGENT_BROKER_ENV] = broker.endpoint;
    process.env[AGENT_TOKEN_ENV] = token;
    const stderrChunks: string[] = [];
    const stderrWrite = vi
      .spyOn(process.stderr, 'write')
      .mockImplementation((chunk) => {
        stderrChunks.push(String(chunk));
        return true;
      });
    try {
      // argv[0] is an absolute path with separators, exactly like a real
      // agent invoking `process.execPath` on Windows.
      await executeAgentExec({
        permission: 'prod-db',
        executableAndArgs: [process.execPath, '-e', 'process.exit(0)'],
      });
      expect(process.exitCode).toBe(1);
      expect(stderrChunks.join('')).toContain('denied (policy-denied)');

      // Exit is sent before the sealed audit write completes. Wait for the
      // broker's observable completion boundary, then require the persisted
      // event rather than racing real Windows ACL I/O with a short poll.
      await session.queue;
      const snapshot = await state.read();
      const denial = snapshot.audit.find(
        (event) => event.action === 'authorization-denied',
      );
      expect(denial).toBeDefined();
      expect(denial?.permissionKey).toBe('prod-db');
      expect(denial?.reason).toBe('policy-denied');
      // The command field, when present, stays a bare schema-valid name.
      if (denial?.command !== undefined) {
        expect(denial.command).toMatch(/^[A-Za-z0-9][A-Za-z0-9._+-]*$/u);
        expect(denial.command.includes('/') || denial.command.includes('\\')).toBe(
          false,
        );
      }
    } finally {
      stderrWrite.mockRestore();
      delete process.env[AGENT_BROKER_ENV];
      delete process.env[AGENT_TOKEN_ENV];
      session.secrets = new Map();
      await broker.cleanup().catch(() => undefined);
      state.close();
      process.exitCode = undefined;
    }
  });
});
