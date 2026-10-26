import { rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { afterEach, describe, expect, it } from 'vitest';

import { deriveAuthorizationStateKey } from '@kavrix/crypto';
import { grantIdSchema, timestampSchema, type GrantRecord } from '@kavrix/schemas';

import { createSecureTestDirectory } from '../../../packages/key-files/test/secure-temporary-directory.js';
import { AuthorizationState } from '../src/execution/authorization-state.js';

const directories: string[] = [];
const scope = { scopeKind: 'database' as const, scopeId: 'db_grant_denials' };

afterEach(async () => {
  const pending = directories.splice(0);
  await Promise.all(
    pending.map((directory) =>
      rm(directory, { force: true, recursive: true }).catch(() => undefined),
    ),
  );
});

async function openState(): Promise<{
  state: AuthorizationState;
  directory: string;
}> {
  const directory = await createSecureTestDirectory(
    join(tmpdir(), 'kavrix-grant-denial-'),
  );
  directories.push(directory);
  const state = await AuthorizationState.open(
    join(directory, 'owner.key'),
    deriveAuthorizationStateKey(new Uint8Array(32).fill(9), scope),
    scope,
  );
  return { state, directory };
}

function grantRecord(overrides: Partial<GrantRecord> = {}): GrantRecord {
  return {
    grantId: grantIdSchema.parse('grant-denial-regression'),
    secret: 'production/database',
    actor: 'user',
    commands: ['node'],
    createdAt: timestampSchema.parse(new Date(Date.now() - 120_000).toISOString()),
    usedCount: 0,
    ...overrides,
  };
}

/**
 * Regression: `grant-expired` and `grant-exhausted` denials staged their audit
 * event and then threw inside the locked transition, discarding the draft —
 * so a raced denial (another invocation claiming the final use first) left
 * zero persisted audit events. Every denial must now commit its audit event
 * with the state before the typed error reaches the caller.
 */
describe('grant consumption denial audit', () => {
  it('persists grant-exhausted when the final use was consumed under the lock', async () => {
    const { state } = await openState();
    try {
      const grantId = grantIdSchema.parse('grant-denial-regression');
      await state.putGrant(grantRecord({ grantId, maxUses: 1, usedCount: 1 }));
      await expect(
        state.consumeGrantUse(grantId, { executable: 'node' }),
      ).rejects.toMatchObject({ errorCode: 'GRANT_INVALID' });

      const snapshot = await state.read();
      const event = snapshot.audit.find((entry) => entry.action === 'grant-exhausted');
      expect(event).toBeDefined();
      expect(event?.grantId).toBe(grantId);
      expect(event?.secret).toBe('production/database');
      expect(event?.command).toBe('node');
      // The raced denial consumed nothing.
      expect(snapshot.grants[grantId]?.usedCount).toBe(1);
    } finally {
      state.close();
    }
  });

  it('persists grant-expired for an expired grant', async () => {
    const { state } = await openState();
    try {
      const grantId = grantIdSchema.parse('grant-denial-regression');
      await state.putGrant(
        grantRecord({
          grantId,
          expiresAt: timestampSchema.parse(new Date(Date.now() - 60_000).toISOString()),
        }),
      );
      await expect(
        state.consumeGrantUse(grantId, { executable: 'node' }),
      ).rejects.toMatchObject({ errorCode: 'GRANT_INVALID' });

      const snapshot = await state.read();
      const event = snapshot.audit.find((entry) => entry.action === 'grant-expired');
      expect(event).toBeDefined();
      expect(event?.grantId).toBe(grantId);
      expect(event?.command).toBe('node');
    } finally {
      state.close();
    }
  });

  it('persists an authorization-denied event for a raced revocation', async () => {
    const { state } = await openState();
    try {
      const grantId = grantIdSchema.parse('grant-denial-regression');
      await state.putGrant(
        grantRecord({
          grantId,
          revokedAt: timestampSchema.parse(new Date(Date.now() - 30_000).toISOString()),
        }),
      );
      await expect(
        state.consumeGrantUse(grantId, { executable: 'node' }),
      ).rejects.toMatchObject({ errorCode: 'AUTHORIZATION_DENIED' });

      const snapshot = await state.read();
      const event = snapshot.audit.find(
        (entry) => entry.action === 'authorization-denied',
      );
      expect(event).toBeDefined();
      expect(event?.grantId).toBe(grantId);
      expect(event?.reason).toBe('revoked');
      expect(event?.secret).toBe('production/database');
    } finally {
      state.close();
    }
  });

  it('persists an authorization-denied event when the grant vanished', async () => {
    const { state } = await openState();
    try {
      const grantId = grantIdSchema.parse('grant-denial-regression');
      await expect(
        state.consumeGrantUse(grantId, { executable: 'node' }),
      ).rejects.toMatchObject({ errorCode: 'GRANT_INVALID' });

      const snapshot = await state.read();
      const event = snapshot.audit.find(
        (entry) => entry.action === 'authorization-denied',
      );
      expect(event).toBeDefined();
      expect(event?.grantId).toBe(grantId);
      expect(event?.reason).toBe('invalid-request');
    } finally {
      state.close();
    }
  });

  it('still consumes an allowed use and audits it exactly once', async () => {
    const { state } = await openState();
    try {
      const grantId = grantIdSchema.parse('grant-denial-regression');
      await state.putGrant(grantRecord({ grantId, maxUses: 2 }));
      const consumed = await state.consumeGrantUse(grantId, {
        executable: 'node',
        argvPreview: ['-e', 'process.exit(0)'],
      });
      expect(consumed.usedCount).toBe(1);

      const snapshot = await state.read();
      const allowed = snapshot.audit.filter(
        (entry) => entry.action === 'authorization-allowed',
      );
      expect(allowed).toHaveLength(1);
      expect(allowed[0]?.argvPreview).toEqual(['-e', 'process.exit(0)']);
      expect(snapshot.audit.some((entry) => entry.action === 'grant-exhausted')).toBe(
        false,
      );
    } finally {
      state.close();
    }
  });
});
