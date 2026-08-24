import { randomBytes } from 'node:crypto';
import { rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { deriveAuthorizationStateKey } from '@kavrix/crypto';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';

import {
  AuthorizationStateFileError,
  authorizationStatePath,
  initializeAuthorizationStateFile,
  readAuthorizationStateFile,
  transitionAuthorizationStateFile,
  type AuthorizationScope,
} from '../src/authorization-state-file.js';
import { createSecureTestDirectory as mkdtemp } from './secure-temporary-directory.js';

let directory = '';
let keyFile = '';
const scope: AuthorizationScope = { scopeKind: 'database', scopeId: 'db_local' };

function emptyState() {
  return { version: 1 as const, policies: {}, grants: {}, audit: [] };
}

beforeEach(async () => {
  directory = await mkdtemp(join(tmpdir(), 'kavrix-authorization-state-'));
  keyFile = join(directory, 'owner.key');
});

afterEach(async () => {
  await rm(directory, { force: true, recursive: true });
});

function rootKey(): Uint8Array {
  return new Uint8Array(randomBytes(32));
}

describe('sealed authorization state file', () => {
  it('round-trips an initial state and reports missing files as null', async () => {
    const path = authorizationStatePath(keyFile);
    const key = deriveAuthorizationStateKey(rootKey(), scope);
    expect(await readAuthorizationStateFile(path, key, scope)).toBeNull();

    await initializeAuthorizationStateFile(path, key, scope, emptyState());
    const loaded = await readAuthorizationStateFile(path, key, scope);
    expect(loaded).not.toBeNull();
    expect(loaded?.state.version).toBe(1);
    expect(loaded?.envelope.sequence).toBe(0);
    expect(loaded?.envelope.scopeId).toBe(scope.scopeId);

    const bytes = await import('node:fs/promises').then((fs) => fs.readFile(path));
    const text = bytes.toString('utf8');
    expect(text).not.toContain('"policies":{"x"');
    expect(text.startsWith('{')).toBe(true);
  });

  it('bumps the authenticated sequence across transitions under the lock', async () => {
    const path = authorizationStatePath(keyFile);
    const key = deriveAuthorizationStateKey(rootKey(), scope);
    await initializeAuthorizationStateFile(path, key, scope, emptyState());

    const result = await transitionAuthorizationStateFile(
      path,
      key,
      scope,
      (current) => ({
        nextState: {
          ...current,
          policies: {
            demo: {
              definition: { secret: 'github/token', commands: ['gh'] },
              createdAt: currentEnvelopeCreatedAt(),
            },
          },
        },
        result: 'created' as const,
      }),
    );
    expect(result).toBe('created');

    const loaded = await readAuthorizationStateFile(path, key, scope);
    expect(loaded?.envelope.sequence).toBe(1);
    expect(Object.keys(loaded?.state.policies ?? {})).toEqual(['demo']);
  });

  it('fails closed on a wrong key without disclosing plaintext', async () => {
    const path = authorizationStatePath(keyFile);
    await initializeAuthorizationStateFile(
      path,
      deriveAuthorizationStateKey(rootKey(), scope),
      scope,
      emptyState(),
    );
    let caught: unknown;
    try {
      await readAuthorizationStateFile(
        path,
        deriveAuthorizationStateKey(rootKey(), scope),
        scope,
      );
    } catch (error) {
      caught = error;
    }
    expect(caught).toBeInstanceOf(AuthorizationStateFileError);
    expect((caught as AuthorizationStateFileError).code).toBe('INTEGRITY_FAILURE');
  });

  it('fails closed when any byte of the sealed document changes', async () => {
    const path = authorizationStatePath(keyFile);
    const key = deriveAuthorizationStateKey(rootKey(), scope);
    await initializeAuthorizationStateFile(path, key, scope, emptyState());
    const fs = await import('node:fs/promises');
    const original = await fs.readFile(path, 'utf8');
    const parsed = JSON.parse(original) as Record<string, string>;
    const ciphertext = Buffer.from(parsed['ciphertext'], 'base64url');
    ciphertext[0] ^= 0xff;
    parsed['ciphertext'] = ciphertext.toString('base64url');
    await fs.writeFile(path, JSON.stringify(parsed), 'utf8');

    await expect(readAuthorizationStateFile(path, key, scope)).rejects.toMatchObject({
      code: expect.stringMatching(/INVALID_FORMAT|INTEGRITY_FAILURE/u),
    });
  });

  it('refuses a sidecar that belongs to a different scope', async () => {
    const path = authorizationStatePath(keyFile);
    const otherScope: AuthorizationScope = {
      scopeKind: 'vault',
      scopeId: 'vault_other',
    };
    const key = deriveAuthorizationStateKey(rootKey(), scope);
    await initializeAuthorizationStateFile(path, key, otherScope, emptyState());
    await expect(readAuthorizationStateFile(path, key, scope)).rejects.toMatchObject({
      code: 'SCOPE_MISMATCH',
    });
  });

  it('serializes canonically so reformatting fails closed', async () => {
    const path = authorizationStatePath(keyFile);
    const key = deriveAuthorizationStateKey(rootKey(), scope);
    await initializeAuthorizationStateFile(path, key, scope, emptyState());
    const fs = await import('node:fs/promises');
    const parsed = JSON.parse(await fs.readFile(path, 'utf8')) as object;
    await fs.writeFile(path, JSON.stringify(parsed, null, 2), 'utf8');
    await expect(readAuthorizationStateFile(path, key, scope)).rejects.toMatchObject({
      code: 'INVALID_FORMAT',
    });
  });

  it('rejects a truncated or foreign JSON document', async () => {
    const path = authorizationStatePath(keyFile);
    const fs = await import('node:fs/promises');
    await fs.writeFile(path, '{"format":"kavrix-authorization-state"', 'utf8');
    await expect(
      readAuthorizationStateFile(
        path,
        deriveAuthorizationStateKey(rootKey(), scope),
        scope,
      ),
    ).rejects.toBeInstanceOf(AuthorizationStateFileError);
  });

  function currentEnvelopeCreatedAt(): string {
    return '2026-08-22T00:00:00.000Z';
  }
});
