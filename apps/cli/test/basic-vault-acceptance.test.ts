import { PassThrough, Readable, Writable } from 'node:stream';
import { mkdtemp, readFile, readdir, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';

import { vi, describe, expect, it, afterEach } from 'vitest';
import type * as ClipboardModule from '@kavrix/clipboard';
import type * as KeychainModule from '@kavrix/keychain';

const testAdapters = vi.hoisted(() => {
  const entries = new Map<string, Uint8Array>();
  let copyCount = 0;

  const entryFactory: KeychainModule.NativeEntryFactory = (
    service: string,
    account: string,
  ) => {
    const key = `${service}\u0000${account}`;
    return {
      setSecret: (secret: Uint8Array): Promise<void> => {
        const previous = entries.get(key);
        previous?.fill(0);
        entries.set(key, Uint8Array.from(secret));
        return Promise.resolve();
      },
      getSecret: (): Promise<Uint8Array | null> => {
        const secret = entries.get(key);
        return Promise.resolve(secret === undefined ? null : Uint8Array.from(secret));
      },
      deleteCredential: (): Promise<void> => {
        const previous = entries.get(key);
        previous?.fill(0);
        entries.delete(key);
        return Promise.resolve();
      },
    };
  };

  const createClipboard = (): ClipboardModule.SecureClipboardPort => ({
    copy: (
      secret: Uint8Array,
      options: ClipboardModule.ClipboardCopyOptions,
    ): Promise<ClipboardModule.ClipboardCopyReceipt> => {
      void secret;
      void options;
      copyCount += 1;
      return Promise.resolve({
        generation: copyCount,
        requestedClearAfterMs: 30_000,
        cleanupRetryDeadlineAfterMs: 30_700,
        maxCleanupAttempts: 4,
        clearAfterMs: 30_000,
      });
    },
    lock: (): Promise<boolean> => Promise.resolve(false),
    dispose: (): Promise<boolean> => Promise.resolve(false),
    takeBackgroundError: (): Error | null => null,
  });

  return {
    entryFactory,
    createClipboard,
    reset: (): void => {
      for (const secret of entries.values()) secret.fill(0);
      entries.clear();
      copyCount = 0;
    },
  };
});

vi.mock('@kavrix/keychain', async () => {
  const actual = await vi.importActual<typeof KeychainModule>('@kavrix/keychain');
  return {
    ...actual,
    loadNativeEntryFactory: (): Promise<KeychainModule.NativeEntryFactory> =>
      Promise.resolve(testAdapters.entryFactory),
  };
});

vi.mock('@kavrix/clipboard', async () => {
  const actual = await vi.importActual<typeof ClipboardModule>('@kavrix/clipboard');
  return { ...actual, createSecureClipboard: testAdapters.createClipboard };
});

import {
  apiSessionResponseSchema,
  apiScopesSchema,
  changeRecordSchema,
  contentHashForRecord,
  syncPullQuerySchema,
  syncPullResponseSchema,
  syncPushRequestSchema,
  syncPushResponseSchema,
  syncCursorSchema,
  tombstoneRecordSchema,
  vaultBootstrapRequestSchema,
  vaultBootstrapResponseSchema,
  type ChangeRecord,
  type OpaqueMutation,
  type OpaqueSyncRecord,
  type VaultRecord,
} from '@kavrix/schemas';
import { acquiredSecretSchema, runCli, type CliDependencies } from '../src/index.js';
import type { SecretInputPort } from '../src/secret-input.js';

const SERVER_URL = 'https://acceptance.example/';
const PUBLIC_VALUE = 'acceptance-user-opaque';
const SECRET_VALUE = 'acceptance-password-never-plaintext';

type ActiveMutationRecord = Extract<
  OpaqueMutation,
  { entityType: 'vault' | 'group' | 'item' }
>['record'];

type StoredChange = Readonly<{
  change: ChangeRecord;
  record: OpaqueSyncRecord;
}>;

class OpaqueAcceptanceControlPlane {
  readonly requestBodies: string[] = [];
  readonly #active = new Map<string, ActiveMutationRecord>();
  readonly #visible = new Map<string, OpaqueSyncRecord>();
  readonly #changes: StoredChange[] = [];
  readonly #accepted = new Map<
    string,
    Readonly<{ body: string; change: ChangeRecord }>
  >();
  readonly #batches = new Map<string, Readonly<{ body: string; response: unknown }>>();
  #vault: VaultRecord | null = null;
  #deviceId = '';
  #serverVaultRevision = 0;

  fetch(input: Request | URL, init?: RequestInit): Response {
    const url = new URL(input instanceof Request ? input.url : String(input));
    const method = init?.method ?? (input instanceof Request ? input.method : 'GET');
    const body = typeof init?.body === 'string' ? init.body : '';
    if (body.length > 0) this.requestBodies.push(body);

    const path = url.pathname.split('/').filter((segment) => segment.length > 0);
    if (
      method === 'POST' &&
      path.length === 2 &&
      path[0] === 'v1' &&
      path[1] === 'vaults'
    ) {
      return this.bootstrap(url, body);
    }
    if (
      method === 'GET' &&
      path.length === 2 &&
      path[0] === 'v1' &&
      path[1] === 'session'
    ) {
      return this.session(url);
    }
    if (
      method === 'GET' &&
      path.length === 3 &&
      path[0] === 'v1' &&
      path[1] === 'vaults'
    ) {
      return this.fetchVault(url, path[2] ?? '');
    }
    if (
      path.length === 4 &&
      path[0] === 'v1' &&
      path[1] === 'vaults' &&
      path[3] === 'sync'
    ) {
      if (method === 'GET') return this.pull(url, path[2] ?? '');
      if (method === 'POST') return this.push(url, path[2] ?? '', body);
    }
    return jsonResponse(url, 404, {
      error: { code: 'NOT_FOUND', message: 'Not found' },
    });
  }

  assertNoPlaintextBodies(): void {
    const encoded = this.requestBodies.join('\n');
    expect(encoded).not.toContain(PUBLIC_VALUE);
    expect(encoded).not.toContain(SECRET_VALUE);
  }

  private bootstrap(url: URL, body: string): Response {
    const request = vaultBootstrapRequestSchema.parse(JSON.parse(body) as unknown);
    this.#vault = request.vault;
    this.#deviceId = request.device.id;
    this.#active.set(this.key('vault', request.vault.id), request.vault);
    const change = changeRecordSchema.parse({
      id: 'change.acceptance.1',
      vaultId: request.vault.id,
      serverSequence: 1,
      recordRevision: request.vault.revision,
      operation: 'upsert',
      ciphertextHash: contentHashForRecord(request.vault),
      createdAt: request.vault.updatedAt,
      entityType: 'vault',
      entityId: request.vault.id,
    });
    this.#visible.set(this.key('vault', request.vault.id), request.vault);
    this.#changes.push({ change, record: request.vault });
    const response = vaultBootstrapResponseSchema.parse({
      vaultId: request.vault.id,
      deviceId: request.device.id,
    });
    return jsonResponse(url, 201, response);
  }

  private session(url: URL): Response {
    if (this.#vault === null)
      return jsonResponse(url, 404, {
        error: { code: 'NOT_FOUND', message: 'Not found' },
      });
    return jsonResponse(
      url,
      200,
      apiSessionResponseSchema.parse({
        vaultId: this.#vault.id,
        deviceId: this.#deviceId,
        scopes: apiScopesSchema.parse(['sync:read', 'sync:write', 'device:manage']),
      }),
    );
  }

  private fetchVault(url: URL, vaultId: string): Response {
    if (this.#vault === null || this.#vault.id !== vaultId) {
      return jsonResponse(url, 404, {
        error: { code: 'NOT_FOUND', message: 'Not found' },
      });
    }
    return jsonResponse(url, 200, this.#vault);
  }

  private pull(url: URL, vaultId: string): Response {
    if (this.#vault === null || this.#vault.id !== vaultId) {
      return jsonResponse(url, 404, {
        error: { code: 'NOT_FOUND', message: 'Not found' },
      });
    }
    const query = syncPullQuerySchema.parse(
      Object.fromEntries(url.searchParams.entries()),
    );
    const pending = this.#changes.filter(
      ({ change }) => change.serverSequence > query.serverSequence,
    );
    const page = pending.slice(0, query.limit);
    const serverSequence = page.at(-1)?.change.serverSequence ?? query.serverSequence;
    const response = syncPullResponseSchema.parse({
      vaultId: this.#vault.id,
      serverVaultRevision: this.#serverVaultRevision,
      changes: page,
      nextCursor: syncCursorSchema.parse({
        vaultId: this.#vault.id,
        serverSequence,
        highestSeenVaultRevision: this.#serverVaultRevision,
      }),
      hasMore: pending.length > page.length,
    });
    return jsonResponse(url, 200, response);
  }

  private push(url: URL, vaultId: string, body: string): Response {
    if (this.#vault === null || this.#vault.id !== vaultId) {
      return jsonResponse(url, 404, {
        error: { code: 'NOT_FOUND', message: 'Not found' },
      });
    }
    const batch = syncPushRequestSchema.parse(JSON.parse(body) as unknown);
    const previousBatch = this.#batches.get(batch.batchIdempotencyKey);
    if (previousBatch !== undefined) {
      if (previousBatch.body !== body)
        throw new Error('Acceptance batch key was reused.');
      return jsonResponse(url, 200, previousBatch.response);
    }

    const results: (
      | Readonly<{
          status: 'accepted';
          idempotencyKey: string;
          disposition: 'committed' | 'duplicate';
          change: ChangeRecord;
        }>
      | Readonly<{
          status: 'conflict';
          idempotencyKey: string;
          currentRevision: number;
          current: OpaqueSyncRecord | null;
        }>
    )[] = [];

    for (const mutation of batch.mutations) {
      const prior = this.#accepted.get(mutation.idempotencyKey);
      if (prior !== undefined) {
        if (prior.body !== JSON.stringify(mutation)) {
          throw new Error('Acceptance mutation key was reused.');
        }
        results.push({
          status: 'accepted',
          idempotencyKey: mutation.idempotencyKey,
          disposition: 'duplicate',
          change: prior.change,
        });
        continue;
      }

      const key = this.key(mutation.entityType, mutation.record.id);
      const predecessor = this.#active.get(key);
      const expected =
        predecessor === undefined
          ? null
          : mutation.entityType === 'vault'
            ? 'revision' in predecessor
              ? predecessor.revision
              : null
            : 'recordRevision' in predecessor
              ? predecessor.recordRevision
              : null;
      const supplied =
        mutation.entityType === 'vault'
          ? mutation.expectedVaultRevision
          : mutation.expectedRecordRevision;
      if (supplied !== expected) {
        results.push({
          status: 'conflict',
          idempotencyKey: mutation.idempotencyKey,
          currentRevision: expected ?? 0,
          current: this.#visible.get(key) ?? null,
        });
        continue;
      }

      const change = changeRecordSchema.parse({
        id: `change.acceptance.${String(this.#changes.length + 1)}`,
        vaultId: batch.vaultId,
        serverSequence: this.#changes.length + 1,
        recordRevision:
          mutation.entityType === 'vault'
            ? mutation.record.revision
            : mutation.record.recordRevision,
        operation: operationFor(mutation, predecessor),
        ciphertextHash: contentHashForRecord(mutation.record),
        createdAt: '2026-08-14T00:00:00.000Z',
        entityType: mutation.entityType,
        entityId: mutation.record.id,
      });
      const visible = visibleRecordFor(mutation, predecessor);
      this.#active.set(key, mutation.record);
      this.#visible.set(key, visible);
      this.#changes.push({ change, record: visible });
      this.#serverVaultRevision += 1;
      if (mutation.entityType === 'vault') this.#vault = mutation.record;
      const mutationBody = JSON.stringify(mutation);
      this.#accepted.set(mutation.idempotencyKey, { body: mutationBody, change });
      results.push({
        status: 'accepted',
        idempotencyKey: mutation.idempotencyKey,
        disposition: 'committed',
        change,
      });
    }

    const response = syncPushResponseSchema.parse({
      vaultId: batch.vaultId,
      serverVaultRevision: this.#serverVaultRevision,
      batchIdempotencyKey: batch.batchIdempotencyKey,
      results,
    });
    this.#batches.set(batch.batchIdempotencyKey, { body, response });
    return jsonResponse(url, 200, response);
  }

  private key(entityType: string, entityId: string): string {
    return `${entityType}:${entityId}`;
  }
}

function operationFor(
  mutation: OpaqueMutation,
  predecessor: ActiveMutationRecord | undefined,
): ChangeRecord['operation'] {
  if (mutation.entityType === 'vault') return 'upsert';
  if (mutation.record.tombstonedAt !== undefined) return 'tombstone';
  if (predecessor !== undefined && hasTombstonedAt(predecessor)) {
    return 'restore';
  }
  return 'upsert';
}

function visibleRecordFor(
  mutation: OpaqueMutation,
  predecessor: ActiveMutationRecord | undefined,
): OpaqueSyncRecord {
  if (mutation.entityType === 'vault') return mutation.record;
  if (mutation.record.tombstonedAt === undefined) return mutation.record;
  if (predecessor === undefined || !hasTombstonedAt(predecessor)) {
    throw new Error('Acceptance tombstone predecessor is missing.');
  }
  return tombstoneRecordSchema.parse({
    vaultId: mutation.record.vaultId,
    entityType: mutation.entityType,
    entityId: mutation.record.id,
    state: 'deleted',
    tombstoneRevision: mutation.record.recordRevision,
    lastRecordRevision: predecessor.recordRevision,
    lastCiphertextHash: contentHashForRecord(predecessor),
    deletedAt: mutation.record.tombstonedAt,
  });
}

function hasTombstonedAt(
  record: ActiveMutationRecord,
): record is TombstonableActiveRecord {
  return 'tombstonedAt' in record;
}

type TombstonableActiveRecord = Extract<
  ActiveMutationRecord,
  { recordRevision: number }
>;

function jsonResponse(url: URL, status: number, value: unknown): Response {
  const response = new Response(JSON.stringify(value), {
    status,
    headers: { 'content-type': 'application/json; charset=utf-8' },
  });
  Object.defineProperty(response, 'url', { value: url.href });
  return response;
}

describe('basic command-only vault acceptance', () => {
  let controlPlane: OpaqueAcceptanceControlPlane;

  afterEach(async () => {
    vi.unstubAllGlobals();
    testAdapters.reset();
    if (home.length > 0) await rm(home, { recursive: true, force: true });
    home = '';
  });

  it('completes init, mutation, sync, masked read, copy, lock, reopen, update, archive, restore, and read', async () => {
    home = await mkdtemp(join(tmpdir(), 'kavrix-basic-acceptance-'));
    controlPlane = new OpaqueAcceptanceControlPlane();
    vi.stubGlobal('fetch', controlPlane.fetch.bind(controlPlane));

    const initialization = await execute(
      [
        'init',
        '--server',
        SERVER_URL,
        '--secret-backend',
        'native',
        '--confirmation-stdin',
      ],
      { interactive: true },
    );
    expect(initialization.stdout).toBe('Vault initialized.\n');
    expect(initialization.stderr).toContain('Portable key:');
    expect(initialization.stderr).toContain('Recovery key:');
    expect(initialization.stderr).not.toContain('Error [');

    const unlocked = await execute(['unlock', '--check', '--secret-backend', 'native']);
    expect(unlocked.stdout).toBe('Vault unlock verified and relocked.\n');

    await execute(['group', 'create', 'Personal', '--secret-backend', 'native']);
    await execute([
      'credential',
      'create',
      'Personal',
      'Primary',
      '--secret-backend',
      'native',
    ]);
    await execute(
      [
        'field',
        'add',
        'Personal',
        'Primary',
        'username',
        '--type',
        'text',
        '--label',
        'Username',
        '--value-stdin',
        '--secret-backend',
        'native',
      ],
      { secretValues: [PUBLIC_VALUE] },
    );
    await execute(
      [
        'field',
        'add',
        'Personal',
        'Primary',
        'password',
        '--type',
        'secret',
        '--label',
        'Password',
        '--sensitive',
        '--value-stdin',
        '--secret-backend',
        'native',
      ],
      { secretValues: [SECRET_VALUE] },
    );

    const synchronized = await execute([
      'sync',
      '--json',
      '--secret-backend',
      'native',
    ]);
    expect(JSON.parse(synchronized.stdout)).toMatchObject({
      vaultState: 'locked',
      syncState: 'idle',
      pendingChanges: 0,
    });

    const shown = await execute([
      'show',
      'Personal',
      'Primary',
      '--secret-backend',
      'native',
    ]);
    expect(shown.stdout).toContain('acceptance-user-opaque');
    expect(shown.stdout).toContain('[REDACTED]');
    expect(shown.stdout).not.toContain(SECRET_VALUE);

    const copied = await execute([
      'copy',
      'Personal',
      'Primary',
      'password',
      '--secret-backend',
      'native',
    ]);
    expect(copied.stdout).toContain('Copied Password');
    expect(copied.stdout).not.toContain(SECRET_VALUE);

    await execute(['lock', '--secret-backend', 'native']);
    const reopened = await execute([
      'show',
      'Personal',
      'Primary',
      '--secret-backend',
      'native',
    ]);
    expect(reopened.stdout).toContain('[REDACTED]');
    expect(reopened.stdout).not.toContain(SECRET_VALUE);

    const listed = await execute([
      'credential',
      'list',
      'Personal',
      '--json',
      '--secret-backend',
      'native',
    ]);
    const credentials = JSON.parse(listed.stdout) as { id: string }[];
    const credential = credentials[0];
    if (credential === undefined)
      throw new Error('Acceptance credential list was empty.');

    await execute([
      'credential',
      'rename',
      'Personal',
      'Primary',
      'Updated',
      '--secret-backend',
      'native',
    ]);
    await execute([
      'credential',
      'archive',
      'Personal',
      'Updated',
      '--secret-backend',
      'native',
    ]);
    await execute([
      'credential',
      'restore',
      'Personal',
      credential.id,
      '--secret-backend',
      'native',
    ]);

    const read = await execute([
      'get',
      'Personal',
      'Updated',
      'username',
      '--secret-backend',
      'native',
    ]);
    expect(read.stdout).toBe(`${PUBLIC_VALUE}\n`);
    const maskedRead = await execute([
      'get',
      'Personal',
      'Updated',
      'password',
      '--secret-backend',
      'native',
    ]);
    expect(maskedRead.stdout).toBe('[REDACTED]\n');
    expect(maskedRead.stdout).not.toContain(SECRET_VALUE);

    controlPlane.assertNoPlaintextBodies();
    expect(await treeContains(home, SECRET_VALUE)).toBe(false);
  }, 120_000);
});

let home = '';

type ExecuteOptions = Readonly<{
  interactive?: boolean;
  secretValues?: readonly string[];
}>;

async function execute(
  arguments_: readonly string[],
  options: ExecuteOptions = {},
): Promise<Readonly<{ stdout: string; stderr: string }>> {
  const stdout = capture(false);
  const terminal = options.interactive === true ? interactiveTerminal() : undefined;
  const stderr = terminal?.output ?? capture(false);
  const secrets = scriptedSecrets(options.secretValues ?? [], terminal?.output.value);
  const dependencies: CliDependencies = {
    ports: undefined as never,
    secrets,
    environment: { CREDS_HOME: home },
    runtime: {
      stdin: terminal?.input ?? Readable.from([]),
      stdout: stdout.stream,
      stderr: stderr.stream,
    },
  };
  const exitCode = await runCli(arguments_, dependencies);
  if (exitCode !== 0) {
    throw new Error(`Acceptance command failed with exit code ${String(exitCode)}.`);
  }
  terminal?.input.destroy();
  return { stdout: stdout.value(), stderr: stderr.value() };
}

function scriptedSecrets(
  values: readonly string[],
  terminalOutput: (() => string) | undefined,
): SecretInputPort {
  let index = 0;
  return {
    read: (request) => {
      if (!request.fromStdin)
        throw new Error('Acceptance unexpectedly requested masked input.');
      const value = values[index];
      index += 1;
      if (value === undefined)
        throw new Error('Acceptance secret input was incomplete.');
      return Promise.resolve(acquiredSecretSchema.parse(value));
    },
    readBatch: (request) => {
      if (request.kinds.length === 2 && request.kinds[0] === 'portable-key') {
        const output = terminalOutput?.() ?? '';
        const portable = /Portable key: ([^\r\n]+)/u.exec(output)?.[1];
        const recovery = /Recovery key: ([^\r\n]+)/u.exec(output)?.[1];
        if (portable === undefined || recovery === undefined) {
          throw new Error('Acceptance initialization material was not displayed.');
        }
        return Promise.resolve([
          acquiredSecretSchema.parse(portable),
          acquiredSecretSchema.parse(recovery),
        ]);
      }
      return Promise.reject(new Error('Acceptance secret batch was unexpected.'));
    },
  };
}

class FakeTtyInput extends PassThrough {
  readonly isTTY = true;
  isRaw = false;

  setRawMode(enabled: boolean): void {
    this.isRaw = enabled;
  }
}

function interactiveTerminal(): Readonly<{
  input: FakeTtyInput;
  output: CapturedOutput;
}> {
  const input = new FakeTtyInput();
  const output = capture(true, (value) => {
    if (value.includes('Type saved and press Enter')) input.write('saved\n');
  });
  return { input, output };
}

type CapturedOutput = Readonly<{
  stream: Writable;
  value: () => string;
}>;

function capture(isTTY: boolean, onWrite?: (value: string) => void): CapturedOutput {
  let content = '';
  const stream = new Writable({
    write(chunk, _encoding, callback) {
      const value = Buffer.from(chunk).toString('utf8');
      content += value;
      onWrite?.(value);
      callback();
    },
  }) as Writable & { isTTY?: boolean };
  if (isTTY) stream.isTTY = true;
  return { stream, value: () => content };
}

async function treeContains(root: string, needle: string): Promise<boolean> {
  const visit = async (directory: string): Promise<boolean> => {
    for (const entry of await readdir(directory, { withFileTypes: true })) {
      const path = resolve(directory, entry.name);
      if (entry.isDirectory() && (await visit(path))) return true;
      if (entry.isFile()) {
        const bytes = await readFile(path);
        try {
          if (bytes.includes(Buffer.from(needle, 'utf8'))) return true;
        } finally {
          bytes.fill(0);
        }
      }
    }
    return false;
  };
  return visit(root);
}
