import { spawn, type ChildProcessByStdio } from 'node:child_process';
import { createServer } from 'node:net';
import type { Readable } from 'node:stream';
import { fileURLToPath } from 'node:url';

import { deviceIdSchema, type VaultBootstrapRequest } from '@kavrix/schemas';
import { MongoClient } from 'mongodb';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';

import { assertMongoApiDatabaseCompatibility } from '../src/mongo-operations.js';
import { MongoBackupSource } from '@kavrix/storage';
import {
  attachmentChunk,
  attachmentFinalize,
  attachmentStart,
  groupRecord,
  itemRecord,
  mutation,
  vaultRecord,
} from '../../../packages/storage/test/fixtures.js';

const mongodbUri = process.env['KAVRIX_MONGODB_URI'];
const databaseName = process.env['KAVRIX_DATABASE_NAME'];
const acceptanceToken = Buffer.alloc(32).toString('base64url');
const maxCapturedProcessOutputBytes = 1 * 1024 * 1024;
const processStartupTimeoutMs = 15_000;
const processShutdownTimeoutMs = 15_000;

interface RunningApiProcess {
  readonly child: ChildProcessByStdio<null, Readable, Readable>;
  readonly output: ProcessOutput;
  readonly port: number;
}

class ProcessOutput {
  readonly #chunks: Buffer[] = [];
  #bytes = 0;
  #exceeded = false;

  public append(chunk: Buffer): void {
    if (this.#exceeded) return;
    this.#bytes += chunk.byteLength;
    if (this.#bytes > maxCapturedProcessOutputBytes) {
      this.#exceeded = true;
      return;
    }
    this.#chunks.push(chunk);
  }

  public text(): string {
    return Buffer.concat(this.#chunks).toString('utf8');
  }

  public exceeded(): boolean {
    return this.#exceeded;
  }
}

interface HttpResult {
  readonly body: unknown;
  readonly status: number;
}

describe('Mongo operational acceptance', () => {
  const processes: RunningApiProcess[] = [];
  let client: MongoClient | undefined;

  beforeAll(async () => {
    const uri = requireEnvironment(mongodbUri, 'KAVRIX_MONGODB_URI');
    const name = requireEnvironment(databaseName, 'KAVRIX_DATABASE_NAME');
    client = new MongoClient(uri, {
      appName: 'kavrix-operational-acceptance',
    });
    await client.connect();

    const hello = await client.db('admin').command({ hello: 1 });
    expect(typeof hello['setName']).toBe('string');
    expect(hello['setName']).not.toBe('');
    expect(typeof hello['logicalSessionTimeoutMinutes']).toBe('number');
    expect(hello['logicalSessionTimeoutMinutes']).toBeGreaterThan(0);
    await assertMongoApiDatabaseCompatibility(client.db(name));
  });

  afterAll(async () => {
    for (const process of processes) {
      await stopApiProcess(process);
    }
    if (client !== undefined) {
      const name = requireEnvironment(databaseName, 'KAVRIX_DATABASE_NAME');
      await client.db(name).dropDatabase();
      await client.close();
    }
  });

  it('runs the production API contract across two processes', async () => {
    const name = requireEnvironment(databaseName, 'KAVRIX_DATABASE_NAME');
    const firstPort = await availablePort();
    const secondPort = await availablePort();
    processes.push(startApiProcess(firstPort, name));
    processes.push(startApiProcess(secondPort, name));

    await Promise.all(processes.map((process) => waitForReady(process)));
    for (const process of processes) {
      const health = await request(process.port, '/health');
      expect(health.status).toBe(200);
      expect(health.body).toEqual({ status: 'ok' });
      const readiness = await request(process.port, '/ready');
      expect(readiness.status).toBe(200);
      expect(readiness.body).toEqual({ status: 'ready' });
    }

    const vault = vaultRecord(0);
    const bootstrap = await request(firstPort, '/v1/vaults', {
      body: bootstrapBody(vault),
      method: 'POST',
    });
    expect(bootstrap.status).toBe(201);
    expect(bootstrap.body).toEqual({
      vaultId: vault.id,
      deviceId: 'device.1',
    });

    const session = await request(secondPort, '/v1/session');
    expect(session.status).toBe(200);
    expect(session.body).toEqual({
      vaultId: vault.id,
      deviceId: 'device.1',
      scopes: ['sync:read', 'sync:write', 'device:manage'],
    });

    const initialSync = await request(
      secondPort,
      `/v1/vaults/${vault.id}/sync?serverSequence=0&highestSeenVaultRevision=0&limit=10`,
    );
    expect(initialSync.status).toBe(200);
    expect(initialSync.body).toMatchObject({
      vaultId: vault.id,
      serverVaultRevision: 0,
      hasMore: false,
    });

    const group = groupRecord();
    const item = itemRecord();
    const syncPush = await request(secondPort, `/v1/vaults/${vault.id}/sync`, {
      body: {
        vaultId: vault.id,
        batchIdempotencyKey: 'operational-sync-batch-0001',
        mutations: [
          mutation('group', group, null, 'operational-group-0001'),
          mutation('item', item, null, 'operational-item-0001'),
        ],
      },
      method: 'POST',
    });
    expect(syncPush.status).toBe(200);

    const start = attachmentStart();
    const attachmentPath = `/v1/vaults/${vault.id}/groups/${group.id}/items/${item.id}/attachments/${
      attachmentFinalize().record.id
    }`;
    const opened = await request(secondPort, `${attachmentPath}/stream/open`, {
      body: start,
      method: 'POST',
    });
    expect(opened.status).toBe(200);

    const firstChunk = await request(secondPort, `${attachmentPath}/stream/chunks/0`, {
      body: { start, chunk: attachmentChunk(0, 'message') },
      method: 'PUT',
    });
    expect(firstChunk.status).toBe(200);
    const finalChunk = await request(secondPort, `${attachmentPath}/stream/chunks/1`, {
      body: { start, chunk: attachmentChunk(1, 'final') },
      method: 'PUT',
    });
    expect(finalChunk.status).toBe(200);
    const finalized = await request(secondPort, `${attachmentPath}/stream/finalize`, {
      body: { start, finalize: attachmentFinalize() },
      method: 'POST',
    });
    expect(finalized.status).toBe(204);
    const attachment = await request(secondPort, attachmentPath);
    expect(attachment.status).toBe(200);

    const activeClient = client;
    if (activeClient === undefined) throw new Error('MongoDB client is unavailable.');
    const backupSource = new MongoBackupSource(activeClient, activeClient.db(name));
    const snapshot = await backupSource.open(vault.id);
    const entryKinds: string[] = [];
    try {
      for await (const entry of snapshot.records) entryKinds.push(entry.kind);
    } finally {
      await snapshot.close();
    }
    expect(entryKinds).toEqual(
      expect.arrayContaining([
        'group',
        'item',
        'attachment',
        'attachment-header',
        'attachment-chunk',
      ]),
    );

    for (const process of processes) {
      expect(process.output.exceeded()).toBe(false);
      const output = process.output.text();
      expect(output).not.toContain(uriValue());
      expect(output).not.toContain('plaintext-storage-canary');
    }
  });
});

function startApiProcess(port: number, name: string): RunningApiProcess {
  const output = new ProcessOutput();
  const child = spawn(
    process.execPath,
    [fileURLToPath(new URL('../dist/main.js', import.meta.url))],
    {
      cwd: workspaceRoot(),
      env: {
        ...process.env,
        KAVRIX_DATABASE_NAME: name,
        KAVRIX_API_ENVIRONMENT: 'production',
        KAVRIX_API_HOST: '127.0.0.1',
        KAVRIX_API_PORT: String(port),
        KAVRIX_API_TRUSTED_PROXIES: '127.0.0.1',
        KAVRIX_API_BOOTSTRAP_ENABLED: 'true',
      },
      shell: false,
      stdio: ['ignore', 'pipe', 'pipe'],
      windowsHide: true,
    },
  );
  child.stdout.on('data', (chunk: Buffer) => {
    output.append(chunk);
  });
  child.stderr.on('data', (chunk: Buffer) => {
    output.append(chunk);
  });
  return { child, output, port };
}

async function waitForReady(process: RunningApiProcess): Promise<void> {
  const deadline = Date.now() + processStartupTimeoutMs;
  while (Date.now() < deadline) {
    if (process.child.exitCode !== null || process.child.signalCode !== null) {
      throw new Error('The API process exited before readiness.');
    }
    try {
      const response = await request(process.port, '/ready');
      if (response.status === 200) return;
    } catch {
      // The listener may not exist yet.
    }
    await delay(50);
  }
  throw new Error('The API process did not become ready.');
}

async function stopApiProcess(apiProcess: RunningApiProcess): Promise<void> {
  if (apiProcess.child.exitCode === null && apiProcess.child.signalCode === null) {
    apiProcess.child.kill('SIGTERM');
  }
  const result = await waitForClose(apiProcess.child, processShutdownTimeoutMs);
  if (!result.closed) {
    apiProcess.child.kill('SIGKILL');
    await waitForClose(apiProcess.child, 2_000);
    throw new Error('The API process did not stop safely.');
  }
  if (globalThis.process.platform === 'win32') {
    if (
      apiProcess.child.exitCode === null &&
      apiProcess.child.signalCode === 'SIGTERM'
    ) {
      return;
    }
  } else if (apiProcess.child.exitCode === 0 && apiProcess.child.signalCode === null) {
    return;
  }
  throw new Error('The API process stopped with a failure.');
}

function waitForClose(
  child: ChildProcessByStdio<null, Readable, Readable>,
  timeoutMs: number,
): Promise<{ readonly closed: boolean }> {
  if (child.exitCode !== null || child.signalCode !== null) {
    return Promise.resolve({ closed: true });
  }
  return new Promise((resolve) => {
    const timer = setTimeout(() => {
      resolve({ closed: false });
    }, timeoutMs);
    child.once('close', () => {
      clearTimeout(timer);
      resolve({ closed: true });
    });
  });
}

async function request(
  port: number,
  path: string,
  options: { readonly body?: unknown; readonly method?: string } = {},
): Promise<HttpResult> {
  const headers: Record<string, string> = {
    'x-forwarded-proto': 'https',
  };
  if (options.body !== undefined) {
    headers['content-type'] = 'application/json';
  }
  headers['authorization'] = `Bearer ${acceptanceToken}`;
  const init: RequestInit = {
    method: options.method ?? 'GET',
    headers,
  };
  if (options.body !== undefined) init.body = JSON.stringify(options.body);
  const response = await fetch(`http://127.0.0.1:${String(port)}${path}`, init);
  const text = await response.text();
  let body: unknown = undefined;
  if (text.length > 0) {
    try {
      body = JSON.parse(text) as unknown;
    } catch {
      body = text;
    }
  }
  return { body, status: response.status };
}

function bootstrapBody(vault: ReturnType<typeof vaultRecord>): VaultBootstrapRequest {
  return {
    vault,
    device: {
      id: deviceIdSchema.parse('device.1'),
      schemaVersion: vault.schemaVersion,
    },
  } satisfies VaultBootstrapRequest;
}

async function availablePort(): Promise<number> {
  const server = createServer();
  return new Promise((resolve, reject) => {
    server.once('error', reject);
    server.listen(0, '127.0.0.1', () => {
      const address = server.address();
      if (address === null || typeof address === 'string') {
        server.close();
        reject(new Error('Failed to allocate an acceptance port.'));
        return;
      }
      server.close((error) => {
        if (error === undefined) resolve(address.port);
        else reject(error);
      });
    });
  });
}

function requireEnvironment(value: string | undefined, name: string): string {
  if (value === undefined || value.trim().length === 0) {
    throw new Error(`${name} is required.`);
  }
  return value;
}

function uriValue(): string {
  return requireEnvironment(mongodbUri, 'KAVRIX_MONGODB_URI');
}

function workspaceRoot(): string {
  return fileURLToPath(new URL('../../../', import.meta.url));
}

function delay(milliseconds: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, milliseconds));
}
