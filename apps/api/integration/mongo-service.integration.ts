import { randomUUID } from 'node:crypto';
import { createServer } from 'node:net';

import { MongoClient } from 'mongodb';
import { describe, expect, it } from 'vitest';

import { migrateMongoApiDatabase } from '../src/mongo-operations.js';
import { apiServiceExitCode, runMongoApiService } from '../src/service.js';
import { startMongoApiServer } from '../src/server.js';

const mongodbUri = process.env['KAVRIX_MONGODB_URI'];
const describeMongo =
  mongodbUri === undefined || mongodbUri.length === 0 ? describe.skip : describe;

class IntegrationSignals {
  readonly #listeners = new Map<'SIGINT' | 'SIGTERM', Set<() => void>>();

  public on(signal: 'SIGINT' | 'SIGTERM', listener: () => void): void {
    const listeners = this.#listeners.get(signal) ?? new Set();
    listeners.add(listener);
    this.#listeners.set(signal, listeners);
  }

  public off(signal: 'SIGINT' | 'SIGTERM', listener: () => void): void {
    this.#listeners.get(signal)?.delete(listener);
  }

  public send(signal: 'SIGINT' | 'SIGTERM'): void {
    for (const listener of this.#listeners.get(signal) ?? []) listener();
  }
}

describeMongo('Mongo API service process composition', () => {
  it('starts, serves liveness, and gracefully closes against a real replica set', async () => {
    const uri = requireMongoUri();
    const databaseName = `kavrix_service_test_${randomUUID().replaceAll('-', '')}`;
    const port = await availablePort();
    const migrationClient = new MongoClient(uri, {
      appName: 'kavrix-service-test-migrator',
    });
    await migrationClient.connect();
    try {
      await migrateMongoApiDatabase(migrationClient.db(databaseName));
    } finally {
      await migrationClient.close();
    }
    const signals = new IntegrationSignals();
    const output: string[] = [];
    const running = runMongoApiService({
      environment: {
        KAVRIX_MONGODB_URI: uri,
        KAVRIX_DATABASE_NAME: databaseName,
        KAVRIX_API_ENVIRONMENT: 'test',
        KAVRIX_API_HOST: '127.0.0.1',
        KAVRIX_API_PORT: String(port),
      },
      signals,
      output: {
        write: (message) => {
          output.push(message);
        },
      },
      startServer: startMongoApiServer,
    });

    try {
      const response = await waitForHealth(`http://127.0.0.1:${String(port)}/health`);
      expect(response.status).toBe(200);
      await expect(response.json()).resolves.toEqual({ status: 'ok' });
    } finally {
      signals.send('SIGTERM');
    }

    await expect(running).resolves.toBe(apiServiceExitCode.success);
    expect(output.join('')).toBe(
      '[kavrix-api] started\n[kavrix-api] shutdown requested\n[kavrix-api] stopped\n',
    );

    const cleanup = new MongoClient(uri, { appName: 'kavrix-service-test-cleanup' });
    await cleanup.connect();
    await cleanup.db(databaseName).dropDatabase();
    await cleanup.close();
  });
});

async function availablePort(): Promise<number> {
  const server = createServer();
  return new Promise((resolve, reject) => {
    server.once('error', reject);
    server.listen(0, '127.0.0.1', () => {
      const address = server.address();
      if (address === null || typeof address === 'string') {
        server.close();
        reject(new Error('Failed to allocate an integration port'));
        return;
      }
      server.close((error) => {
        if (error === undefined) resolve(address.port);
        else reject(error);
      });
    });
  });
}

async function waitForHealth(url: string): Promise<Response> {
  const deadline = Date.now() + 15_000;
  while (Date.now() < deadline) {
    try {
      const response = await fetch(url);
      if (response.ok) return response;
    } catch (error) {
      if (!(error instanceof TypeError)) throw error;
    }
    await new Promise((resolve) => setTimeout(resolve, 50));
  }
  throw new Error('The Mongo API service did not become healthy');
}

function requireMongoUri(): string {
  if (mongodbUri === undefined || mongodbUri.length === 0) {
    throw new Error('KAVRIX_MONGODB_URI is required');
  }
  return mongodbUri;
}
