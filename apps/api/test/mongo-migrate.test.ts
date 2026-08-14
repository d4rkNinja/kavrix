import { readFileSync } from 'node:fs';

import type { Db, MongoClient } from 'mongodb';
import { describe, expect, it, vi } from 'vitest';

import {
  mongoMigrationExitCode,
  runMongoMigration,
  type MongoMigrationRuntime,
} from '../scripts/mongo-migrate.js';
import type { MongoSchemaStateDocument } from '../src/mongo-operations.js';

const scriptSource = readFileSync(
  new URL('../scripts/mongo-migrate.ts', import.meta.url),
  'utf8',
);

describe('Mongo migration command', () => {
  it('uses protected environment input and generic output boundaries', () => {
    expect(scriptSource).toContain('parseMongoApiServiceEnvironment');
    expect(scriptSource).toContain('process.env');
    expect(scriptSource).not.toContain('process.argv.slice');
    expect(scriptSource).not.toContain('error.message');
    expect(scriptSource).not.toContain('error.stack');
    expect(scriptSource).toContain('[kavrix-api] migration complete');
    expect(scriptSource).toContain('[kavrix-api] migration failed');
  });

  it('returns EX_CONFIG without constructing a client for invalid input', async () => {
    const createClient = vi.fn();
    const output = captureOutput();

    await expect(
      runMongoMigration({}, runtime({ createClient, output })),
    ).resolves.toBe(mongoMigrationExitCode.invalidConfiguration);
    expect(createClient).not.toHaveBeenCalled();
    expect(output.text()).toBe('[kavrix-api] migration configuration invalid\n');
  });

  it('redacts connection failures and closes the client', async () => {
    const output = captureOutput();
    const secretUri = 'mongodb://operator:plaintext-canary@db.invalid/kavrix';
    const close = vi.fn(() => Promise.resolve());
    const client = {
      connect: vi.fn(() => Promise.reject(new Error(`failed ${secretUri}`))),
      close,
    } as unknown as MongoClient;

    await expect(
      runMongoMigration(
        { KAVRIX_MONGODB_URI: secretUri },
        runtime({ createClient: () => client, output }),
      ),
    ).resolves.toBe(mongoMigrationExitCode.runtimeFailure);
    expect(close).toHaveBeenCalledOnce();
    expect(output.text()).toBe('[kavrix-api] migration failed\n');
    expect(output.text()).not.toContain(secretUri);
    expect(output.text()).not.toContain('plaintext-canary');
  });
});

function runtime(overrides: Partial<MongoMigrationRuntime>): MongoMigrationRuntime {
  return {
    createClient: () =>
      ({
        connect: () => Promise.resolve(),
        db: () => ({}) as Db,
        close: () => Promise.resolve(),
      }) as unknown as MongoClient,
    output: captureOutput(),
    migrate: (): Promise<MongoSchemaStateDocument> =>
      Promise.resolve({
        _id: 'kavrix',
        schemaVersion: 1,
        migrationId: 'baseline-contracts-v1',
        appliedAt: '2026-08-14T00:00:00.000Z',
      }),
    ...overrides,
  };
}

function captureOutput(): {
  stdout(message: string): void;
  stderr(message: string): void;
  text(): string;
} {
  const messages: string[] = [];
  return {
    stdout: (message) => messages.push(message),
    stderr: (message) => messages.push(message),
    text: () => messages.join(''),
  };
}
