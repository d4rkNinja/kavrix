import type { ClockPort } from '@kavrix/core';
import {
  assertMongoStorageCompatibility,
  installMongoStorageContracts,
  MongoVaultStorage,
} from '@kavrix/storage';
import type { FastifyInstance } from 'fastify';
import { MongoClient } from 'mongodb';
import { z } from 'zod';

import { buildApi, type BuildApiOptions } from './app.js';
import { NodeInviteIdPort } from './invite-id.js';
import {
  assertMongoApiCompatibility,
  installMongoApiContracts,
  MongoAuthorizationPort,
  MongoVaultBootstrapPort,
} from './mongo-persistence.js';
import { assertMongoApiDatabaseCompatibility } from './mongo-operations.js';
import { MongoRateLimitPort } from './mongo-rate-limit.js';
import { NodeTokenPort } from './token.js';

const mongoApiServerConfigSchema = z
  .object({
    mongodbUri: z
      .string()
      .min(1)
      .max(4_096)
      .regex(/^mongodb(?:\+srv)?:\/\//u, 'A MongoDB connection URI is required'),
    databaseName: z
      .string()
      .min(1)
      .max(64)
      .regex(/^[^/\\. "$*<>:|?]+$/u, 'Invalid MongoDB database name'),
    environment: z.enum(['development', 'production', 'test']),
    host: z.string().min(1).max(253).default('127.0.0.1'),
    port: z.number().int().min(1).max(65_535).default(3_000),
    trustedProxy: z.union([z.string(), z.array(z.string()).min(1)]).optional(),
    bodyLimit: z.number().int().positive().optional(),
    vaultBootstrapEnabled: z.boolean().optional(),
  })
  .strict();

export type MongoApiServerConfig = z.infer<typeof mongoApiServerConfigSchema>;

export type MongoApiServerSchemaMode = 'validate' | 'install';

export interface MongoApiServerOptions {
  readonly schemaMode?: MongoApiServerSchemaMode;
}

export interface MongoApiServer {
  readonly app: FastifyInstance;
  readonly config: MongoApiServerConfig;
  close(): Promise<void>;
}

export interface StartedMongoApiServer extends MongoApiServer {
  readonly address: string;
}

export interface MongoApiServerRuntime {
  createClient(uri: string): MongoClient;
  buildApi(options: BuildApiOptions): FastifyInstance;
}

const defaultMongoApiServerRuntime: MongoApiServerRuntime = {
  createClient: (uri) =>
    new MongoClient(uri, {
      appName: 'kavrix-api',
    }),
  buildApi,
};

export function parseMongoApiServerConfig(input: unknown): MongoApiServerConfig {
  return mongoApiServerConfigSchema.parse(input);
}

/**
 * Builds the production composition without accepting or owning HTTP TLS keys.
 * Deploy direct TLS outside this factory or configure explicit trusted proxy ranges.
 */
export async function createMongoApiServer(
  input: MongoApiServerConfig,
  runtime: MongoApiServerRuntime = defaultMongoApiServerRuntime,
  options: MongoApiServerOptions = {},
): Promise<MongoApiServer> {
  const config = parseMongoApiServerConfig(input);
  const client = runtime.createClient(config.mongodbUri);
  try {
    await client.connect();
    const database = client.db(config.databaseName);
    if (options.schemaMode === 'install') {
      await installMongoStorageContracts(database);
      await installMongoApiContracts(database);
      await assertMongoStorageCompatibility(database);
      await assertMongoApiCompatibility(database);
    } else {
      await assertMongoApiDatabaseCompatibility(database);
    }
    const storage = new MongoVaultStorage(client, database);
    const authorization = new MongoAuthorizationPort(client, database);
    const app = runtime.buildApi({
      ports: {
        storage,
        authorization,
        tokens: new NodeTokenPort(),
        rateLimits: new MongoRateLimitPort(database),
        clock: new SystemClockPort(),
        inviteIds: new NodeInviteIdPort(),
        bootstrap: new MongoVaultBootstrapPort(client, database),
      },
      environment: config.environment,
      ...(config.trustedProxy === undefined
        ? {}
        : { trustedProxy: config.trustedProxy }),
      ...(config.bodyLimit === undefined ? {} : { bodyLimit: config.bodyLimit }),
      vaultBootstrapEnabled: config.vaultBootstrapEnabled === true,
      readiness: async () => {
        try {
          await database.command({ ping: 1 });
          return true;
        } catch {
          return false;
        }
      },
    });
    app.addHook('onClose', async () => client.close());
    return {
      app,
      config,
      close: async () => app.close(),
    };
  } catch (error) {
    await client.close();
    throw error;
  }
}

export async function startMongoApiServer(
  input: MongoApiServerConfig,
): Promise<StartedMongoApiServer> {
  const server = await createMongoApiServer(input, defaultMongoApiServerRuntime, {
    schemaMode: 'validate',
  });
  try {
    const address = await server.app.listen({
      host: server.config.host,
      port: server.config.port,
    });
    return { ...server, address };
  } catch (error) {
    await server.close();
    throw error;
  }
}

class SystemClockPort implements ClockPort {
  public now(): Date {
    return new Date();
  }
}
