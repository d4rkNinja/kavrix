import type { ClockPort } from '@kavrix/core';
import { MongoVaultStorage } from '@kavrix/storage';
import type { FastifyInstance } from 'fastify';
import { MongoClient } from 'mongodb';
import { z } from 'zod';

import { buildApi } from './app.js';
import { NodeInviteIdPort } from './invite-id.js';
import {
  initializeMongoApiPersistence,
  MongoAuthorizationPort,
  MongoVaultBootstrapPort,
} from './mongo-persistence.js';
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

export interface MongoApiServer {
  readonly app: FastifyInstance;
  readonly config: MongoApiServerConfig;
  close(): Promise<void>;
}

export interface StartedMongoApiServer extends MongoApiServer {
  readonly address: string;
}

export function parseMongoApiServerConfig(input: unknown): MongoApiServerConfig {
  return mongoApiServerConfigSchema.parse(input);
}

/**
 * Builds the production composition without accepting or owning HTTP TLS keys.
 * Deploy direct TLS outside this factory or configure explicit trusted proxy ranges.
 */
export async function createMongoApiServer(
  input: MongoApiServerConfig,
): Promise<MongoApiServer> {
  const config = parseMongoApiServerConfig(input);
  const client = new MongoClient(config.mongodbUri, {
    appName: 'kavrix-api',
  });
  try {
    await client.connect();
    const database = client.db(config.databaseName);
    const storage = new MongoVaultStorage(client, database);
    await storage.initialize();
    await initializeMongoApiPersistence(database);
    const authorization = new MongoAuthorizationPort(client, database);
    const app = buildApi({
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
  const server = await createMongoApiServer(input);
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
