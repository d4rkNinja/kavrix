import { resolve } from 'node:path';
import { pathToFileURL } from 'node:url';

import { MongoClient, type Db } from 'mongodb';

import {
  migrateMongoApiDatabase,
  type MongoSchemaStateDocument,
} from '../src/mongo-operations.js';
import { parseMongoApiServiceEnvironment } from '../src/service-environment.js';

export const mongoMigrationExitCode = {
  success: 0,
  runtimeFailure: 1,
  invalidConfiguration: 78,
} as const;

export interface MongoMigrationOutput {
  stdout(message: string): void;
  stderr(message: string): void;
}

export interface MongoMigrationRuntime {
  createClient(uri: string): MongoClient;
  output: MongoMigrationOutput;
  migrate(database: Db): Promise<MongoSchemaStateDocument>;
}

const defaultRuntime: MongoMigrationRuntime = {
  createClient: (uri) => new MongoClient(uri, { appName: 'kavrix-api-migrator' }),
  output: {
    stdout: (message) => process.stdout.write(message),
    stderr: (message) => process.stderr.write(message),
  },
  migrate: migrateMongoApiDatabase,
};

export async function runMongoMigration(
  environment: Readonly<Record<string, string | undefined>> = process.env,
  runtime: MongoMigrationRuntime = defaultRuntime,
): Promise<number> {
  let config;
  try {
    config = parseMongoApiServiceEnvironment(environment).server;
  } catch {
    runtime.output.stderr('[kavrix-api] migration configuration invalid\n');
    return mongoMigrationExitCode.invalidConfiguration;
  }

  let client: MongoClient | undefined;
  let exitCode: number = mongoMigrationExitCode.runtimeFailure;
  try {
    client = runtime.createClient(config.mongodbUri);
    await client.connect();
    await runtime.migrate(client.db(config.databaseName));
    runtime.output.stdout('[kavrix-api] migration complete\n');
    exitCode = mongoMigrationExitCode.success;
  } catch {
    runtime.output.stderr('[kavrix-api] migration failed\n');
  } finally {
    if (client !== undefined) {
      try {
        await client.close();
      } catch {
        if (exitCode === mongoMigrationExitCode.success) {
          runtime.output.stderr('[kavrix-api] migration failed\n');
          exitCode = mongoMigrationExitCode.runtimeFailure;
        }
      }
    }
  }
  return exitCode;
}

const invokedScript = process.argv[1];
if (
  invokedScript !== undefined &&
  import.meta.url === pathToFileURL(resolve(invokedScript)).href
) {
  process.exitCode = await runMongoMigration();
}
