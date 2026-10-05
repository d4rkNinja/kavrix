import { createRequire } from 'node:module';
import { pathToFileURL } from 'node:url';
import { Worker } from 'node:worker_threads';
import type { SetupToolResult } from '@kavrix/schemas';
import { assertMongoUriAllowed } from './mongo-local-vault.js';

type ConnectionStatus = Extract<SetupToolResult, { kind: 'connection' }>['status'];
// Fixed worker code, never interpolated with user input. A worker provides a
// hard lifetime bound including driver SRV DNS and authentication mechanisms.
// URI strings stay in memory; no arguments, environment, files, or logs.
const probeWorker = `
const { parentPort, workerData } = require('node:worker_threads');
(async () => {
  let client;
  let status = 'unreachable';
  try {
    const { MongoClient } = await import(workerData.driver);
    client = new MongoClient(workerData.uri, {
      serverSelectionTimeoutMS: 5000, connectTimeoutMS: 5000,
      socketTimeoutMS: 10000, timeoutMS: 10000, maxPoolSize: 1,
      mongodbLogPath: 'stderr', mongodbLogComponentSeverities: { default: 'off' }
    });
    await client.connect();
    await client.db(workerData.database).command({ ping: 1 });
    status = 'ok';
  } catch (error) {
    status = error && error.code === 18 ? 'authentication' : 'unreachable';
  } finally {
    if (client) {
      try { await client.close(); } catch { status = 'unreachable'; }
    }
  }
  parentPort.postMessage(status);
})().catch(() => parentPort.postMessage('unreachable'));
`;
/** Read-only authentication/connectivity check; never reads or creates vault records. */
export async function probeMongoConnection(
  uri: string,
  database: string,
): Promise<ConnectionStatus> {
  let checkedUri = uri;
  try {
    const parsed = new URL(uri);
    if (
      !['mongodb:', 'mongodb+srv:'].includes(parsed.protocol) ||
      !database ||
      database.length > 128 ||
      /[/\\. "$\0]/u.test(database)
    )
      return 'invalid';
    // The reviewed driver defaults SRV connections to TLS. Make that default
    // explicit for the shared transport policy; an explicit insecure option
    // still fails before worker creation.
    if (
      parsed.protocol === 'mongodb+srv:' &&
      !Array.from(parsed.searchParams.keys()).some((name) =>
        ['tls', 'ssl'].includes(name.toLowerCase()),
      )
    ) {
      parsed.searchParams.set('tls', 'true');
      checkedUri = parsed.href;
    }
  } catch {
    return 'invalid';
  }
  try {
    assertMongoUriAllowed(checkedUri);
  } catch {
    return 'transport';
  }
  let worker: Worker;
  try {
    worker = new Worker(probeWorker, {
      eval: true,
      execArgv: [],
      stdout: true,
      stderr: true,
      workerData: {
        uri: checkedUri,
        database,
        driver: pathToFileURL(createRequire(import.meta.url).resolve('mongodb')).href,
      },
    });
  } catch {
    return 'unreachable';
  }
  // Drain privately. Driver/worker diagnostics can contain connection secrets.
  worker.stdout.resume();
  worker.stderr.resume();
  const status = await new Promise<ConnectionStatus>((resolve) => {
    const finish = (result: ConnectionStatus): void => {
      clearTimeout(timer);
      resolve(result);
    };
    const timer = setTimeout(() => {
      finish('unreachable');
    }, 15000);
    worker.once('message', (value: unknown) => {
      finish(value === 'ok' || value === 'authentication' ? value : 'unreachable');
    });
    worker.once('error', () => {
      finish('unreachable');
    });
    worker.once('exit', () => {
      finish('unreachable');
    });
  });
  try {
    await worker.terminate();
  } catch {
    return 'unreachable';
  }
  return status;
}
