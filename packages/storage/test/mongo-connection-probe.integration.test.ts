import { randomBytes } from 'node:crypto';
import { MongoClient } from 'mongodb';
import { describe, expect, it } from 'vitest';
import { probeMongoConnection } from '../src/mongo-connection-probe.js';

const uri = process.env['KAVRIX_MONGODB_URI'];
const integration = uri === undefined ? describe.skip : describe;
integration('real MongoDB connection probe', () => {
  it('authenticates and pings without creating collections or a database', async () => {
    const database = `kavrix_probe_${randomBytes(16).toString('hex')}`;
    expect(await probeMongoConnection(uri as string, database)).toBe('ok');
    const inspection = new MongoClient(uri as string, {
      serverSelectionTimeoutMS: 5000,
      timeoutMS: 10000,
    });
    try {
      const collections = await inspection.db(database).listCollections().toArray();
      expect(collections).toEqual([]);
      const databases = await inspection.db('admin').admin().listDatabases();
      expect(databases.databases.some((entry) => entry.name === database)).toBe(false);
    } finally {
      await inspection.close();
    }
  });
});

it('runs the actual isolated driver and classifies a refused local connection without leaking diagnostics', async () => {
  const result = await probeMongoConnection('mongodb://127.0.0.1:1/test', 'test');
  expect(result).toBe('unreachable');
});
