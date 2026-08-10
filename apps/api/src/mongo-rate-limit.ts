import { createHash } from 'node:crypto';

import type { Db } from 'mongodb';

import {
  mongoApiCollectionNames,
  mongoApiRateLimitDocumentSchema,
  type MongoApiRateLimitDocument,
} from './mongo-documents.js';
import type { RateLimitAttempt, RateLimitPort } from './ports.js';

export interface FixedWindowIdentity {
  readonly id: string;
  readonly windowStartedAt: Date;
  readonly expiresAt: Date;
}

export function fixedWindowIdentity(attempt: RateLimitAttempt): FixedWindowIdentity {
  if (
    !Number.isSafeInteger(attempt.limit) ||
    attempt.limit < 1 ||
    !Number.isSafeInteger(attempt.windowSeconds) ||
    attempt.windowSeconds < 1 ||
    !Number.isFinite(attempt.now.getTime())
  ) {
    throw new Error('Invalid rate-limit attempt');
  }
  const windowMilliseconds = attempt.windowSeconds * 1_000;
  const windowStart =
    Math.floor(attempt.now.getTime() / windowMilliseconds) * windowMilliseconds;
  const keyDigest = createHash('sha256')
    .update(String(attempt.windowSeconds), 'ascii')
    .update('\0', 'ascii')
    .update(attempt.key, 'utf8')
    .digest('hex');
  return {
    id: `${keyDigest}:${String(windowStart)}`,
    windowStartedAt: new Date(windowStart),
    expiresAt: new Date(windowStart + windowMilliseconds),
  };
}

export class MongoRateLimitPort implements RateLimitPort {
  readonly #database: Db;

  public constructor(database: Db) {
    this.#database = database;
  }

  public async consume(attempt: RateLimitAttempt): Promise<boolean> {
    const window = fixedWindowIdentity(attempt);
    const value = await this.#database
      .collection<MongoApiRateLimitDocument>(mongoApiCollectionNames.rateLimits)
      .findOneAndUpdate(
        { _id: window.id },
        {
          $inc: { count: 1 },
          $setOnInsert: {
            windowStartedAt: window.windowStartedAt,
            expiresAt: window.expiresAt,
          },
        },
        { upsert: true, returnDocument: 'after' },
      );
    if (value === null) throw new Error('Rate limit counter update failed');
    return mongoApiRateLimitDocumentSchema.parse(value).count <= attempt.limit;
  }
}
