/**
 * Lazy access to the MongoDB driver.
 *
 * The driver is a large module graph: parsing and evaluating it costs about
 * 100 ms and 14 MB of resident memory on the measured platform. Kavrix is
 * local-first, so the overwhelming majority of processes never open a MongoDB
 * datastore, yet every one of them was paying that cost just to import the
 * storage barrel.
 *
 * Keeping the driver's value imports behind this loader means the module graph
 * is only evaluated when a MongoDB-backed store is actually constructed. Type
 * imports stay type-only everywhere else, so nothing about the adapter's
 * contract changes and the driver's shape is still checked at compile time.
 *
 * The load is memoized: the first request resolves the driver and every later
 * request reuses that promise, so concurrent constructors share one evaluation
 * and a rejected load is not retried into a storm.
 */
import type { MongoClient, MongoServerError } from 'mongodb';

/** The runtime values the MongoDB adapters need from the driver. */
export type MongoDriver = Readonly<{
  MongoClient: typeof MongoClient;
  MongoServerError: typeof MongoServerError;
}>;

let driverPromise: Promise<MongoDriver> | undefined;

/**
 * Connection-pool bounds shared by every MongoDB adapter.
 *
 * The driver otherwise defaults to one hundred sockets per client. Kavrix is a
 * single-user, local-first CLI that opens one client and drives it from one
 * process, so that default reserves capacity nothing can use while holding
 * connections the deployment never asked for. Sixteen covers every concurrent
 * operation Kavrix issues, including the transactional collaboration paths.
 *
 * The wait queue is bounded explicitly so a burst of operations waits for a
 * socket within a known bound instead of failing immediately, and fails rather
 * than hanging forever if the bound is exceeded.
 */
export const MONGO_MAX_POOL_SIZE = 16;
export const MONGO_MIN_POOL_SIZE = 0;
export const MONGO_WAIT_QUEUE_TIMEOUT_MS = 10_000;

/**
 * Resolves the driver's runtime bindings, evaluating the driver module graph on
 * first use.
 */
export function loadMongoDriver(): Promise<MongoDriver> {
  driverPromise ??= import('mongodb').then((driver) => ({
    MongoClient: driver.MongoClient,
    MongoServerError: driver.MongoServerError,
  }));
  return driverPromise;
}
