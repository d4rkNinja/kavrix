const tails = new Map<string, Promise<void>>();

function queueKey(service: string, account: string): string {
  return `${String(service.length)}:${service}${String(account.length)}:${account}`;
}

export function withProtectedStateQueue<Result>(
  service: string,
  account: string,
  operation: () => Promise<Result>,
): Promise<Result> {
  const key = queueKey(service, account);
  const predecessor = tails.get(key) ?? Promise.resolve();
  let release!: () => void;
  const tail = new Promise<void>((resolve) => {
    release = resolve;
  });
  tails.set(key, tail);
  return predecessor.then(operation).finally(() => {
    release();
    if (tails.get(key) === tail) tails.delete(key);
  });
}

/** Internal test seam proving settled keyed queues do not accumulate. */
export function protectedStateQueueSize(): number {
  return tails.size;
}
