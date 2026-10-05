/** Match synthetic input readiness to a committed Ink frame, not just regions. */
export function createInputReadiness(getFrame: () => number): {
  readonly painted: () => void;
  readonly wait: () => Promise<void>;
  readonly dispose: () => void;
} {
  let paintedFrame = -1;
  let disposed = false;
  const waiters = new Set<() => void>();
  const settle = (): void => {
    for (const resolve of waiters) resolve();
    waiters.clear();
  };
  return {
    painted: () => {
      paintedFrame = getFrame();
      settle();
    },
    wait: async () => {
      while (!disposed && paintedFrame !== getFrame()) {
        await new Promise<void>((resolve) => waiters.add(resolve));
      }
    },
    dispose: () => {
      disposed = true;
      settle();
    },
  };
}
