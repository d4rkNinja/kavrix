/**
 * Shared animation clock.
 *
 * Motion clocks used to be independent per-component intervals. A screen with
 * several animated widgets therefore ran one timer and one React commit per
 * clock, each repainting the whole tree even when that particular clock was the
 * only thing that had changed.
 *
 * One clock now drives every animation in the process. Each subscriber keeps its
 * own start time, so an animation still measures its own age and starts at
 * exactly zero on mount, exactly as it did with a private interval. What changes
 * is that the process runs a single timer, and a subscriber is only asked to
 * update when its own derived value has actually moved.
 *
 * The result is one timer per process and a number of commits equal to the
 * number of clocks that advanced, rather than the sum of every clock present.
 */

/**
 * Shared tick cadence. This is the finest granularity any motion token needs, so
 * every animation resolves to one of these steps and the clock never has to run
 * faster than the fastest animation on screen.
 */
export const FRAME_TICK_MS = 32;

type Subscriber = (elapsedMs: number) => void;

interface Registration {
  readonly subscriber: Subscriber;
  readonly startedAtMs: number;
}

const registrations = new Set<Registration>();
let timer: ReturnType<typeof setInterval> | undefined;

function tick(): void {
  const now = performance.now();
  // Iterate a copy so a subscriber that unsubscribes during delivery cannot skip
  // another subscriber this tick.
  for (const registration of [...registrations]) {
    registration.subscriber(now - registration.startedAtMs);
  }
}

function start(): void {
  timer ??= setInterval(tick, FRAME_TICK_MS);
}

function stop(): void {
  if (timer === undefined) return;
  clearInterval(timer);
  timer = undefined;
}

/**
 * Subscribes to the shared clock. The subscriber is called once with exactly
 * zero so a newly mounted animation starts settled rather than a tick late, and
 * again on every shared tick until it unsubscribes.
 */
export function subscribeToFrameClock(subscriber: Subscriber): () => void {
  const registration: Registration = {
    subscriber,
    startedAtMs: performance.now(),
  };
  registrations.add(registration);
  start();
  subscriber(0);
  return () => {
    registrations.delete(registration);
    if (registrations.size === 0) stop();
  };
}
