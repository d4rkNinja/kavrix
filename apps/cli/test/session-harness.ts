import type {
  SessionClockPort,
  SessionRuntimePorts,
  SessionSignalName,
  SessionSignalPort,
  SessionTimerPort,
} from '../src/session.js';

/**
 * A monotonic clock and timer the test drives by hand, mirroring the injectable
 * scheduler the clipboard already uses. Nothing here sleeps: expiry is observed
 * by moving the clock, so deadline behaviour is deterministic rather than
 * timing-dependent.
 */
export class ManualRuntime {
  #now = 0;
  readonly #tasks = new Map<object, { dueAt: number; task: () => void }>();

  readonly clock: SessionClockPort = { now: () => this.#now };

  readonly timer: SessionTimerPort = {
    set: (delayMs, task) => {
      const handle = {};
      this.#tasks.set(handle, { dueAt: this.#now + delayMs, task });
      return handle;
    },
    clear: (handle) => {
      this.#tasks.delete(handle);
    },
  };

  /** How many deadlines are currently armed, used to prove nothing is left behind. */
  get armedCount(): number {
    return this.#tasks.size;
  }

  /**
   * Moves the clock forward without servicing timers, modelling a deadline whose
   * timer has not fired yet because the event loop was busy elsewhere.
   */
  jump(ms: number): void {
    this.#now += ms;
  }

  /** Moves the clock forward, firing due tasks in order and allowing re-arming. */
  advance(ms: number): void {
    const target = this.#now + ms;
    for (;;) {
      const due = [...this.#tasks.entries()]
        .filter(([, entry]) => entry.dueAt <= target)
        .sort((left, right) => left[1].dueAt - right[1].dueAt)[0];
      if (due === undefined) break;
      this.#tasks.delete(due[0]);
      this.#now = Math.max(this.#now, due[1].dueAt);
      due[1].task();
    }
    this.#now = target;
  }
}

/**
 * Stands in for process signal delivery. Handlers are tracked per signal so a
 * test can assert that the session removed exactly what it installed.
 */
export class ManualSignals {
  readonly #handlers = new Map<SessionSignalName, Set<() => void>>();

  readonly port: SessionSignalPort = {
    listen: (name, handler) => {
      const handlers = this.#handlers.get(name) ?? new Set<() => void>();
      handlers.add(handler);
      this.#handlers.set(name, handlers);
      return () => {
        handlers.delete(handler);
      };
    },
  };

  raise(name: SessionSignalName): void {
    for (const handler of [...(this.#handlers.get(name) ?? [])]) handler();
  }

  listenerCount(): number {
    let total = 0;
    for (const handlers of this.#handlers.values()) total += handlers.size;
    return total;
  }
}

export interface SessionHarness {
  runtime: ManualRuntime;
  signals: ManualSignals;
  ports: SessionRuntimePorts;
}

export function sessionHarness(): SessionHarness {
  const runtime = new ManualRuntime();
  const signals = new ManualSignals();
  return {
    runtime,
    signals,
    ports: { clock: runtime.clock, timer: runtime.timer, signals: signals.port },
  };
}

/** Never settles, standing in for work blocked on a socket, a pipe, or a prompt. */
export function stalled(): Promise<never> {
  return new Promise<never>(() => undefined);
}
