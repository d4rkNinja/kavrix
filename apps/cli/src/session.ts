import {
  authorizationValid,
  beginSession,
  evaluateSession,
  recordActivity,
  recordAuthorization,
  withdrawAuthorization,
  type SessionLifetimeState,
} from '@kavrix/core';
import {
  DEFAULT_SESSION_LIFETIME_POLICY,
  type SessionExpiryReason,
  type SessionLifetimePolicy,
} from '@kavrix/schemas';

import { CliSessionEndedError } from './errors.js';

export type SessionSignalName = 'SIGINT' | 'SIGTERM' | 'SIGHUP';

/**
 * Which expiry reason each process signal produces. The mapping is exhaustive so
 * a new signal cannot be listened for without also deciding what it means.
 */
const SIGNAL_REASONS = Object.freeze({
  SIGINT: 'interrupted',
  SIGTERM: 'terminated',
  SIGHUP: 'hangup',
} as const satisfies Readonly<Record<SessionSignalName, SessionExpiryReason>>);

const LISTENED_SIGNALS = Object.freeze(
  Object.keys(SIGNAL_REASONS) as readonly SessionSignalName[],
);

/** A monotonic millisecond source. Wall-clock time is deliberately not usable. */
export type SessionClockPort = Readonly<{ now: () => number }>;

export type SessionTimerPort = Readonly<{
  set: (delayMs: number, task: () => void) => object;
  clear: (handle: object) => void;
}>;

/** Installs a signal listener and returns the exact function that removes it. */
export type SessionSignalPort = Readonly<{
  listen: (name: SessionSignalName, handler: () => void) => () => void;
}>;

export type SessionRuntimePorts = Readonly<{
  clock: SessionClockPort;
  timer: SessionTimerPort;
  signals: SessionSignalPort;
}>;

export type InvocationSessionOptions = Readonly<{
  policy?: SessionLifetimePolicy;
  ports?: Partial<SessionRuntimePorts>;
}>;

/**
 * The lifetime of one unlocked command invocation.
 *
 * The session owns three things a command must not own itself: the deadline that
 * bounds how long a decrypted root key may exist, the abort signal that
 * cancellable work is threaded onto, and the ordered cleanup stack that releases
 * that work. Cleanup runs exactly once, in reverse registration order, for every
 * ending — normal completion, thrown error, deadline, inactivity, or signal — so
 * there is no path on which a secret survives the command that acquired it.
 *
 * There is no secret-retaining daemon behind this: the session lives and dies
 * inside one process, and nothing is written down to let a later process resume
 * an unlocked state.
 */
export class InvocationSession {
  readonly #clock: SessionClockPort;
  readonly #timer: SessionTimerPort;
  readonly #controller = new AbortController();
  readonly #detach: (() => void)[] = [];
  readonly #cleanups: {
    readonly name: string;
    readonly run: () => void | Promise<void>;
  }[] = [];

  #state: SessionLifetimeState;
  #reason: SessionExpiryReason | undefined;
  #handle: object | undefined;
  #closing: Promise<void> | undefined;

  constructor(options: InvocationSessionOptions = {}) {
    this.#clock = options.ports?.clock ?? nodeSessionClock();
    this.#timer = options.ports?.timer ?? nodeSessionTimer();
    const signals = options.ports?.signals ?? nodeSessionSignals();
    this.#state = beginSession(
      options.policy ?? DEFAULT_SESSION_LIFETIME_POLICY,
      this.#clock.now(),
    );
    for (const name of LISTENED_SIGNALS) {
      this.#detach.push(
        signals.listen(name, () => {
          this.#end(SIGNAL_REASONS[name]);
        }),
      );
    }
    this.#arm();
  }

  /** Aborts when the session ends for any reason, including normal cleanup. */
  get signal(): AbortSignal {
    return this.#controller.signal;
  }

  /** Why the session ended, or `undefined` while it is still usable. */
  get endedBecause(): SessionExpiryReason | undefined {
    return this.#reason;
  }

  /** The deadlines in force, for rendering and for tests. */
  get policy(): SessionLifetimePolicy {
    return this.#state.policy;
  }

  /**
   * Records progress, restarting the inactivity limit. Reaching a deadline while
   * recording ends the session rather than silently extending it.
   */
  touch(): void {
    if (this.#reason !== undefined) return;
    const now = this.#clock.now();
    const expiry = evaluateSession(this.#state, now);
    if (expiry.expired) {
      this.#end(expiry.reason);
      return;
    }
    this.#state = recordActivity(this.#state, now);
    this.#arm();
  }

  /** Opens a reauthentication window after a proven unlock credential. */
  authorize(): void {
    this.assertLive();
    this.#state = recordAuthorization(this.#state, this.#clock.now());
    this.#arm();
  }

  /** Closes the reauthentication window without ending the session. */
  revokeAuthorization(): void {
    this.#state = withdrawAuthorization(this.#state);
  }

  /** Whether a reauthentication window is still open right now. */
  authorized(): boolean {
    if (this.#reason !== undefined) return false;
    return authorizationValid(this.#state, this.#clock.now());
  }

  /**
   * Fails closed unless the session is usable at this instant. Commands call
   * this immediately before reporting success so a result produced after the
   * deadline can never be rendered as an unlocked outcome.
   */
  assertLive(): void {
    if (this.#reason !== undefined) throw new CliSessionEndedError(this.#reason);
    const expiry = evaluateSession(this.#state, this.#clock.now());
    if (expiry.expired) {
      this.#end(expiry.reason);
      throw new CliSessionEndedError(expiry.reason);
    }
  }

  /**
   * Adds a release step. Steps run in reverse registration order, so a caller
   * registers in the same order it acquires and gets ownership-correct teardown
   * for free. Registering after the session has closed runs the step at once,
   * because a resource acquired past the deadline still has to be released.
   */
  register(name: string, cleanup: () => void | Promise<void>): void {
    if (this.#closing !== undefined) {
      void Promise.resolve()
        .then(cleanup)
        .catch(() => {
          // A late resource is released best effort; the closing report has
          // already been produced, so there is nowhere left to surface this.
        });
      return;
    }
    this.#cleanups.push({ name, run: cleanup });
  }

  /**
   * Releases everything exactly once. Concurrent and repeat calls await the same
   * teardown. Every step is attempted even when an earlier one fails, and the
   * failures are reported together rather than masking each other.
   */
  close(): Promise<void> {
    this.#closing ??= this.#closeOnce();
    return this.#closing;
  }

  async #closeOnce(): Promise<void> {
    this.#disarm();
    // Cancel anything still threaded onto the signal. A normal close carries no
    // expiry reason, so the abort is deliberately untyped: nothing ended badly.
    if (!this.#controller.signal.aborted) this.#controller.abort();
    for (const detach of this.#detach.splice(0).reverse()) detach();

    const failures: unknown[] = [];
    for (const step of this.#cleanups.splice(0).reverse()) {
      try {
        await step.run();
      } catch (error) {
        failures.push(error);
      }
    }
    if (failures.length > 0) {
      throw new AggregateError(failures, 'Session resources could not be released.', {
        cause: failures[0],
      });
    }
  }

  /**
   * Marks the session unusable and cancels every operation threaded onto its
   * signal. The first reason wins: a session that already timed out is not
   * relabelled by the signal that arrives while it is cleaning up.
   */
  #end(reason: SessionExpiryReason): void {
    this.#reason ??= reason;
    this.#disarm();
    if (!this.#controller.signal.aborted) {
      this.#controller.abort(new CliSessionEndedError(this.#reason));
    }
  }

  #arm(): void {
    this.#disarm();
    if (this.#reason !== undefined) return;
    const expiry = evaluateSession(this.#state, this.#clock.now());
    if (expiry.expired) {
      this.#end(expiry.reason);
      return;
    }
    this.#handle = this.#timer.set(expiry.remainingMs, () => {
      this.#handle = undefined;
      const current = evaluateSession(this.#state, this.#clock.now());
      if (current.expired) this.#end(current.reason);
      else this.#arm();
    });
  }

  #disarm(): void {
    if (this.#handle === undefined) return;
    this.#timer.clear(this.#handle);
    this.#handle = undefined;
  }
}

/**
 * Runs `operation` under a session and guarantees teardown.
 *
 * The operation is raced against the session ending so cleanup never waits on
 * work that has stopped making progress: a command blocked on a socket or a pipe
 * cannot hold a decrypted root key past the deadline just by refusing to notice
 * the abort. An abandoned operation still has its resources released, because
 * they are on the session's cleanup stack rather than in its own local scope.
 */
export async function runWithInvocationSession<Output>(
  options: InvocationSessionOptions,
  operation: (session: InvocationSession) => Promise<Output>,
): Promise<Output> {
  const session = new InvocationSession(options);
  let outcome:
    | Readonly<{ succeeded: true; value: Output }>
    | Readonly<{ succeeded: false; error: unknown }>;
  try {
    outcome = { succeeded: true, value: await race(session, operation) };
  } catch (error) {
    outcome = { succeeded: false, error };
  }

  let cleanupError: unknown;
  let cleanupFailed = false;
  try {
    await session.close();
  } catch (error) {
    cleanupError = error;
    cleanupFailed = true;
  }

  if (cleanupFailed) {
    if (!outcome.succeeded) {
      throw new AggregateError(
        [outcome.error, cleanupError],
        'The session operation and its cleanup both failed.',
        { cause: outcome.error },
      );
    }
    throw cleanupError;
  }
  if (!outcome.succeeded) throw outcome.error;
  // The operation finished, but it may have finished after the deadline. A
  // result produced by an expired session is not a success.
  session.assertLive();
  return outcome.value;
}

async function race<Output>(
  session: InvocationSession,
  operation: (session: InvocationSession) => Promise<Output>,
): Promise<Output> {
  const work = operation(session);
  // An abandoned operation must not become an unhandled rejection once the
  // session has already reported why it ended.
  work.catch(() => undefined);
  return await Promise.race([work, ended(session.signal)]);
}

function ended(signal: AbortSignal): Promise<never> {
  return new Promise((_resolve, reject) => {
    if (signal.aborted) {
      reject(abortReason(signal));
      return;
    }
    signal.addEventListener(
      'abort',
      () => {
        reject(abortReason(signal));
      },
      { once: true },
    );
  });
}

function abortReason(signal: AbortSignal): Error {
  const reason: unknown = signal.reason;
  return reason instanceof Error ? reason : new CliSessionEndedError('interrupted');
}

export function nodeSessionClock(): SessionClockPort {
  return { now: () => performance.now() };
}

export function nodeSessionTimer(): SessionTimerPort {
  return {
    set: (delayMs, task) => {
      const handle = setTimeout(task, delayMs);
      // A deadline must not be the reason the process stays alive; it only
      // shortens a session that is already running.
      handle.unref();
      return handle;
    },
    clear: (handle) => {
      clearTimeout(handle as NodeJS.Timeout);
    },
  };
}

export function nodeSessionSignals(): SessionSignalPort {
  return {
    listen: (name, handler) => {
      process.on(name, handler);
      return () => {
        process.off(name, handler);
      };
    },
  };
}
