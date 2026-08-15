import { z } from 'zod';

/**
 * Bounds for an unlocked-session lifetime.
 *
 * A session is the span of one command invocation that holds a decrypted root
 * key in memory. There is no secret-retaining daemon, so these limits bound a
 * single process rather than a background agent: the shortest useful window is
 * one second, and the ceiling matches the `creds run --timeout` ceiling so a
 * guarded child can never outlive the session that authorized it.
 */
export const MIN_SESSION_TIMEOUT_MS = 1_000;
export const MAX_SESSION_TIMEOUT_MS = 86_400_000;

/**
 * Defaults chosen so an unattended terminal locks well before a coffee break
 * ends, while a long interactive flow (a rotation with several masked prompts,
 * or a large import) still completes without an artificial interruption.
 */
export const DEFAULT_INVOCATION_TIMEOUT_MS = 900_000;
export const DEFAULT_IDLE_TIMEOUT_MS = 120_000;
export const DEFAULT_REAUTHENTICATION_WINDOW_MS = 120_000;

/**
 * Why an unlocked session stopped being usable.
 *
 * Every reason is terminal: a session is never resumed after expiry, because
 * resuming would mean keeping the root key alive past the point the policy said
 * it should be gone. `clock-regression` exists because expiry is measured on a
 * monotonic clock; a backward reading means the clock cannot be trusted to
 * enforce the deadline, so the session fails closed instead of guessing.
 */
export const sessionExpiryReasonSchema = z.enum([
  /** The whole invocation reached its wall-clock limit. */
  'invocation-timeout',
  /** No activity was recorded within the inactivity limit. */
  'idle-timeout',
  /** The operator interrupted the invocation (SIGINT). */
  'interrupted',
  /** The supervisor asked the process to stop (SIGTERM). */
  'terminated',
  /** The controlling terminal went away (SIGHUP). */
  'hangup',
  /** The monotonic clock moved backward, so deadlines are unenforceable. */
  'clock-regression',
]);

/**
 * The three limits that govern one unlocked session.
 *
 * `idleTimeoutMs` and `reauthenticationWindowMs` are both capped by
 * `invocationTimeoutMs`: an inactivity limit longer than the invocation limit
 * could never fire, and a reauthentication window longer than the invocation
 * would outlive the session that holds it, which would make a single
 * authorization silently cover a longer span than the policy allows.
 */
export const sessionLifetimePolicySchema = z
  .object({
    invocationTimeoutMs: z
      .number()
      .int()
      .min(MIN_SESSION_TIMEOUT_MS)
      .max(MAX_SESSION_TIMEOUT_MS),
    idleTimeoutMs: z
      .number()
      .int()
      .min(MIN_SESSION_TIMEOUT_MS)
      .max(MAX_SESSION_TIMEOUT_MS),
    reauthenticationWindowMs: z
      .number()
      .int()
      .min(MIN_SESSION_TIMEOUT_MS)
      .max(MAX_SESSION_TIMEOUT_MS),
  })
  .strict()
  .superRefine((policy, context) => {
    if (policy.idleTimeoutMs > policy.invocationTimeoutMs) {
      context.addIssue({
        code: 'custom',
        message: 'An inactivity limit cannot exceed the invocation limit',
        path: ['idleTimeoutMs'],
      });
    }
    if (policy.reauthenticationWindowMs > policy.invocationTimeoutMs) {
      context.addIssue({
        code: 'custom',
        message: 'A reauthentication window cannot exceed the invocation limit',
        path: ['reauthenticationWindowMs'],
      });
    }
  });

export const DEFAULT_SESSION_LIFETIME_POLICY: SessionLifetimePolicy = Object.freeze({
  invocationTimeoutMs: DEFAULT_INVOCATION_TIMEOUT_MS,
  idleTimeoutMs: DEFAULT_IDLE_TIMEOUT_MS,
  reauthenticationWindowMs: DEFAULT_REAUTHENTICATION_WINDOW_MS,
});

export type SessionExpiryReason = z.infer<typeof sessionExpiryReasonSchema>;
export type SessionLifetimePolicy = z.infer<typeof sessionLifetimePolicySchema>;
