import {
  DEFAULT_SESSION_LIFETIME_POLICY,
  sessionLifetimePolicySchema,
  type SessionExpiryReason,
  type SessionLifetimePolicy,
} from '@kavrix/schemas';

import { ValidationError } from '../errors.js';

/**
 * The observable state of one unlocked session, measured on a monotonic clock.
 *
 * Every timestamp is a monotonic reading in milliseconds, not a wall-clock
 * instant: wall-clock time can be moved by the operator or by NTP, and a session
 * whose deadline could be pushed forward by changing the system clock would not
 * be a deadline at all. The state is immutable so a caller cannot lose an
 * activity or authorization update by holding a stale reference — each recorder
 * returns the next state.
 */
export type SessionLifetimeState = Readonly<{
  policy: SessionLifetimePolicy;
  startedAtMs: number;
  lastActivityAtMs: number;
  /** When the current reauthentication window opened, or `null` if none is open. */
  authorizedAtMs: number | null;
}>;

/**
 * Whether a session may still be used, and if not, why it stopped.
 *
 * `remainingMs` is the time left before the *earliest* of the two deadlines, so
 * a caller can arm a single timer from it without recomputing the policy.
 */
export type SessionExpiry =
  | Readonly<{ expired: false; remainingMs: number }>
  | Readonly<{ expired: true; reason: SessionExpiryReason }>;

/**
 * Opens a session at a monotonic reading.
 *
 * The policy is parsed rather than trusted so an out-of-bounds or cross-field
 * inconsistent limit is rejected at the boundary instead of producing a deadline
 * that can never fire.
 */
export function beginSession(
  policy: SessionLifetimePolicy = DEFAULT_SESSION_LIFETIME_POLICY,
  nowMs = 0,
): SessionLifetimeState {
  const parsed = sessionLifetimePolicySchema.parse(policy);
  assertMonotonicReading(nowMs);
  return Object.freeze({
    policy: Object.freeze(parsed),
    startedAtMs: nowMs,
    lastActivityAtMs: nowMs,
    authorizedAtMs: null,
  });
}

/**
 * Records that the operator or the command did something at `nowMs`, which
 * restarts the inactivity limit but never extends the invocation limit.
 *
 * A reading before the last recorded activity means the clock moved backward.
 * That is rejected rather than clamped: clamping would silently accept a clock
 * that cannot enforce the inactivity deadline.
 */
export function recordActivity(
  state: SessionLifetimeState,
  nowMs: number,
): SessionLifetimeState {
  assertMonotonicReading(nowMs);
  if (nowMs < state.lastActivityAtMs) {
    throw new ValidationError('A session clock reading cannot move backward.');
  }
  return Object.freeze({ ...state, lastActivityAtMs: nowMs });
}

/**
 * Opens or refreshes the reauthentication window after a successful unlock or
 * explicit reauthentication. This also counts as activity, because proving an
 * unlock credential is the strongest possible evidence the operator is present.
 */
export function recordAuthorization(
  state: SessionLifetimeState,
  nowMs: number,
): SessionLifetimeState {
  const active = recordActivity(state, nowMs);
  return Object.freeze({ ...active, authorizedAtMs: nowMs });
}

/**
 * Closes the reauthentication window without ending the session, so the next
 * privileged step must prove the unlock credential again.
 */
export function withdrawAuthorization(
  state: SessionLifetimeState,
): SessionLifetimeState {
  return Object.freeze({ ...state, authorizedAtMs: null });
}

/**
 * Decides whether the session is still usable at `nowMs`.
 *
 * The invocation limit is checked before the inactivity limit so a session that
 * has blown both reports the stronger, non-recoverable reason. A reading before
 * the session start expires the session with `clock-regression` instead of
 * throwing, because this is called from cleanup paths that must reach a decision
 * even when the clock is untrustworthy.
 */
export function evaluateSession(
  state: SessionLifetimeState,
  nowMs: number,
): SessionExpiry {
  if (!Number.isFinite(nowMs) || nowMs < state.startedAtMs) {
    return Object.freeze({ expired: true, reason: 'clock-regression' as const });
  }
  if (nowMs - state.startedAtMs >= state.policy.invocationTimeoutMs) {
    return Object.freeze({ expired: true, reason: 'invocation-timeout' as const });
  }
  if (nowMs - state.lastActivityAtMs >= state.policy.idleTimeoutMs) {
    return Object.freeze({ expired: true, reason: 'idle-timeout' as const });
  }
  const untilInvocation = state.startedAtMs + state.policy.invocationTimeoutMs - nowMs;
  const untilIdle = state.lastActivityAtMs + state.policy.idleTimeoutMs - nowMs;
  return Object.freeze({
    expired: false,
    remainingMs: Math.min(untilInvocation, untilIdle),
  });
}

/**
 * Whether a reauthentication window is still open at `nowMs`.
 *
 * An expired session is never authorized, so a command cannot ride a window that
 * was opened before the session timed out.
 */
export function authorizationValid(
  state: SessionLifetimeState,
  nowMs: number,
): boolean {
  if (state.authorizedAtMs === null) return false;
  if (evaluateSession(state, nowMs).expired) return false;
  return nowMs - state.authorizedAtMs < state.policy.reauthenticationWindowMs;
}

function assertMonotonicReading(nowMs: number): void {
  if (!Number.isFinite(nowMs) || nowMs < 0) {
    throw new ValidationError(
      'A session clock reading must be a finite, non-negative number of milliseconds.',
    );
  }
}
