import {
  DEFAULT_SESSION_LIFETIME_POLICY,
  sessionLifetimePolicySchema,
  type SessionLifetimePolicy,
} from '@kavrix/schemas';

import { CliUsageError } from '../errors.js';

/**
 * Environment overrides for the session deadlines. These are operator policy,
 * not secrets, so reading them from the environment is safe; a secret would never
 * be accepted from here. Both are optional, and an unset variable keeps the
 * shipped default rather than disabling the limit.
 */
const INVOCATION_TIMEOUT_VARIABLE = 'CREDS_SESSION_TIMEOUT_MS';
const IDLE_TIMEOUT_VARIABLE = 'CREDS_SESSION_IDLE_TIMEOUT_MS';
const REAUTHENTICATION_WINDOW_VARIABLE = 'CREDS_REAUTH_WINDOW_MS';

/**
 * Resolves the deadlines for one invocation.
 *
 * A malformed, out-of-bounds, or internally inconsistent override fails closed
 * with a usage error instead of falling back to the default: silently ignoring a
 * limit the operator asked for would leave a session running longer than they
 * believe it can. The rejected value is never echoed back.
 */
export function resolveSessionLifetimePolicy(
  environment: Readonly<Record<string, string | undefined>> = process.env,
): SessionLifetimePolicy {
  const candidate = {
    invocationTimeoutMs:
      readMilliseconds(environment, INVOCATION_TIMEOUT_VARIABLE) ??
      DEFAULT_SESSION_LIFETIME_POLICY.invocationTimeoutMs,
    idleTimeoutMs:
      readMilliseconds(environment, IDLE_TIMEOUT_VARIABLE) ??
      DEFAULT_SESSION_LIFETIME_POLICY.idleTimeoutMs,
    reauthenticationWindowMs:
      readMilliseconds(environment, REAUTHENTICATION_WINDOW_VARIABLE) ??
      DEFAULT_SESSION_LIFETIME_POLICY.reauthenticationWindowMs,
  };
  const parsed = sessionLifetimePolicySchema.safeParse(candidate);
  if (!parsed.success) {
    throw new CliUsageError('The session lifetime policy is invalid.');
  }
  return Object.freeze(parsed.data);
}

function readMilliseconds(
  environment: Readonly<Record<string, string | undefined>>,
  key: string,
): number | undefined {
  const raw = environment[key];
  if (raw === undefined) return undefined;
  const trimmed = raw.trim();
  if (trimmed.length === 0) return undefined;
  // Only a canonical unsigned decimal is accepted, so `1e3`, `0x10`, `+5`, and a
  // leading-zero form cannot smuggle in a value the schema bounds would then
  // report as valid.
  if (!/^(?:0|[1-9][0-9]{0,12})$/u.test(trimmed)) {
    throw new CliUsageError('The session lifetime policy is invalid.');
  }
  return Number.parseInt(trimmed, 10);
}
