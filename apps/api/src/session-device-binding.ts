import {
  apiSessionResponseSchema,
  deviceRecordSchema,
  sha256DigestSchema,
  supportedSchemaVersionSchema,
  supportedTokenVersionSchema,
} from '@kavrix/schemas';

import type { SessionPrincipal } from './ports.js';

export interface SessionDeviceBindingInput {
  readonly presentedTokenHash: unknown;
  readonly sessionTokenHash: unknown;
  readonly session: unknown;
  readonly device: unknown;
}

/**
 * Returns the canonical principal only while the session and device describe the
 * same currently supported authorization. Callers must treat null as generic
 * authentication failure and must never repair divergent records in-band.
 */
export function bindSessionToDevice(
  input: SessionDeviceBindingInput,
): SessionPrincipal | null {
  const presentedTokenHash = sha256DigestSchema.safeParse(input.presentedTokenHash);
  const sessionTokenHash = sha256DigestSchema.safeParse(input.sessionTokenHash);
  const session = apiSessionResponseSchema.safeParse(input.session);
  const device = deviceRecordSchema.safeParse(input.device);
  if (
    !presentedTokenHash.success ||
    !sessionTokenHash.success ||
    !session.success ||
    !device.success ||
    device.data.revokedAt !== undefined ||
    !supportedSchemaVersionSchema.safeParse(device.data.schemaVersion).success ||
    !supportedTokenVersionSchema.safeParse(device.data.tokenVersion).success
  ) {
    return null;
  }
  if (
    presentedTokenHash.data !== sessionTokenHash.data ||
    device.data.tokenHash !== presentedTokenHash.data ||
    device.data.vaultId !== session.data.vaultId ||
    device.data.id !== session.data.deviceId ||
    device.data.scopes.length !== session.data.scopes.length ||
    !device.data.scopes.every((scope) => session.data.scopes.includes(scope))
  ) {
    return null;
  }
  return session.data;
}
