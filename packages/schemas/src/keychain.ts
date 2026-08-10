import { z } from 'zod';

import { deviceIdSchema, keySlotIdSchema, vaultIdSchema } from './identifiers.js';

export const deviceUnlockSecretSchema = z
  .instanceof(Uint8Array)
  .refine((value) => value.byteLength === 32, {
    error: 'Device unlock secrets must contain exactly 32 bytes',
  })
  .brand<'DeviceUnlockSecret'>();

export const keychainLocatorSchema = z
  .object({
    version: z.literal(1),
    vaultId: vaultIdSchema,
    deviceId: deviceIdSchema,
    keySlotId: keySlotIdSchema,
  })
  .strict();

/** Raw bytes for one canonical 32-byte API bearer. */
export const sessionCredentialSecretSchema = z
  .instanceof(Uint8Array)
  .refine((value) => value.byteLength === 32, {
    error: 'Session credential secrets must contain exactly 32 bytes',
  })
  .brand<'SessionCredentialSecret'>();

/** A session credential is device-scoped and is never keyed by a VRK slot. */
export const sessionCredentialLocatorSchema = z
  .object({
    version: z.literal(1),
    vaultId: vaultIdSchema,
    deviceId: deviceIdSchema,
    purpose: z.literal('api-session'),
  })
  .strict();

export type DeviceUnlockSecret = z.infer<typeof deviceUnlockSecretSchema>;
export type KeychainLocator = z.infer<typeof keychainLocatorSchema>;
export type SessionCredentialSecret = z.infer<typeof sessionCredentialSecretSchema>;
export type SessionCredentialLocator = z.infer<typeof sessionCredentialLocatorSchema>;
