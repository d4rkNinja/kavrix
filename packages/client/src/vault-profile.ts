import {
  keychainLocatorSchema,
  sessionCredentialLocatorSchema,
  vaultIdSchema,
  deviceIdSchema,
  type DeviceId,
  type VaultId,
} from '@kavrix/schemas';
import { z } from 'zod';

const profileServerUrlSchema = z
  .url()
  .max(2_048)
  .superRefine((value, context) => {
    const url = new URL(value);
    if (
      url.href !== value ||
      !url.pathname.endsWith('/') ||
      url.username.length > 0 ||
      url.password.length > 0 ||
      url.search.length > 0 ||
      url.hash.length > 0 ||
      (url.protocol !== 'https:' &&
        !(url.protocol === 'http:' && isLoopbackHostname(url.hostname)))
    ) {
      context.addIssue({
        code: 'custom',
        message: 'The server URL is not a canonical secure base URL',
      });
    }
  });

/** Non-secret identity and protected-locator binding for one local vault device. */
export const vaultProfileSchema = z
  .object({
    version: z.literal(1),
    serverUrl: profileServerUrlSchema,
    vaultId: vaultIdSchema,
    deviceId: deviceIdSchema,
    deviceLocator: keychainLocatorSchema,
    sessionLocator: sessionCredentialLocatorSchema,
  })
  .strict()
  .superRefine((profile, context) => {
    if (
      profile.deviceLocator.vaultId !== profile.vaultId ||
      profile.deviceLocator.deviceId !== profile.deviceId ||
      profile.sessionLocator.vaultId !== profile.vaultId ||
      profile.sessionLocator.deviceId !== profile.deviceId
    ) {
      context.addIssue({
        code: 'custom',
        path: ['vaultId'],
        message: 'Profile locators must match its vault and device',
      });
    }
  });

export type VaultProfile = z.infer<typeof vaultProfileSchema>;

/**
 * Durable local persistence for a non-secret profile.
 *
 * `store` must durably flush before resolving. Repeating the exact profile is
 * idempotent; reusing its vault/device identity or either protected locator for
 * a different profile must fail closed. `load` returns a fresh canonical copy.
 * There is intentionally no initialization-time delete: storage begins only
 * after durable network intent, and an ambiguous request may already have
 * committed the profile's vault/device remotely.
 */
export interface VaultProfileStorePort {
  load(vaultId: VaultId, deviceId: DeviceId): Promise<VaultProfile | null>;
  store(profile: VaultProfile): Promise<void>;
}

export function isInsecureLoopbackProfile(profile: VaultProfile): boolean {
  return new URL(profile.serverUrl).protocol === 'http:';
}

function isLoopbackHostname(hostname: string): boolean {
  if (hostname === '[::1]') return true;
  const octets = hostname.split('.');
  return (
    octets.length === 4 &&
    octets[0] === '127' &&
    octets.every((octet) => /^\d{1,3}$/u.test(octet) && Number(octet) <= 255)
  );
}
