import type { DatastoreProfile } from './datastore-profiles.js';
import type { DatabaseFlatCommandOptions } from './database-flat-commands.js';
import { resolveSessionUnlock, SessionUnlockError } from './session-unlock.js';

/**
 * Resolves the stored OS-session unlock material for one profile. Shared by
 * every `--session` code path: fails closed with actionable operator errors
 * when no session exists, expired, tampered, or the keychain is unavailable.
 */
export async function sessionPassphraseForOptions(
  options: DatabaseFlatCommandOptions,
  profile: DatastoreProfile,
): Promise<string> {
  try {
    const material = await resolveSessionUnlock({
      target: {
        profileId: profile.id,
        databaseId: profile.databaseId,
        keyFile: profile.keyFile,
      },
    });
    if (material === null) {
      throw new SessionUnlockError(
        'unavailable',
        'No session unlock is enabled for the selected profile; run `kavrix session enable` or unlock with the passphrase.',
      );
    }
    return material.passphrase;
  } catch (error) {
    if (error instanceof SessionUnlockError && error.code === 'unavailable') {
      // Distinguish "never enabled / revoked" from transport failure.
      throw error;
    }
    if (error instanceof SessionUnlockError) {
      const hint =
        error.code === 'expired'
          ? ' Run `kavrix session enable` again or unlock with the passphrase.'
          : error.code === 'tampered'
            ? ' Run `kavrix session revoke` and enable it again.'
            : ' Unlock with the passphrase.';
      throw new SessionUnlockError(error.code, error.message + hint);
    }
    throw error;
  }
}

export { SessionUnlockError };
