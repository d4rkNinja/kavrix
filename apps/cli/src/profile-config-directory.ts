import { LocalCliError } from './cli-error.js';

/** Reviewed message when both config-dir spellings are supplied together. */
export const CONFLICTING_PROFILE_CONFIG_DIR_MESSAGE =
  'Use either --profile-config-dir or --config-dir, not both.';

/**
 * Resolve the protected profile configuration directory from the two CLI
 * spellings. Both flags mean the same directory; supplying both is rejected so
 * operators never silently prefer one over the other.
 */
export function resolveProfileConfigDirectory(
  profileConfigDir: string | undefined,
  configDir: string | undefined,
): string | undefined {
  if (profileConfigDir !== undefined && configDir !== undefined) {
    throw new LocalCliError(CONFLICTING_PROFILE_CONFIG_DIR_MESSAGE);
  }
  return profileConfigDir ?? configDir;
}
