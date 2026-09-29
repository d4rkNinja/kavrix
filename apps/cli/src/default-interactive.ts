import { LocalCliError } from './cli-error.js';
import { DatastoreProfileRegistry } from './datastore-profiles.js';
import {
  runInitTuiOnboarding,
  writeInitTuiOnboardingComplete,
} from './init-tui-onboarding.js';
import { resolveProfileConfigDirectory } from './profile-config-directory.js';
import { terminalColorEnabled } from './terminal-presentation.js';
import { runInteractiveTui } from './tui-command.js';

export type InteractiveDefaultRoute = 'onboarding' | 'tui';

export interface InteractiveDefaultOptions {
  ascii?: boolean;
  color?: boolean;
  /** Commander `--no-splash` sets `splash: false`. */
  splash?: boolean;
  profileConfigDir?: string;
  configDir?: string;
}

/** Bare `kavrix` needs an interactive stdin+stdout; automation keeps commands. */
export function interactiveDefaultEligible(
  stdin: Readonly<{ isTTY?: boolean }> = process.stdin,
  stdout: Readonly<{ isTTY?: boolean }> = process.stdout,
): boolean {
  return stdin.isTTY === true && stdout.isTTY === true;
}

/**
 * Onboarded means a protected profile registry exists with at least one
 * datastore profile. Anything else routes to the init onboarding wizard.
 */
export async function resolveInteractiveDefaultRoute(
  options: Readonly<{
    profileConfigDir?: string;
    configDir?: string;
  }> = {},
): Promise<InteractiveDefaultRoute> {
  const directory = resolveProfileConfigDirectory(
    options.profileConfigDir,
    options.configDir,
  );
  const registry = await DatastoreProfileRegistry.openIfPresent(
    directory === undefined ? {} : { configDirectory: directory },
  );
  if (registry === null) return 'onboarding';
  return (await registry.list()).length === 0 ? 'onboarding' : 'tui';
}

/**
 * Bare `kavrix` on a TTY: run the init onboarding wizard when no profile
 * exists, then open the interactive TUI. Already onboarded sessions open the
 * TUI directly. Cancelled onboarding exits cleanly; a failed wizard surfaces
 * its message through the standard CLI error path.
 */
export async function runDefaultInteractiveAction(
  options: InteractiveDefaultOptions = {},
): Promise<void> {
  const route = await resolveInteractiveDefaultRoute(options);
  if (route === 'onboarding' && process.stderr.isTTY) {
    const result = await runInitTuiOnboarding({
      ...(options.profileConfigDir === undefined
        ? {}
        : { profileConfigDir: options.profileConfigDir }),
      ...(options.configDir === undefined ? {} : { configDir: options.configDir }),
      ...(options.ascii === true ? { ascii: true } : {}),
      ...(options.color === true
        ? { color: true }
        : options.color === false
          ? { color: false }
          : {}),
      ...(options.splash === false ? { splash: false } : {}),
    });
    if (result.status === 'cancelled') {
      process.stderr.write(
        'Setup cancelled. Run kavrix again to retry, or kavrix init --no-tui for classic prompts.\n',
      );
      return;
    }
    if (result.status === 'failed') {
      throw new LocalCliError(result.message);
    }
    writeInitTuiOnboardingComplete({
      color: terminalColorEnabled(process.stderr),
      profileId: result.profileId,
      datastore: result.datastore,
      ...(result.recoveryFile === undefined
        ? {}
        : { recoveryFile: result.recoveryFile }),
      write: (text) => process.stderr.write(text),
    });
  }
  // When onboarding cannot render (stderr not a TTY) the TUI still opens;
  // profiles can be created from its Profiles screen, and `kavrix init
  // --no-tui` remains the classic fallback.
  await runInteractiveTui(options);
}
