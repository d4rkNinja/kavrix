import { spawn } from 'node:child_process';
import { mkdir, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

import { databaseIdSchema, profileIdSchema } from '@kavrix/schemas';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

import {
  interactiveDefaultEligible,
  resolveInteractiveDefaultRoute,
  runDefaultInteractiveAction,
} from '../src/default-interactive.js';
import { DatastoreProfileRegistry } from '../src/datastore-profiles.js';
import { runLocalCli } from '../src/local-vault-cli.js';
import { LocalCliError } from '../src/cli-error.js';
import { createSecureTestDirectory as mkdtemp } from '../../../packages/key-files/test/secure-temporary-directory.js';

const repoRoot = resolve(dirname(fileURLToPath(import.meta.url)), '../../..');
const BIN = join(repoRoot, 'apps', 'cli', 'dist', 'bin.js');

// Hoisted mocks: the real default-interactive module keeps its own logic, but
// its Ink entry points (TUI mount, onboarding wizard) become controllable.
const tuiState = vi.hoisted(() => ({ run: vi.fn() }));
const onboardingState = vi.hoisted(() => ({ run: vi.fn(), complete: vi.fn() }));

vi.mock('../src/tui-command.js', () => ({
  runInteractiveTui: tuiState.run,
  registerTuiCommand: vi.fn(),
}));
vi.mock('../src/init-tui-onboarding.js', () => ({
  runInitTuiOnboarding: onboardingState.run,
  writeInitTuiOnboardingComplete: onboardingState.complete,
}));

let directory = '';
let homeDirectory = '';

const stdinDescriptor = Object.getOwnPropertyDescriptor(process.stdin, 'isTTY');
const stdoutDescriptor = Object.getOwnPropertyDescriptor(process.stdout, 'isTTY');
const stderrDescriptor = Object.getOwnPropertyDescriptor(process.stderr, 'isTTY');
const originalHome = process.env['HOME'];
const originalUserProfile = process.env['USERPROFILE'];
const originalXdgConfigHome = process.env['XDG_CONFIG_HOME'];

function stubTty(stdin: boolean, stdout: boolean, stderr: boolean): void {
  Object.defineProperty(process.stdin, 'isTTY', { configurable: true, value: stdin });
  Object.defineProperty(process.stdout, 'isTTY', { configurable: true, value: stdout });
  Object.defineProperty(process.stderr, 'isTTY', { configurable: true, value: stderr });
}

function restoreTty(): void {
  for (const [stream, descriptor] of [
    [process.stdin, stdinDescriptor],
    [process.stdout, stdoutDescriptor],
    [process.stderr, stderrDescriptor],
  ] as const) {
    if (descriptor === undefined) {
      delete (stream as { isTTY?: boolean }).isTTY;
    } else {
      Object.defineProperty(stream, 'isTTY', descriptor);
    }
  }
}

/**
 * Pins every default-directory input (HOME, USERPROFILE, XDG_CONFIG_HOME —
 * the workspace test setup sets the latter) so the default route resolution
 * is deterministic and never touches the operator's real Kavrix home.
 */
function pinHome(): string {
  const home = join(directory, 'home');
  process.env['HOME'] = home;
  process.env['USERPROFILE'] = home;
  process.env['XDG_CONFIG_HOME'] = join(home, '.config');
  return home;
}

function restoreHome(): void {
  for (const [name, value] of [
    ['HOME', originalHome],
    ['USERPROFILE', originalUserProfile],
    ['XDG_CONFIG_HOME', originalXdgConfigHome],
  ] as const) {
    if (value === undefined) {
      delete process.env[name];
    } else {
      process.env[name] = value;
    }
  }
}

function fileProfile(id = 'default') {
  return {
    id: profileIdSchema.parse(id),
    datastore: 'file' as const,
    databaseId: databaseIdSchema.parse(`db_${id}`),
    dataFile: join(directory, 'default.kavrix-db'),
    keyFile: join(directory, 'default.kavrix-db-key'),
  };
}

beforeEach(async () => {
  directory = await mkdtemp(join(tmpdir(), 'kavrix-default-interactive-'));
  homeDirectory = pinHome();
  vi.clearAllMocks();
  tuiState.run.mockResolvedValue(undefined);
  onboardingState.run.mockResolvedValue({ status: 'cancelled' });
});

afterEach(async () => {
  restoreTty();
  restoreHome();
  vi.restoreAllMocks();
  await rm(directory, { force: true, recursive: true });
});

describe('interactiveDefaultEligible', () => {
  it('requires an interactive stdin and stdout', () => {
    expect(interactiveDefaultEligible({ isTTY: true }, { isTTY: true })).toBe(true);
    expect(interactiveDefaultEligible({ isTTY: false }, { isTTY: true })).toBe(false);
    expect(interactiveDefaultEligible({ isTTY: true }, { isTTY: false })).toBe(false);
    expect(interactiveDefaultEligible({}, { isTTY: true })).toBe(false);
    expect(interactiveDefaultEligible({ isTTY: true }, {})).toBe(false);
  });
});

describe('resolveInteractiveDefaultRoute', () => {
  it('routes to onboarding when no profile registry exists', async () => {
    await expect(
      resolveInteractiveDefaultRoute({ configDir: directory }),
    ).resolves.toBe('onboarding');
  });

  it('routes to onboarding when the registry exists without profiles', async () => {
    await DatastoreProfileRegistry.open({ configDirectory: directory });
    await expect(
      resolveInteractiveDefaultRoute({ configDir: directory }),
    ).resolves.toBe('onboarding');
  });

  it('routes to the TUI once a datastore profile is onboarded', async () => {
    const registry = await DatastoreProfileRegistry.open({
      configDirectory: directory,
    });
    await registry.add(fileProfile());
    await expect(
      resolveInteractiveDefaultRoute({ configDir: directory }),
    ).resolves.toBe('tui');
  });
});

describe('runDefaultInteractiveAction', () => {
  it('opens the TUI directly when a profile exists', async () => {
    const registry = await DatastoreProfileRegistry.open({
      configDirectory: directory,
    });
    await registry.add(fileProfile());
    stubTty(true, true, true);
    await runDefaultInteractiveAction({ configDir: directory });
    expect(tuiState.run).toHaveBeenCalledTimes(1);
    expect(onboardingState.run).not.toHaveBeenCalled();
  });

  it('runs onboarding first and then opens the TUI', async () => {
    onboardingState.run.mockResolvedValue({
      status: 'completed',
      profileId: 'default',
      datastore: 'file',
      recoveryFile: join(directory, 'recovery.kit'),
    });
    stubTty(true, true, true);
    await runDefaultInteractiveAction({ configDir: directory });
    expect(onboardingState.run).toHaveBeenCalledTimes(1);
    expect(onboardingState.complete).toHaveBeenCalledWith(
      expect.objectContaining({ profileId: 'default', datastore: 'file' }),
    );
    expect(tuiState.run).toHaveBeenCalledTimes(1);
  });

  it('stops cleanly when onboarding is cancelled', async () => {
    stubTty(true, true, true);
    const stderr = vi.spyOn(process.stderr, 'write').mockReturnValue(true);
    await runDefaultInteractiveAction({ configDir: directory });
    expect(stderr).toHaveBeenCalledWith(expect.stringMatching(/Setup cancelled/u));
    expect(tuiState.run).not.toHaveBeenCalled();
  });

  it('surfaces a failed onboarding wizard through the CLI error path', async () => {
    onboardingState.run.mockResolvedValue({
      status: 'failed',
      message: 'recovery verification failed',
    });
    stubTty(true, true, true);
    await expect(
      runDefaultInteractiveAction({ configDir: directory }),
    ).rejects.toBeInstanceOf(LocalCliError);
    expect(tuiState.run).not.toHaveBeenCalled();
  });

  it('skips the wizard and opens the TUI when stderr is not a TTY', async () => {
    stubTty(true, true, false);
    await runDefaultInteractiveAction({ configDir: directory });
    expect(onboardingState.run).not.toHaveBeenCalled();
    expect(tuiState.run).toHaveBeenCalledTimes(1);
  });
});

describe('bare kavrix (runLocalCli)', () => {
  it('keeps classic help behavior when non-interactive', async () => {
    stubTty(false, false, false);
    const stderr = vi.spyOn(process.stderr, 'write').mockReturnValue(true);
    await runLocalCli(['node', 'kavrix']);
    expect(stderr).toHaveBeenCalledWith(expect.stringMatching(/Usage: kavrix/u));
    expect(tuiState.run).not.toHaveBeenCalled();
    expect(onboardingState.run).not.toHaveBeenCalled();
  });

  it('keeps failing on unknown command names with usage exit 2', async () => {
    stubTty(true, true, true);
    const originalExitCode = process.exitCode;
    process.exitCode = undefined;
    const stderr = vi.spyOn(process.stderr, 'write').mockReturnValue(true);
    try {
      await runLocalCli(['node', 'kavrix', 'definitely-not-a-kavrix-command']);
    } catch {
      // runLocalCli classifies instead of rethrowing.
    }
    expect(process.exitCode).toBe(2);
    expect(stderr).toHaveBeenCalledWith(
      expect.stringMatching(/unknown command 'definitely-not-a-kavrix-command'/u),
    );
    expect(tuiState.run).not.toHaveBeenCalled();
    expect(onboardingState.run).not.toHaveBeenCalled();
    process.exitCode = originalExitCode;
  });

  it('runs the onboarding wizard first on an unonboarded interactive session', async () => {
    stubTty(true, true, true);
    const stderr = vi.spyOn(process.stderr, 'write').mockReturnValue(true);
    // HOME/XDG point at the empty scratch directory, so no profile registry
    // exists and the default action must route to onboarding.
    await runLocalCli(['node', 'kavrix']);
    expect(onboardingState.run).toHaveBeenCalledTimes(1);
    expect(tuiState.run).not.toHaveBeenCalled();
    expect(stderr).toHaveBeenCalledWith(expect.stringMatching(/Setup cancelled/u));
  });

  it('opens the TUI directly on an onboarded interactive session', async () => {
    const configDirectory = join(homeDirectory, '.config', 'kavrix');
    await mkdir(dirname(configDirectory), { recursive: true });
    const registry = await DatastoreProfileRegistry.open({ configDirectory });
    await registry.add(fileProfile());
    stubTty(true, true, true);
    await runLocalCli(['node', 'kavrix']);
    expect(onboardingState.run).not.toHaveBeenCalled();
    expect(tuiState.run).toHaveBeenCalledTimes(1);
  });

  it('still parses flags and subcommands through commander', async () => {
    stubTty(true, true, true);
    const stdout = vi.spyOn(process.stdout, 'write').mockReturnValue(true);
    await runLocalCli(['node', 'kavrix', '--version']);
    expect(stdout).toHaveBeenCalledWith(expect.stringContaining('0.'));
    expect(tuiState.run).not.toHaveBeenCalled();
    expect(onboardingState.run).not.toHaveBeenCalled();
  });
});

describe('bare kavrix (built CLI, non-interactive)', () => {
  it('keeps classic help behavior: usage on stderr, empty stdout, exit 0', async () => {
    const child = spawn(process.execPath, [BIN], {
      stdio: ['pipe', 'pipe', 'pipe'],
      windowsHide: true,
    });
    const stdout: Buffer[] = [];
    const stderr: Buffer[] = [];
    child.stdout.on('data', (chunk: Buffer) => stdout.push(chunk));
    child.stderr.on('data', (chunk: Buffer) => stderr.push(chunk));
    child.stdin.end();
    const code = await new Promise<number | null>((res, rej) => {
      child.on('error', rej);
      child.on('close', (exitCode) => res(exitCode));
    });
    expect(code).toBe(0);
    expect(stdout).toHaveLength(0);
    expect(Buffer.concat(stderr).toString('utf8')).toMatch(/Usage: kavrix/u);
  });
});
