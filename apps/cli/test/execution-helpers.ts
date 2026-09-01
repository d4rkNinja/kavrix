import { rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { Readable } from 'node:stream';

import { profileIdSchema, timestampSchema, type VaultId } from '@kavrix/schemas';
import { FileEncryptedDatabaseStore } from '@kavrix/storage';
import { vi } from 'vitest';

import { DatabaseSession } from '../src/database-session.js';
import {
  DatastoreProfileRegistry,
  type DatastoreProfile,
} from '../src/datastore-profiles.js';
import { runLocalCli } from '../src/local-vault-cli.js';
import { createSecureTestDirectory as mkdtemp } from '../../../packages/key-files/test/secure-temporary-directory.js';

export const EXEC_PASSPHRASE = 'correct horse battery staple';

export interface ExecutionFixture {
  readonly directory: string;
  readonly dataFile: string;
  readonly keyFile: string;
  readonly vaultId: VaultId;
  /** Arguments selecting this fixture's bound database vault. */
  readonly routingArgs: readonly string[];
}

function seedTimestamp(): string {
  return timestampSchema.parse(new Date().toISOString());
}

/**
 * Creates one encrypted database container, seeds credentials, registers a
 * bound file datastore profile, and returns everything the execution commands
 * need to run against it.
 */
export async function createExecutionFixture(
  credentials: Readonly<Record<string, string>>,
): Promise<ExecutionFixture> {
  const directory = await mkdtemp(join(tmpdir(), 'kavrix-exec-'));
  const dataFile = join(directory, 'database.kavrix');
  const keyFile = join(directory, 'owner.key');
  const passphrase = Buffer.from(EXEC_PASSPHRASE, 'utf8');
  const store = await FileEncryptedDatabaseStore.open(dataFile);
  let initialized: Awaited<ReturnType<typeof DatabaseSession.initialize>>;
  let vaultId: VaultId;
  try {
    initialized = await DatabaseSession.initialize({
      store,
      keyFile,
      passphrase,
      label: 'execution tests',
    });
    const session = await DatabaseSession.open({ store, keyFile, passphrase });
    try {
      const vault = await session.createVault('main');
      await session.updateVault(vault.id, (payload) => {
        for (const [name, value] of Object.entries(credentials)) {
          payload.records[name] = { value, updatedAt: seedTimestamp() };
        }
        return payload;
      });
      vaultId = vault.id;
    } finally {
      await session.close();
    }
  } finally {
    await store.close();
  }

  const profileConfigDir = join(directory, 'profiles');
  const registry = await DatastoreProfileRegistry.open({
    configDirectory: profileConfigDir,
  });
  const profile: DatastoreProfile = {
    id: profileIdSchema.parse('exec'),
    datastore: 'file',
    databaseId: initialized.databaseId,
    dataFile,
    keyFile,
  };
  await registry.add(profile);
  await registry.use(profile.id);
  await registry.setDefaultVaultId(profile.id, vaultId, initialized.databaseId);

  return {
    directory,
    dataFile,
    keyFile,
    vaultId,
    routingArgs: ['--profile', 'exec', '--profile-config-dir', profileConfigDir],
  };
}

export async function destroyFixture(fixture: ExecutionFixture): Promise<void> {
  await rm(fixture.directory, { force: true, recursive: true });
}

export interface CliRunResult {
  readonly stdout: string;
  readonly stderr: string;
  /** The stable exit code runLocalCli produced for this invocation. */
  readonly exitCode: number;
}

/**
 * Runs the real CLI composition end to end, feeding stdin frames and
 * capturing stdout, stderr, and the resulting process exit code.
 */
export async function runCli(
  args: readonly string[],
  stdinInput = '',
): Promise<CliRunResult> {
  const originalStdin = process.stdin;
  const originalExitCode = typeof process.exitCode === 'number' ? process.exitCode : 0;
  const stdout: string[] = [];
  const stderr: string[] = [];
  Object.defineProperty(process, 'stdin', {
    configurable: true,
    value: Readable.from(stdinInput.length === 0 ? [] : [stdinInput]),
  });
  const writeOut = vi.spyOn(process.stdout, 'write').mockImplementation((chunk) => {
    stdout.push(String(chunk));
    return true;
  });
  const writeErr = vi.spyOn(process.stderr, 'write').mockImplementation((chunk) => {
    stderr.push(String(chunk));
    return true;
  });
  try {
    await runLocalCli(['node', 'kavrix', ...args]);
  } finally {
    writeOut.mockRestore();
    writeErr.mockRestore();
    Object.defineProperty(process, 'stdin', {
      configurable: true,
      value: originalStdin,
    });
    if (process.platform === 'win32') {
      await new Promise<void>((resolve) => setTimeout(resolve, 25));
    }
  }
  const observed = typeof process.exitCode === 'number' ? process.exitCode : 0;
  process.exitCode = originalExitCode === 0 ? undefined : originalExitCode;
  return { stdout: stdout.join(''), stderr: stderr.join(''), exitCode: observed };
}

export function passphraseFrame(): string {
  return `${EXEC_PASSPHRASE}\n`;
}

/** Feeds stdin frames while an in-process handler runs. */
export async function withStdinFrames<T>(
  input: string,
  operation: () => Promise<T>,
): Promise<T> {
  const originalStdin = process.stdin;
  Object.defineProperty(process, 'stdin', {
    configurable: true,
    value: Readable.from(input.length === 0 ? [] : [input]),
  });
  try {
    return await operation();
  } finally {
    Object.defineProperty(process, 'stdin', {
      configurable: true,
      value: originalStdin,
    });
    if (process.platform === 'win32') {
      await new Promise<void>((resolve) => setTimeout(resolve, 25));
    }
  }
}
