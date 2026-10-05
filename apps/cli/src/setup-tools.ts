import { lstat, opendir, realpath } from 'node:fs/promises';
import { homedir } from 'node:os';
import { dirname, join, resolve } from 'node:path';
import {
  hardenExistingSecureDirectory,
  validateSecureFileDestination,
} from '@kavrix/key-files';
import { probeMongoConnection } from '@kavrix/storage';
import {
  setupToolActionSchema,
  setupToolResultSchema,
  type SetupToolAction,
  type SetupToolResult,
} from '@kavrix/schemas';

/** Host-owned, bounded filesystem and connection tools; no protected file reads. */
export async function runSetupTool(
  input: SetupToolAction,
  managedDirectory: string,
): Promise<SetupToolResult> {
  const action = setupToolActionSchema.parse(input);
  if (action.type === 'test-setup-mongodb')
    return {
      kind: 'connection',
      status: await probeMongoConnection(action.databaseUrl, action.database),
    };
  if (action.type === 'repair-setup-directory') {
    const managed = resolve(managedDirectory);
    const metadata = await lstat(managed);
    if (
      !metadata.isDirectory() ||
      metadata.isSymbolicLink() ||
      managed === dirname(managed) ||
      managed === resolve(homedir())
    )
      throw new Error(
        'Repair is limited to the Kavrix artifact directory. Choose a secure default or repair this location manually.',
      );
    const directory = await realpath(managed);
    if (
      (await realpath(dirname(resolve(action.path)))) !== directory ||
      (await realpath(homedir())) === directory
    )
      throw new Error(
        'This destination is outside the Kavrix artifact directory. Choose a secure default; other folders are never changed.',
      );
    if (process.platform !== 'win32' && metadata.uid !== process.getuid?.())
      throw new Error('The selected Kavrix folder is not owned by the current user.');
    if (action.mode === 'apply') {
      await hardenExistingSecureDirectory(managed);
      await validateSecureFileDestination(action.path);
    }
    return setupToolResultSchema.parse({
      kind: 'repair',
      directory,
      mode: action.mode,
    });
  }
  const directory = await realpath(action.path);
  const entries: { name: string; path: string }[] = [];
  let scanned = 0;
  let truncated = false;
  const handle = await opendir(directory);
  for await (const entry of handle) {
    if (++scanned > 1000 || entries.length === 100) {
      truncated = true;
      break;
    }
    if (entry.isDirectory() && !entry.isSymbolicLink())
      entries.push({ name: entry.name, path: join(directory, entry.name) });
  }
  entries.sort((left, right) => left.name.localeCompare(right.name));
  return setupToolResultSchema.parse({
    kind: 'folders',
    directory,
    parent: dirname(directory),
    entries,
    truncated,
  });
}

export function connectionNotice(
  status: Extract<SetupToolResult, { kind: 'connection' }>['status'],
): string {
  switch (status) {
    case 'ok':
      return 'MongoDB connection and authentication verified. No vault records were read or created.';
    case 'invalid':
      return 'Check the MongoDB address syntax and database name. Nothing was created.';
    case 'transport':
      return 'Secure MongoDB transport is required. Use TLS for remote hosts; insecure TLS options are refused.';
    case 'authentication':
      return 'MongoDB authentication failed. Re-enter the connection credentials. Nothing was created.';
    case 'unreachable':
      return 'MongoDB could not be reached. Check the server, network, and TLS configuration, then test again.';
  }
}
