import {
  discardBackupPlaintext,
  openDatabaseBackupArchive,
  parseDatabaseBackupArchive,
  sealDatabaseBackupArchive,
} from '@kavrix/crypto';
import {
  deleteSecureFile,
  readSecureFile,
  writeSecureStreamFile,
} from '@kavrix/key-files';
import {
  MAX_DATABASE_BACKUP_PLAINTEXT_BYTES,
  profileIdSchema,
  type DatabaseId,
  type ProfileId,
} from '@kavrix/schemas';

import { LocalCliError } from './cli-error.js';
import {
  DatastoreProfileRegistry,
  type DatastoreProfile,
} from './datastore-profiles.js';
import {
  authenticationFailure,
  invalidConfiguration,
  securityIntegrityFailure,
} from './execution/exit-codes.js';
import { LocalSecretInput } from './local-secrets.js';

export interface BackupCommandOptions {
  readonly profile?: string;
  readonly profileConfigDir?: string;
  readonly configDir?: string;
  readonly file?: string;
  readonly dataFile?: string;
  readonly passphraseStdin?: boolean;
  readonly overwrite?: boolean;
  readonly json?: boolean;
}

const NO_PROFILE_MESSAGE =
  'No datastore profile is selected. Create one with `kavrix db profile add`, or pass --profile.';

async function resolveFileBackupProfile(
  options: BackupCommandOptions,
): Promise<Readonly<{ dataFile: string; databaseId: DatabaseId }>> {
  const configDirectory = options.profileConfigDir ?? options.configDir;
  const registryOptions = configDirectory === undefined ? {} : { configDirectory };
  const registry =
    options.profile === undefined
      ? await DatastoreProfileRegistry.openIfPresent(registryOptions)
      : await DatastoreProfileRegistry.open(registryOptions);
  if (registry === null) throw invalidConfiguration(NO_PROFILE_MESSAGE);
  if (options.profile === undefined) {
    const current = await registry.current();
    if (current === null) throw invalidConfiguration(NO_PROFILE_MESSAGE);
    return assertFileProfile(current);
  }
  let parsed: ProfileId;
  try {
    parsed = profileIdSchema.parse(options.profile);
  } catch {
    throw new LocalCliError('Profile ID is invalid.');
  }
  return assertFileProfile(await registry.get(parsed));
}

function assertFileProfile(
  profile: DatastoreProfile,
): Readonly<{ dataFile: string; databaseId: DatabaseId }> {
  if (profile.datastore !== 'file') {
    throw invalidConfiguration(
      'Backup supports local-file datastore profiles only in this release; MongoDB database backup is not available yet.',
    );
  }
  if (profile.databaseId === undefined) {
    throw invalidConfiguration(
      'The selected datastore profile is not bound to a database; run `kavrix db init` for that profile first.',
    );
  }
  return { dataFile: profile.dataFile, databaseId: profile.databaseId };
}

/** Reads the new backup passphrase as a confirmed pair (masked, or two stdin frames). */
async function readNewBackupPassphrase(
  options: BackupCommandOptions,
): Promise<Uint8Array> {
  const input = new LocalSecretInput(process.stdin, process.stderr);
  const frames =
    options.passphraseStdin === true
      ? await input.read(['new-passphrase', 'new-passphrase'], true)
      : await input.readConfirmed('new-passphrase');
  const [first, confirmed] = frames as readonly [string, string];
  if (first !== confirmed) {
    throw new LocalCliError('Backup passphrases do not match.');
  }
  return new TextEncoder().encode(first);
}

/** Reads the existing backup passphrase (masked prompt, or one stdin frame). */
async function readExistingBackupPassphrase(
  options: BackupCommandOptions,
): Promise<Uint8Array> {
  const input = new LocalSecretInput(process.stdin, process.stderr);
  const frames =
    options.passphraseStdin === true
      ? await input.read(['passphrase'], true)
      : await input.read(['passphrase'], false);
  return new TextEncoder().encode(frames[0] ?? '');
}

function requirePath(value: string | undefined, flag: string): string {
  if (value === undefined || value.length === 0) {
    throw new LocalCliError(`Missing required ${flag} <path>.`);
  }
  return value;
}

function writeJsonResult(value: unknown): void {
  process.stdout.write(JSON.stringify(value) + '\n');
}

/** Publishes protected bytes as a new file; --overwrite replaces an existing one. */
async function publishProtectedFile(
  path: string,
  contents: Uint8Array,
  overwrite: boolean,
  subject: string,
  maximumBytes: number,
): Promise<void> {
  const source = async function* (): AsyncIterable<Uint8Array> {
    await Promise.resolve();
    yield contents;
  };
  try {
    await writeSecureStreamFile(path, source(), maximumBytes);
  } catch (error) {
    const code = (error as { code?: unknown }).code;
    if (code === 'KEY_FILE_ALREADY_EXISTS') {
      if (!overwrite) {
        throw new LocalCliError(
          `${subject} already exists. Re-run with --overwrite to replace it.`,
        );
      }
      await deleteSecureFile(path, maximumBytes);
      await writeSecureStreamFile(path, source(), maximumBytes);
      return;
    }
    throw error;
  }
}

async function openArchiveFromPath(
  archivePath: string,
  passphrase: Uint8Array,
): Promise<{
  readonly databaseId: string;
  readonly createdAt: string;
  readonly plaintextBytes: number;
  readonly plaintext: Uint8Array;
}> {
  const bytes = await readSecureFile(archivePath, MAX_DATABASE_BACKUP_PLAINTEXT_BYTES);
  let parsed;
  try {
    parsed = parseDatabaseBackupArchive(bytes);
  } catch {
    throw securityIntegrityFailure(
      'The backup archive is not a valid Kavrix database backup.',
    );
  }
  try {
    const opened = await openDatabaseBackupArchive(parsed, passphrase);
    return {
      databaseId: opened.header.databaseId,
      createdAt: opened.createdAt,
      plaintextBytes: parsed.plaintextBytes,
      plaintext: opened.plaintext,
    };
  } catch {
    // A wrong passphrase and a modified archive are deliberately
    // indistinguishable: one generic authentication failure.
    throw authenticationFailure(
      'Backup authentication failed. Check the archive passphrase and the file integrity.',
    );
  }
}

export async function handleBackupCreate(options: BackupCommandOptions): Promise<void> {
  const archivePath = requirePath(options.file, '--file');
  const profile = await resolveFileBackupProfile(options);
  const passphrase = await readNewBackupPassphrase(options);
  const databaseBytes = await readSecureFile(
    profile.dataFile,
    MAX_DATABASE_BACKUP_PLAINTEXT_BYTES,
  );
  const archive = await sealDatabaseBackupArchive(databaseBytes, passphrase, {
    datastore: 'file',
    databaseId: profile.databaseId,
  });
  const serialized = new TextEncoder().encode(JSON.stringify(archive));
  await publishProtectedFile(
    archivePath,
    serialized,
    options.overwrite === true,
    'Backup file',
    MAX_DATABASE_BACKUP_PLAINTEXT_BYTES,
  );
  if (options.json === true) {
    writeJsonResult({
      created: true,
      file: archivePath,
      databaseId: archive.databaseId,
      plaintextBytes: archive.plaintextBytes,
      archiveBytes: serialized.byteLength,
      createdAt: archive.createdAt,
    });
    return;
  }
  process.stdout.write(
    [
      `Backup archive created: ${archivePath}`,
      `Database: ${archive.databaseId}`,
      `Sealed bytes: ${String(archive.plaintextBytes)}`,
      `Created at: ${archive.createdAt}`,
      'Keep the archive and its passphrase on separate protected media from the owner key.',
    ].join('\n') + '\n',
  );
}

export async function handleBackupVerify(options: BackupCommandOptions): Promise<void> {
  const archivePath = requirePath(options.file, '--file');
  const passphrase = await readExistingBackupPassphrase(options);
  const opened = await openArchiveFromPath(archivePath, passphrase);
  discardBackupPlaintext(opened.plaintext);
  if (options.json === true) {
    writeJsonResult({
      valid: true,
      file: archivePath,
      databaseId: opened.databaseId,
      plaintextBytes: opened.plaintextBytes,
      createdAt: opened.createdAt,
    });
    return;
  }
  process.stdout.write(
    [
      `Backup archive verified: ${archivePath}`,
      `Database: ${opened.databaseId}`,
      `Sealed bytes: ${String(opened.plaintextBytes)}`,
      `Created at: ${opened.createdAt}`,
    ].join('\n') + '\n',
  );
}

export async function handleBackupRestore(
  options: BackupCommandOptions,
): Promise<void> {
  const archivePath = requirePath(options.file, '--file');
  const dataFile = requirePath(options.dataFile, '--data-file');
  const passphrase = await readExistingBackupPassphrase(options);
  const opened = await openArchiveFromPath(archivePath, passphrase);
  try {
    await publishProtectedFile(
      dataFile,
      opened.plaintext,
      options.overwrite === true,
      'Destination file',
      MAX_DATABASE_BACKUP_PLAINTEXT_BYTES,
    );
  } finally {
    discardBackupPlaintext(opened.plaintext);
  }
  if (options.json === true) {
    writeJsonResult({
      restored: true,
      file: archivePath,
      dataFile,
      databaseId: opened.databaseId,
      plaintextBytes: opened.plaintextBytes,
    });
    return;
  }
  process.stdout.write(
    [
      `Database file restored: ${dataFile}`,
      `Database: ${opened.databaseId}`,
      'Next: point a profile at the restored file with `kavrix db profile add <id> --datastore file --data-file <path> --key-file <key-path>`,',
      'then unlock with the existing owner key, or recover ownership with `kavrix db recovery use` and a database recovery kit.',
    ].join('\n') + '\n',
  );
}
