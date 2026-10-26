import {
  AuthenticationError,
  openVaultExportArchive,
  parseVaultExportArchive,
  sealVaultExportArchive,
  zeroize,
} from '@kavrix/crypto';
import { readSecureFile } from '@kavrix/key-files';
import {
  MAX_VAULT_EXPORT_ARCHIVE_BYTES,
  type VaultExportArchive,
  type VaultExportEntry,
} from '@kavrix/schemas';

import { publishProtectedFile } from './backup-command-impl.js';
import { LocalCliError } from './cli-error.js';
import {
  readDatabaseFlatSecrets,
  rejectUnboundDatabaseProfile,
  usesDatabaseContainer,
  withDatabaseFlatVault,
  type DatabaseFlatCommandOptions,
} from './database-flat-commands.js';
import {
  authenticationFailure,
  credentialMissing,
  securityIntegrityFailure,
} from './execution/exit-codes.js';
import {
  flatOptions,
  validateImportedName,
  type DatabaseVaultRoutingOptions,
} from './import-env-command-impl.js';

export type VaultExportCommandOptions = DatabaseVaultRoutingOptions &
  Readonly<{
    file?: string;
    prefix?: string;
    overwrite?: boolean;
    json?: boolean;
  }>;

export type ImportArchiveCommandOptions = VaultExportCommandOptions;

function requireFile(value: string | undefined): string {
  if (value === undefined || value.length === 0) {
    throw new LocalCliError('Missing required --file <path>.');
  }
  return value;
}

function requirePrefix(value: string | undefined): string {
  const prefix = value ?? '';
  // eslint-disable-next-line no-control-regex
  if (/[\u0000-\u001f\u007f]/u.test(prefix)) {
    throw new LocalCliError('--prefix must not contain control characters.');
  }
  return prefix;
}

async function requireDatabaseContainer(
  flat: DatabaseFlatCommandOptions,
  command: string,
): Promise<void> {
  await rejectUnboundDatabaseProfile(flat, command);
  if (!(await usesDatabaseContainer(flat))) {
    throw new LocalCliError(
      `${command} requires a database-container profile; legacy version 2 vaults are not supported.`,
    );
  }
}

function writeJson(value: unknown): void {
  process.stdout.write(JSON.stringify(value) + '\n');
}

export async function handleVaultExport(
  options: VaultExportCommandOptions,
): Promise<void> {
  const file = requireFile(options.file);
  const prefix = requirePrefix(options.prefix);
  const flat = flatOptions(options);
  await requireDatabaseContainer(flat, 'export');
  const secrets = await readDatabaseFlatSecrets(flat, [
    'new-passphrase',
    'new-passphrase',
  ]);
  const [archivePassphrase, confirmation] = secrets.extras;
  if (archivePassphrase === undefined || archivePassphrase !== confirmation) {
    throw new LocalCliError('Export passphrases do not match.');
  }
  let entries: VaultExportEntry[] = [];
  await withDatabaseFlatVault(flat, secrets, async (session, vaultId) => {
    await session.inspectVault(vaultId, (payload) => {
      entries = Object.entries(payload.records)
        .filter(([name]) => name.startsWith(prefix))
        .sort(([left], [right]) => (left < right ? -1 : left > right ? 1 : 0))
        .map(([name, record]) => ({
          name,
          value: record.value,
          updatedAt: record.updatedAt,
        }));
    });
  });
  if (entries.length === 0) {
    throw credentialMissing();
  }
  const passphrase = new TextEncoder().encode(archivePassphrase);
  let archive: VaultExportArchive;
  try {
    archive = await sealVaultExportArchive(entries, passphrase);
  } finally {
    zeroize(passphrase);
  }
  const names = entries.map((entry) => entry.name);
  const serialized = new TextEncoder().encode(JSON.stringify(archive));
  await publishProtectedFile(
    file,
    serialized,
    options.overwrite === true,
    'Export file',
    MAX_VAULT_EXPORT_ARCHIVE_BYTES,
  );
  if (options.json === true) {
    writeJson({
      exported: names.length,
      file,
      names,
      archiveBytes: serialized.byteLength,
      createdAt: archive.createdAt,
    });
    return;
  }
  process.stdout.write(
    [
      `Exported ${String(names.length)} credential${names.length === 1 ? '' : 's'} to ${file}.`,
      ...names.map((name) => `  ${name}`),
      'The archive holds decrypted values sealed under its own passphrase; store both separately.',
    ].join('\n') + '\n',
  );
}

export async function handleImportArchive(
  options: ImportArchiveCommandOptions,
): Promise<void> {
  const file = requireFile(options.file);
  const prefix = requirePrefix(options.prefix);
  // Parse the archive before any unlock material is requested, so a wrong
  // or damaged file fails closed without prompting.
  let archive: VaultExportArchive;
  try {
    archive = parseVaultExportArchive(
      await readSecureFile(file, MAX_VAULT_EXPORT_ARCHIVE_BYTES),
    );
  } catch (error) {
    if ((error as { name?: unknown }).name === 'PortableKeyFileError') throw error;
    throw securityIntegrityFailure('The file is not a valid Kavrix export archive.');
  }
  const flat = flatOptions(options);
  await requireDatabaseContainer(flat, 'import archive');
  const secrets = await readDatabaseFlatSecrets(flat, ['archive-passphrase']);
  const passphrase = new TextEncoder().encode(secrets.extras[0] ?? '');
  let entries: readonly VaultExportEntry[];
  try {
    entries = (await openVaultExportArchive(archive, passphrase)).entries;
  } catch (error) {
    // Only a genuine authentication failure (wrong passphrase or a tampered
    // archive) may surface as the authentication exit; any other error keeps
    // its own reviewed classification instead of masquerading as user error.
    if (!(error instanceof AuthenticationError)) throw error;
    throw authenticationFailure(
      'Export archive authentication failed. Check the archive passphrase and the file integrity.',
    );
  } finally {
    zeroize(passphrase);
  }
  const names = entries.map((entry) => `${prefix}${entry.name}`);
  for (const name of names) validateImportedName(name);
  await withDatabaseFlatVault(flat, secrets, async (session, vaultId) => {
    await session.updateVault(vaultId, (payload) => {
      const conflicts =
        options.overwrite === true
          ? []
          : names.filter((name) => Object.hasOwn(payload.records, name));
      if (conflicts.length > 0) {
        throw new LocalCliError(
          `Credential already exists: ${String(conflicts[0])}${
            conflicts.length > 1 ? ` (and ${String(conflicts.length - 1)} more)` : ''
          }. Re-run with --overwrite to replace imported values.`,
        );
      }
      const updatedAt = new Date().toISOString();
      for (const [index, entry] of entries.entries()) {
        const name = names[index];
        if (name === undefined) continue;
        payload.records[name] = { value: entry.value, updatedAt };
      }
      return payload;
    });
  });
  if (options.json === true) {
    writeJson({ imported: names.length, file, names });
    return;
  }
  process.stdout.write(
    [
      `Imported ${String(names.length)} credential${names.length === 1 ? '' : 's'} from ${file} into the selected vault.`,
      ...names.map((name) => `  ${name}`),
    ].join('\n') + '\n',
  );
}
