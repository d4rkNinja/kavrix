import {
  AuthenticationError,
  decryptStateEnvelope,
  openDatabaseBackupArchive,
  parseDatabaseBackupArchive,
  zeroize,
} from '@kavrix/crypto';
import { authorizationStatePath, readSecureFile } from '@kavrix/key-files';
import {
  authorizationStateDocumentSchema,
  authorizationStateEnvelopeSchema,
  canonicalJson,
  fileDatabaseContainerSchema,
  firewallBackupBundleSchema,
  MAX_AUTHORIZATION_STATE_BYTES,
  MAX_DATABASE_BACKUP_PLAINTEXT_BYTES,
  type DatabaseId,
  type FirewallBackupBundle,
  type AuthorizationStateEnvelope,
} from '@kavrix/schemas';
import {
  openDatabaseAuthorizationStateAccess,
  readDatabaseFlatSecrets,
  type DatabaseFlatCommandOptions,
} from './database-flat-commands.js';
import { AuthorizationState } from './execution/authorization-state.js';
import {
  invalidConfiguration,
  securityIntegrityFailure,
  authenticationFailure,
} from './execution/exit-codes.js';

async function readEnvelope(
  keyFile: string,
): Promise<AuthorizationStateEnvelope | null> {
  try {
    return authorizationStateEnvelopeSchema.parse(
      JSON.parse(
        Buffer.from(
          await readSecureFile(
            authorizationStatePath(keyFile),
            MAX_AUTHORIZATION_STATE_BYTES,
          ),
        ).toString('utf8'),
      ) as unknown,
    );
  } catch (error) {
    if ((error as { code?: unknown }).code === 'KEY_FILE_NOT_FOUND') return null;
    throw error;
  }
}

/** Reject a source that changes while its independently atomic files are copied. */
export async function packFirewallBackup(
  dataFile: string,
  keyFile: string,
  databaseId: DatabaseId,
): Promise<Uint8Array> {
  const database = await readSecureFile(dataFile, MAX_DATABASE_BACKUP_PLAINTEXT_BYTES);
  const authorization = await readEnvelope(keyFile);
  const again = await readSecureFile(dataFile, MAX_DATABASE_BACKUP_PLAINTEXT_BYTES);
  const againAuthorization = await readEnvelope(keyFile);
  if (
    !Buffer.from(database).equals(again) ||
    canonicalJson(authorization) !== canonicalJson(againAuthorization)
  )
    throw securityIntegrityFailure(
      'Database or firewall state changed during backup; retry.',
    );
  const container = fileDatabaseContainerSchema.parse(
    JSON.parse(Buffer.from(database).toString('utf8')) as unknown,
  );
  if (container.database.id !== databaseId)
    throw securityIntegrityFailure('Backup database binding is invalid.');
  const bundle = firewallBackupBundleSchema.parse({
    format: 'kavrix-firewall-backup',
    version: 1,
    databaseId,
    database: Buffer.from(database).toString('base64url'),
    authorization,
  });
  return new TextEncoder().encode(canonicalJson(bundle));
}

export function unpackFirewallBackup(
  bytes: Uint8Array,
  databaseId: string,
  version: 1 | 2 = 1,
): { database: Uint8Array; bundle?: FirewallBackupBundle } {
  let decoded: unknown;
  try {
    decoded = JSON.parse(Buffer.from(bytes).toString('utf8'));
  } catch {
    if (version === 2)
      throw securityIntegrityFailure('Firewall recovery payload is malformed.');
    return { database: bytes };
  }
  if (
    decoded === null ||
    typeof decoded !== 'object' ||
    Reflect.get(decoded, 'format') !== 'kavrix-firewall-backup'
  ) {
    if (version === 2)
      throw securityIntegrityFailure('Firewall recovery payload is malformed.');
    return { database: bytes };
  }
  if (version !== 2)
    throw securityIntegrityFailure('Firewall recovery envelope version is invalid.');
  const bundle = firewallBackupBundleSchema.parse(decoded);
  const database = Buffer.from(bundle.database, 'base64url');
  const container = fileDatabaseContainerSchema.parse(
    JSON.parse(database.toString('utf8')) as unknown,
  );
  if (bundle.databaseId !== databaseId || container.database.id !== databaseId)
    throw securityIntegrityFailure('Recovery database binding is invalid.');
  return { database, bundle };
}

/** Two-stage restore: first the database, then explicit authenticated policy recovery. */
export type FirewallRestoreOptions = DatabaseFlatCommandOptions & {
  file?: string;
  overwrite?: boolean;
};
export async function restoreFirewallState(
  options: FirewallRestoreOptions,
): Promise<unknown> {
  if (options.file === undefined) throw invalidConfiguration('--file is required.');
  const archiveBytes = await readSecureFile(
    options.file,
    MAX_DATABASE_BACKUP_PLAINTEXT_BYTES,
  );
  let archive;
  try {
    archive = parseDatabaseBackupArchive(archiveBytes);
  } catch {
    throw securityIntegrityFailure('The backup archive is invalid.');
  }
  const secrets = await readDatabaseFlatSecrets(options, ['archive-passphrase'], {
    requireVaultSelection: false,
  });
  const passphrase = new TextEncoder().encode(secrets.extras[0] ?? '');
  let opened;
  try {
    opened = await openDatabaseBackupArchive(archive, passphrase);
  } catch (error) {
    if (error instanceof AuthenticationError)
      throw authenticationFailure(
        'Backup authentication failed. Check the archive passphrase and the file integrity.',
      );
    throw securityIntegrityFailure('The backup archive is invalid.');
  } finally {
    zeroize(passphrase);
  }
  try {
    const { bundle } = unpackFirewallBackup(
      opened.plaintext,
      opened.header.databaseId,
      archive.version,
    );
    if (bundle?.authorization == null)
      throw invalidConfiguration('The archive contains no recoverable firewall state.');
    const access = await openDatabaseAuthorizationStateAccess(options, secrets);
    let state: AuthorizationState | undefined;
    let plaintext: Uint8Array | undefined;
    try {
      if (access.databaseId !== bundle.databaseId)
        throw securityIntegrityFailure('Recovery belongs to another database.');
      const envelope = bundle.authorization;
      try {
        plaintext = await decryptStateEnvelope(envelope, access.authorizationStateKey, {
          domain: 'kavrix/authorization-state/v1',
          scopeKind: 'database',
          scopeId: access.databaseId,
          sequence: envelope.sequence,
        });
      } catch {
        throw securityIntegrityFailure(
          'The archived firewall state failed authentication.',
        );
      }
      const recovered = authorizationStateDocumentSchema.parse(
        JSON.parse(Buffer.from(plaintext).toString('utf8')) as unknown,
      );
      state = await AuthorizationState.open(
        access.keyFile,
        access.authorizationStateKey,
        { scopeKind: 'database', scopeId: access.databaseId },
      );
      await state.mutate((view) => {
        if (
          options.overwrite !== true &&
          (Object.keys(view.snapshot.policies).length > 0 ||
            Object.keys(view.snapshot.grants).length > 0)
        )
          throw invalidConfiguration(
            'Existing firewall state requires explicit --overwrite.',
          );
        view.next((draft) => {
          const last = draft.audit.at(-1)?.seq ?? 0;
          draft.policies = recovered.policies;
          draft.grants = {};
          draft.audit = [...draft.audit, ...recovered.audit]
            .slice(-511)
            .map((event, index) => ({ ...event, seq: last + index + 1 }));
          draft.audit.push({
            seq: (draft.audit.at(-1)?.seq ?? last) + 1,
            occurredAt: new Date().toISOString(),
            actor: 'user',
            action: 'firewall-restored',
          });
        });
      });
      return {
        firewallRestored: true,
        policies: Object.keys(recovered.policies).length,
        discardedGrants: Object.keys(recovered.grants).length,
      };
    } finally {
      state?.close();
      zeroize(plaintext);
      zeroize(access.authorizationStateKey);
    }
  } finally {
    zeroize(opened.plaintext);
  }
}
