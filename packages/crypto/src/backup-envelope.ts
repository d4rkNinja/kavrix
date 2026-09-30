import { randomBytes } from 'node:crypto';

import {
  canonicalJson,
  databaseBackupArchiveSchema,
  MAX_DATABASE_BACKUP_PLAINTEXT_BYTES,
  type DatabaseBackupArchive,
  type DatabaseId,
} from '@kavrix/schemas';
import sodium from 'libsodium-wrappers';

import { decodeBase64Url, encodeBase64Url, zeroize } from './bytes.js';
import { AuthenticationError, CryptoInputError } from './errors.js';
import { createPassphraseDerivation, derivePassphraseKek } from './keys.js';

const BACKUP_ARCHIVE_NONCE_BYTES = 24;
const BACKUP_AAD_DOMAIN = Buffer.from('kavrix/database-backup-aad/v1', 'ascii');

/** Authenticated header fields of an archive; the crypto fields are appended by sealing. */
export type BackupArchiveHeader = Readonly<{
  datastore: 'file';
  databaseId: DatabaseId;
}>;

function headerBytes(
  archive: Omit<DatabaseBackupArchive, 'nonce' | 'authenticationTag' | 'ciphertext'>,
): Uint8Array {
  const encoded = Buffer.from(
    canonicalJson({
      format: archive.format,
      version: archive.version,
      createdAt: archive.createdAt,
      datastore: archive.datastore,
      databaseId: archive.databaseId,
      plaintextBytes: archive.plaintextBytes,
      derivation: archive.derivation,
    }),
    'utf8',
  );
  const length = Buffer.allocUnsafe(4);
  length.writeUInt32BE(encoded.byteLength);
  return Buffer.concat([BACKUP_AAD_DOMAIN, length, encoded]);
}

/**
 * Seals one local database file into a passphrase-protected archive document.
 *
 * The Argon2id key-encryption key stretched from the passphrase seals the
 * database bytes with XChaCha20-Poly1305; the canonical header — including the
 * opaque database identity and exact plaintext length — is the associated
 * data, so an archive cannot be relabeled, truncated, or spliced without
 * failing authentication. The passphrase itself is never stored.
 */
export async function sealDatabaseBackupArchive(
  plaintext: Uint8Array,
  passphrase: Uint8Array,
  header: BackupArchiveHeader,
): Promise<DatabaseBackupArchive> {
  if (
    !(plaintext instanceof Uint8Array) ||
    plaintext.byteLength === 0 ||
    plaintext.byteLength > MAX_DATABASE_BACKUP_PLAINTEXT_BYTES
  ) {
    throw new CryptoInputError(
      'Backup plaintext is empty or outside the supported range',
    );
  }
  const derivation = createPassphraseDerivation();
  const kek = await derivePassphraseKek(passphrase, derivation);
  const base = {
    format: 'kavrix-database-backup' as const,
    version: 1 as const,
    createdAt: new Date().toISOString(),
    datastore: header.datastore,
    databaseId: header.databaseId,
    plaintextBytes: plaintext.byteLength,
    derivation,
  };
  const aad = headerBytes(base);
  const nonce = randomBytes(BACKUP_ARCHIVE_NONCE_BYTES);
  try {
    await sodium.ready;
    const encrypted = sodium.crypto_aead_xchacha20poly1305_ietf_encrypt_detached(
      plaintext,
      aad,
      null,
      nonce,
      kek,
    );
    return {
      ...base,
      nonce: encodeBase64Url(nonce),
      ciphertext: encodeBase64Url(encrypted.ciphertext),
      authenticationTag: encodeBase64Url(encrypted.mac),
    };
  } finally {
    zeroize(kek);
    zeroize(aad);
    zeroize(nonce);
  }
}

/**
 * Parses untrusted archive bytes and returns the validated document without
 * deriving any key. Unknown fields, versions, or malformed encodings fail
 * closed before any cryptographic work.
 */
export function parseDatabaseBackupArchive(bytes: Uint8Array): DatabaseBackupArchive {
  let text: string;
  try {
    text = Buffer.from(bytes).toString('utf8');
  } catch {
    throw new CryptoInputError('Backup archive is not valid UTF-8 JSON');
  }
  let parsed: unknown;
  try {
    parsed = JSON.parse(text);
  } catch {
    throw new CryptoInputError('Backup archive is not valid JSON');
  }
  return databaseBackupArchiveSchema.parse(parsed);
}

/**
 * Authenticates and opens one archive document under its passphrase.
 *
 * The stored header is the expected associated data, so any field tampering
 * fails the AEAD before plaintext exists. A wrong passphrase and a modified
 * archive are deliberately indistinguishable: both fail with a generic
 * authentication error.
 */
export async function openDatabaseBackupArchive(
  archive: DatabaseBackupArchive,
  passphrase: Uint8Array,
): Promise<{ header: BackupArchiveHeader; plaintext: Uint8Array; createdAt: string }> {
  const aad = headerBytes(archive);
  let kek: Uint8Array | undefined;
  let nonce: Uint8Array | undefined;
  let ciphertext: Uint8Array | undefined;
  let tag: Uint8Array | undefined;
  let plaintext: Uint8Array | undefined;
  try {
    kek = await derivePassphraseKek(passphrase, archive.derivation);
    nonce = decodeBase64Url(archive.nonce, { exactBytes: BACKUP_ARCHIVE_NONCE_BYTES });
    ciphertext = decodeBase64Url(archive.ciphertext);
    tag = decodeBase64Url(archive.authenticationTag, {
      exactBytes: 16,
    });
    if (ciphertext.byteLength !== archive.plaintextBytes) {
      throw new AuthenticationError();
    }
    await sodium.ready;
    try {
      plaintext = sodium.crypto_aead_xchacha20poly1305_ietf_decrypt_detached(
        null,
        ciphertext,
        tag,
        aad,
        nonce,
        kek,
      );
    } catch {
      throw new AuthenticationError();
    }
    return {
      header: { datastore: archive.datastore, databaseId: archive.databaseId },
      plaintext,
      createdAt: archive.createdAt,
    };
  } finally {
    zeroize(kek);
    zeroize(nonce);
    zeroize(ciphertext);
    zeroize(tag);
    zeroize(aad);
  }
}

/** Clears an opened backup plaintext buffer. Callers hold the only reference after this. */
export function discardBackupPlaintext(plaintext: Uint8Array): void {
  zeroize(plaintext);
}
