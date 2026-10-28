import { randomBytes } from 'node:crypto';

import {
  canonicalJson,
  MAX_VAULT_EXPORT_PLAINTEXT_BYTES,
  vaultExportArchiveSchema,
  vaultExportPlaintextSchema,
  type VaultExportArchive,
  type VaultExportEntry,
  type VaultExportPlaintext,
} from '@kavrix/schemas';
import sodium from 'libsodium-wrappers';

import { decodeBase64Url, encodeBase64Url, zeroize } from './bytes.js';
import { AuthenticationError, CryptoInputError } from './errors.js';
import { createPassphraseDerivation, derivePassphraseKek } from './keys.js';

const EXPORT_NONCE_BYTES = 24;
const EXPORT_TAG_BYTES = 16;
// Distinct from the database-backup domain, so neither archive kind can be
// presented as the other even under the same passphrase.
const EXPORT_AAD_DOMAIN = Buffer.from('kavrix/vault-export-aad/v1', 'ascii');

type ExportHeader = Omit<
  VaultExportArchive,
  'nonce' | 'authenticationTag' | 'ciphertext'
>;

function headerBytes(header: ExportHeader): Uint8Array {
  const encoded = Buffer.from(
    canonicalJson({
      format: header.format,
      version: header.version,
      createdAt: header.createdAt,
      entryCount: header.entryCount,
      plaintextBytes: header.plaintextBytes,
      derivation: header.derivation,
    }),
    'utf8',
  );
  const length = Buffer.allocUnsafe(4);
  length.writeUInt32BE(encoded.byteLength);
  return Buffer.concat([EXPORT_AAD_DOMAIN, length, encoded]);
}

/**
 * Seals decrypted vault entries under an Argon2id-stretched passphrase with
 * XChaCha20-Poly1305. The canonical header, including the entry count and
 * exact plaintext length, is the associated data.
 */
export async function sealVaultExportArchive(
  entries: readonly VaultExportEntry[],
  passphrase: Uint8Array,
  details?: Pick<VaultExportPlaintext, 'structured' | 'policies'>,
): Promise<VaultExportArchive> {
  const validated = vaultExportPlaintextSchema.parse({
    entries: [...entries],
    ...details,
  });
  const plaintext = Buffer.from(canonicalJson(validated), 'utf8');
  let kek: Uint8Array | undefined;
  let aad: Uint8Array | undefined;
  let nonce: Uint8Array | undefined;
  try {
    if (plaintext.byteLength > MAX_VAULT_EXPORT_PLAINTEXT_BYTES) {
      throw new CryptoInputError('Export plaintext exceeds the supported size');
    }
    const derivation = createPassphraseDerivation();
    kek = await derivePassphraseKek(passphrase, derivation);
    const header: ExportHeader = {
      format: 'kavrix-vault-export',
      version: validated.structured === undefined ? 1 : 2,
      createdAt: new Date().toISOString(),
      entryCount: validated.structured?.items.length ?? validated.entries.length,
      plaintextBytes: plaintext.byteLength,
      derivation,
    };
    aad = headerBytes(header);
    nonce = randomBytes(EXPORT_NONCE_BYTES);
    await sodium.ready;
    const encrypted = sodium.crypto_aead_xchacha20poly1305_ietf_encrypt_detached(
      plaintext,
      aad,
      null,
      nonce,
      kek,
    );
    return vaultExportArchiveSchema.parse({
      ...header,
      nonce: encodeBase64Url(nonce),
      ciphertext: encodeBase64Url(encrypted.ciphertext),
      authenticationTag: encodeBase64Url(encrypted.mac),
    });
  } finally {
    zeroize(plaintext);
    zeroize(kek);
    zeroize(aad);
    zeroize(nonce);
  }
}

/** Parses untrusted archive bytes without deriving any key. */
export function parseVaultExportArchive(bytes: Uint8Array): VaultExportArchive {
  let parsed: unknown;
  try {
    parsed = JSON.parse(Buffer.from(bytes).toString('utf8'));
  } catch {
    throw new CryptoInputError('Export archive is not valid JSON');
  }
  const result = vaultExportArchiveSchema.safeParse(parsed);
  if (!result.success) {
    throw new CryptoInputError('Export archive is not a valid Kavrix vault export');
  }
  return result.data;
}

/**
 * Authenticates and opens one export archive. A wrong passphrase and a
 * modified archive both fail with the same generic authentication error.
 */
export async function openVaultExportArchive(
  archive: VaultExportArchive,
  passphrase: Uint8Array,
): Promise<Readonly<VaultExportPlaintext & { createdAt: string }>> {
  const aad = headerBytes(archive);
  let kek: Uint8Array | undefined;
  let nonce: Uint8Array | undefined;
  let ciphertext: Uint8Array | undefined;
  let tag: Uint8Array | undefined;
  let plaintext: Uint8Array | undefined;
  try {
    kek = await derivePassphraseKek(passphrase, archive.derivation);
    nonce = decodeBase64Url(archive.nonce, { exactBytes: EXPORT_NONCE_BYTES });
    tag = decodeBase64Url(archive.authenticationTag, { exactBytes: EXPORT_TAG_BYTES });
    ciphertext = decodeBase64Url(archive.ciphertext, {
      // Same bound the export schema enforces; a cast object must not skip it
      // and force a large allocation before the byteLength check below.
      maximumBytes: MAX_VAULT_EXPORT_PLAINTEXT_BYTES,
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
    let decoded: unknown;
    try {
      decoded = JSON.parse(Buffer.from(plaintext).toString('utf8'));
    } catch {
      throw new CryptoInputError('Export plaintext is malformed');
    }
    const result = vaultExportPlaintextSchema.safeParse(decoded);
    if (
      !result.success ||
      (result.data.structured?.items.length ?? result.data.entries.length) !==
        archive.entryCount ||
      (archive.version === 1) !== (result.data.structured === undefined)
    ) {
      throw new CryptoInputError('Export plaintext is malformed');
    }
    return Object.freeze({
      ...result.data,
      createdAt: archive.createdAt,
    });
  } finally {
    zeroize(kek);
    zeroize(nonce);
    zeroize(ciphertext);
    zeroize(tag);
    zeroize(aad);
    zeroize(plaintext);
  }
}
