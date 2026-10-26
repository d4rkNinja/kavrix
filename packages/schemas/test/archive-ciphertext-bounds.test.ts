import { describe, expect, it } from 'vitest';

import {
  DEFAULT_MAX_BACKUP_RECORDS,
  MAX_ARGON2_MEMORY_KIB,
  MAX_CIPHERTEXT_CHARS,
  MAX_DATABASE_BACKUP_CIPHERTEXT_CHARS,
  MAX_DATABASE_BACKUP_PLAINTEXT_BYTES,
  MAX_VAULT_EXPORT_CIPHERTEXT_CHARS,
  MAX_VAULT_EXPORT_PLAINTEXT_BYTES,
  base64UrlSchema,
  databaseBackupArchiveSchema,
  encryptedBackupFooterSchema,
  maxBase64UrlCharsForByteLimit,
  vaultExportArchiveSchema,
} from '../src/index.js';

const DERIVATION = {
  algorithm: 'argon2id',
  version: 1,
  salt: 'A'.repeat(22),
  memoryKiB: MAX_ARGON2_MEMORY_KIB,
  passes: 3,
  parallelism: 4,
  outputLength: 32,
} as const;

function encodeBase64Url(bytes: number): string {
  return Buffer.alloc(bytes, 1).toString('base64url');
}

describe('maxBase64UrlCharsForByteLimit', () => {
  it('computes the exact canonical unpadded character count for a byte limit', () => {
    expect(maxBase64UrlCharsForByteLimit(1)).toBe(2);
    expect(maxBase64UrlCharsForByteLimit(2)).toBe(3);
    expect(maxBase64UrlCharsForByteLimit(3)).toBe(4);
    expect(maxBase64UrlCharsForByteLimit(4)).toBe(6);
    expect(maxBase64UrlCharsForByteLimit(5)).toBe(7);
    expect(maxBase64UrlCharsForByteLimit(6)).toBe(8);
    expect(maxBase64UrlCharsForByteLimit(MAX_CIPHERTEXT_CHARS)).toBe(
      4 * Math.floor(MAX_CIPHERTEXT_CHARS / 3) + (MAX_CIPHERTEXT_CHARS % 3),
    );
  });

  it('keeps the archive ceilings consistent with their advertised byte bounds', () => {
    expect(MAX_DATABASE_BACKUP_CIPHERTEXT_CHARS).toBe(
      maxBase64UrlCharsForByteLimit(MAX_DATABASE_BACKUP_PLAINTEXT_BYTES),
    );
    expect(MAX_VAULT_EXPORT_CIPHERTEXT_CHARS).toBe(
      maxBase64UrlCharsForByteLimit(MAX_VAULT_EXPORT_PLAINTEXT_BYTES),
    );
  });
});

describe('database backup archive ciphertext bounds', () => {
  it('accepts a backup whose ciphertext exceeds the shared record-level character cap', () => {
    const plaintextBytes = Math.floor((MAX_CIPHERTEXT_CHARS * 3) / 4) + 1_572_864;
    const archive = {
      format: 'kavrix-database-backup',
      version: 1,
      createdAt: '2026-01-01T00:00:00.000Z',
      datastore: 'file',
      databaseId: 'db-1',
      plaintextBytes,
      derivation: DERIVATION,
      nonce: 'A'.repeat(32),
      authenticationTag: 'A'.repeat(22),
      ciphertext: encodeBase64Url(plaintextBytes),
    };

    expect(plaintextBytes).toBeLessThanOrEqual(MAX_DATABASE_BACKUP_PLAINTEXT_BYTES);
    expect(archive.ciphertext.length).toBeGreaterThan(MAX_CIPHERTEXT_CHARS);
    expect(base64UrlSchema.safeParse(archive.ciphertext).success).toBe(false);
    expect(databaseBackupArchiveSchema.safeParse(archive).success).toBe(true);
  });

  it('rejects a backup whose ciphertext cannot decode within the plaintext bound', () => {
    const archive = {
      format: 'kavrix-database-backup',
      version: 1,
      createdAt: '2026-01-01T00:00:00.000Z',
      datastore: 'file',
      databaseId: 'db-1',
      plaintextBytes: MAX_DATABASE_BACKUP_PLAINTEXT_BYTES,
      derivation: DERIVATION,
      nonce: 'A'.repeat(32),
      authenticationTag: 'A'.repeat(22),
      ciphertext: 'A'.repeat(MAX_DATABASE_BACKUP_CIPHERTEXT_CHARS + 1),
    };

    const result = databaseBackupArchiveSchema.safeParse(archive);
    expect(result.success).toBe(false);
    if (!result.success) {
      expect(result.error.issues[0]?.code).toBe('too_big');
    }
  });
});

describe('vault export archive ciphertext bounds', () => {
  it('accepts an export whose ciphertext exceeds the shared record-level character cap', () => {
    const plaintextBytes = Math.floor((MAX_CIPHERTEXT_CHARS * 3) / 4) + 1_572_864;
    const archive = {
      format: 'kavrix-vault-export',
      version: 1,
      createdAt: '2026-01-01T00:00:00.000Z',
      entryCount: 1,
      plaintextBytes,
      derivation: DERIVATION,
      nonce: 'A'.repeat(32),
      authenticationTag: 'A'.repeat(22),
      ciphertext: encodeBase64Url(plaintextBytes),
    };

    expect(archive.ciphertext.length).toBeGreaterThan(MAX_CIPHERTEXT_CHARS);
    expect(plaintextBytes).toBeLessThanOrEqual(MAX_VAULT_EXPORT_PLAINTEXT_BYTES);
    expect(vaultExportArchiveSchema.safeParse(archive).success).toBe(true);
  });
});

describe('encrypted backup footer record count', () => {
  it('accepts record counts up to the backup record ceiling', () => {
    const footer = {
      type: 'footer',
      version: 1,
      recordCount: DEFAULT_MAX_BACKUP_RECORDS,
      transcriptSha256: 'A'.repeat(43),
      authenticationTag: 'A'.repeat(43),
    };
    expect(encryptedBackupFooterSchema.safeParse(footer).success).toBe(true);
  });

  it('rejects record counts the verification receipt could not represent', () => {
    const footer = {
      type: 'footer',
      version: 1,
      recordCount: DEFAULT_MAX_BACKUP_RECORDS + 1,
      transcriptSha256: 'A'.repeat(43),
      authenticationTag: 'A'.repeat(43),
    };
    expect(encryptedBackupFooterSchema.safeParse(footer).success).toBe(false);
  });
});
