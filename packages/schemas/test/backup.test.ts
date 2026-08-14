import { describe, expect, it } from 'vitest';

import {
  backupRestoreStatusSchema,
  backupVerificationSchema,
  DEFAULT_MAX_BACKUP_RECORDS,
  MAX_SUPPORTED_BACKUP_BYTES,
  restoreKnownRecordsVerificationV1Schema,
  sha256DigestSchema,
  type BackupVerification,
  type RestoreKnownRecordsVerificationV1,
} from '../src/index.js';

const NOW = '2026-08-12T00:00:00.000Z';
const LATER = '2026-08-12T00:00:01.000Z';
const DIGEST = sha256DigestSchema.parse(Buffer.alloc(32, 0x11).toString('base64url'));
const OTHER_DIGEST = sha256DigestSchema.parse(
  Buffer.alloc(32, 0x22).toString('base64url'),
);

function backupSummary(
  overrides: Partial<BackupVerification> = {},
): BackupVerification {
  return backupVerificationSchema.parse({
    header: {
      type: 'header',
      format: 'kavrix-encrypted-backup',
      version: 1,
      vaultId: 'vault.1',
      schemaVersion: 1,
      createdAt: NOW,
      authentication: {
        algorithm: 'hkdf-sha256+hmac-sha256',
        salt: DIGEST,
      },
    },
    restoreSessionId: DIGEST,
    recordCount: 1,
    transcriptSha256: DIGEST,
    canonicalEntriesSha256: OTHER_DIGEST,
    ...overrides,
  });
}

function receipt(
  overrides: Partial<RestoreKnownRecordsVerificationV1> = {},
): RestoreKnownRecordsVerificationV1 {
  return restoreKnownRecordsVerificationV1Schema.parse({
    version: 1,
    scope: 'known-v1-records',
    vaultId: 'vault.1',
    vaultRevision: 0,
    restoreSessionId: DIGEST,
    transcriptSha256: DIGEST,
    canonicalEntriesSha256: OTHER_DIGEST,
    recordCount: 1,
    selectedSlot: {
      id: 'slot.1',
      type: 'portable-key',
      keyVersion: 1,
    },
    verified: {
      vaults: 1,
      groups: 0,
      items: 0,
      attachments: 0,
      attachmentHeaders: 0,
      attachmentChunks: 0,
      tombstonePredecessors: {
        groups: 0,
        items: 0,
        attachments: 0,
      },
      tombstones: 0,
      histories: 0,
      audits: 0,
    },
    ...overrides,
  });
}

describe('backupVerificationSchema', () => {
  it('strictly parses the authenticated summary and its staged-entry commitment', () => {
    const summary = backupSummary({ recordCount: DEFAULT_MAX_BACKUP_RECORDS });
    expect(summary.canonicalEntriesSha256).toBe(OTHER_DIGEST);

    expect(
      backupVerificationSchema.safeParse({ ...summary, unexpected: true }).success,
    ).toBe(false);
    expect(
      backupVerificationSchema.safeParse({
        ...summary,
        header: { ...summary.header, unexpected: true },
      }).success,
    ).toBe(false);
  });

  it.each([0, DEFAULT_MAX_BACKUP_RECORDS + 1, Number.MAX_SAFE_INTEGER + 1])(
    'rejects an out-of-bounds record count %s',
    (recordCount) => {
      expect(
        backupVerificationSchema.safeParse({
          ...backupSummary(),
          recordCount,
        }).success,
      ).toBe(false);
    },
  );

  it('pins the current header format, version, schema, and authentication algorithm', () => {
    const summary = backupSummary();
    const headerMutations = [
      { ...summary.header, format: 'other-encrypted-backup' },
      { ...summary.header, version: 2 },
      { ...summary.header, schemaVersion: 2 },
      {
        ...summary.header,
        authentication: {
          ...summary.header.authentication,
          algorithm: 'sha256',
        },
      },
    ];
    for (const header of headerMutations) {
      expect(backupVerificationSchema.safeParse({ ...summary, header }).success).toBe(
        false,
      );
    }
  });
});

describe('restoreKnownRecordsVerificationV1Schema', () => {
  it.each(['portable-key', 'passphrase', 'recovery-key'] as const)(
    'accepts a current %s slot without retaining credentials',
    (type) => {
      expect(
        restoreKnownRecordsVerificationV1Schema.parse({
          ...receipt(),
          selectedSlot: { id: 'slot.1', type, keyVersion: 1 },
        }).selectedSlot.type,
      ).toBe(type);
    },
  );

  it('accepts the complete bounded count algebra at its maximum', () => {
    const parsed = receipt({
      recordCount: DEFAULT_MAX_BACKUP_RECORDS,
      verified: {
        vaults: 1,
        groups: DEFAULT_MAX_BACKUP_RECORDS - 1,
        items: 0,
        attachments: 0,
        attachmentHeaders: 0,
        attachmentChunks: 0,
        tombstonePredecessors: { groups: 0, items: 0, attachments: 0 },
        tombstones: 0,
        histories: 0,
        audits: 0,
      },
    });
    expect(parsed.recordCount).toBe(DEFAULT_MAX_BACKUP_RECORDS);
  });

  it('accepts a restored tombstone without a predecessor entry', () => {
    expect(
      receipt({
        recordCount: 2,
        verified: {
          ...receipt().verified,
          tombstones: 1,
        },
      }).verified.tombstones,
    ).toBe(1);
  });

  it('accepts bounded semantic history and audit counts in the count algebra', () => {
    for (const family of ['histories', 'audits'] as const) {
      const base = receipt();
      expect(
        restoreKnownRecordsVerificationV1Schema.safeParse({
          ...base,
          recordCount: 2,
          verified: { ...base.verified, [family]: 1 },
        }).success,
      ).toBe(true);
    }
  });

  it('rejects incomplete count sums, missing attachment coverage, and tombstone mismatch', () => {
    const base = receipt();
    const invalid = [
      { recordCount: 1, verified: { ...base.verified, groups: 1 } },
      {
        recordCount: 3,
        verified: {
          ...base.verified,
          attachments: 1,
          attachmentHeaders: 0,
          attachmentChunks: 1,
        },
      },
      {
        recordCount: 3,
        verified: {
          ...base.verified,
          attachments: 1,
          attachmentHeaders: 1,
          attachmentChunks: 0,
        },
      },
      {
        recordCount: 2,
        verified: {
          ...base.verified,
          tombstonePredecessors: { groups: 1, items: 0, attachments: 0 },
          tombstones: 0,
        },
      },
    ];

    for (const candidate of invalid) {
      expect(
        restoreKnownRecordsVerificationV1Schema.safeParse({
          ...base,
          ...candidate,
        }).success,
      ).toBe(false);
    }
  });

  it('rejects each individual subcount above the receipt count or supported maximum', () => {
    const base = receipt();
    const directCounts = [
      'groups',
      'items',
      'attachments',
      'attachmentHeaders',
      'attachmentChunks',
      'tombstones',
    ] as const;
    for (const field of directCounts) {
      expect(
        restoreKnownRecordsVerificationV1Schema.safeParse({
          ...base,
          verified: { ...base.verified, [field]: 2 },
        }).success,
      ).toBe(false);
      expect(
        restoreKnownRecordsVerificationV1Schema.safeParse({
          ...base,
          recordCount: DEFAULT_MAX_BACKUP_RECORDS,
          verified: {
            ...base.verified,
            groups: DEFAULT_MAX_BACKUP_RECORDS - 1,
            [field]: DEFAULT_MAX_BACKUP_RECORDS + 1,
          },
        }).success,
      ).toBe(false);
    }
    for (const field of ['groups', 'items', 'attachments'] as const) {
      expect(
        restoreKnownRecordsVerificationV1Schema.safeParse({
          ...base,
          verified: {
            ...base.verified,
            tombstonePredecessors: {
              ...base.verified.tombstonePredecessors,
              [field]: 2,
            },
          },
        }).success,
      ).toBe(false);
    }
  });

  it('rejects unsafe counts, unsupported slots, and excess fields at every level', () => {
    const base = receipt();
    const invalid = [
      { ...base, version: 2 },
      { ...base, scope: 'all-records' },
      { ...base, recordCount: Number.MAX_SAFE_INTEGER + 1 },
      {
        ...base,
        selectedSlot: { id: 'slot.1', type: 'device-key', keyVersion: 1 },
      },
      {
        ...base,
        selectedSlot: { ...base.selectedSlot, keyVersion: 0 },
      },
      { ...base, unexpected: true },
      {
        ...base,
        selectedSlot: { ...base.selectedSlot, unexpected: true },
      },
      { ...base, verified: { ...base.verified, unexpected: true } },
      {
        ...base,
        verified: {
          ...base.verified,
          tombstonePredecessors: {
            ...base.verified.tombstonePredecessors,
            unexpected: true,
          },
        },
      },
    ];
    for (const candidate of invalid) {
      expect(restoreKnownRecordsVerificationV1Schema.safeParse(candidate).success).toBe(
        false,
      );
    }
  });
});

describe('backupRestoreStatusSchema', () => {
  const summary = backupSummary();
  const progress = {
    protocolVersion: 2,
    restoreSessionId: DIGEST,
    maximumBytes: MAX_SUPPORTED_BACKUP_BYTES,
    maximumRecords: DEFAULT_MAX_BACKUP_RECORDS,
    stagedBytes: 512,
    stagedRecords: 1,
    createdAt: NOW,
    updatedAt: LATER,
  } as const;

  it.each([
    { state: 'staging', ...progress, vaultId: 'vault.1' },
    { state: 'sealed', ...progress, vaultId: 'vault.1', summary, sealedAt: LATER },
    {
      state: 'published',
      ...progress,
      vaultId: 'vault.1',
      summary,
      sealedAt: LATER,
      publishedAt: LATER,
    },
    {
      state: 'committed',
      protocolVersion: 2,
      restoreSessionId: DIGEST,
      summary,
      committedAt: LATER,
    },
    {
      state: 'aborted',
      protocolVersion: 2,
      restoreSessionId: DIGEST,
      abortedAt: LATER,
    },
  ])('strictly accepts the legal $state status', (status) => {
    expect(backupRestoreStatusSchema.parse(status)).toEqual(status);
    expect(
      backupRestoreStatusSchema.safeParse({ ...status, unexpected: true }).success,
    ).toBe(false);
  });

  it('allows staging before a vault is bound', () => {
    expect(
      backupRestoreStatusSchema.safeParse({
        state: 'staging',
        ...progress,
        stagedBytes: 0,
        stagedRecords: 0,
      }).success,
    ).toBe(true);
  });

  it('rejects protocol v1, progress beyond bounds, and exact-summary mismatches', () => {
    const sealed = {
      state: 'sealed',
      ...progress,
      vaultId: 'vault.1',
      summary,
      sealedAt: LATER,
    } as const;
    const invalid = [
      { ...sealed, protocolVersion: 1 },
      { ...sealed, stagedRecords: DEFAULT_MAX_BACKUP_RECORDS + 1 },
      { ...sealed, stagedBytes: MAX_SUPPORTED_BACKUP_BYTES + 1 },
      { ...sealed, restoreSessionId: OTHER_DIGEST },
      { ...sealed, vaultId: 'vault.other' },
      { ...sealed, stagedRecords: 0 },
      { state: 'staging', ...progress },
      { state: 'staging', ...progress, stagedRecords: 0, vaultId: 'vault.1' },
      { state: 'staging', ...progress, stagedBytes: 0, vaultId: 'vault.1' },
      {
        state: 'published',
        ...progress,
        vaultId: 'vault.1',
        summary: backupSummary({ restoreSessionId: OTHER_DIGEST }),
        sealedAt: LATER,
        publishedAt: LATER,
      },
      {
        state: 'committed',
        protocolVersion: 2,
        restoreSessionId: OTHER_DIGEST,
        summary,
        committedAt: LATER,
      },
    ];
    for (const status of invalid) {
      expect(backupRestoreStatusSchema.safeParse(status).success).toBe(false);
    }
  });
});
