import { describe, expect, it } from 'vitest';
import {
  sealVaultExportArchive,
  openVaultExportArchive,
} from '../src/vault-export-envelope.js';
import { structuredVaultPayloadSchema } from '@kavrix/schemas';

describe('version 2 structured export envelope', () => {
  it('authenticates structured data, policy candidates, version and vault binding', async () => {
    const payload = structuredVaultPayloadSchema.parse({
      version: 1,
      vaultId: 'vault_export',
      projectContexts: [],
      groups: [],
      items: [],
      attachments: [],
      history: [],
    });
    const passphrase = new TextEncoder().encode('structured-export-test-passphrase');
    const archive = await sealVaultExportArchive([], passphrase, {
      structured: payload,
      policies: { review: { secret: 'github/token', commands: ['gh'] } },
    });
    expect(archive.version).toBe(2);
    expect(JSON.stringify(archive)).not.toContain('github/token');
    expect((await openVaultExportArchive(archive, passphrase)).structured).toEqual(
      payload,
    );
    await expect(
      sealVaultExportArchive(
        [
          {
            name: 'must-not-be-dropped',
            value: 'mixed-format-canary',
            updatedAt: archive.createdAt,
          },
        ],
        passphrase,
        { structured: payload },
      ),
    ).rejects.toThrow();
    await expect(
      openVaultExportArchive({ ...archive, version: 1 }, passphrase),
    ).rejects.toThrow();
    await expect(
      openVaultExportArchive({ ...archive, entryCount: 1 }, passphrase),
    ).rejects.toThrow();
    await expect(openVaultExportArchive(archive, new Uint8Array(32))).rejects.toThrow();
  });
});
