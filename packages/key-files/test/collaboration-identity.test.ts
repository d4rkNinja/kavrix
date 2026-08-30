import { chmod, link, readFile, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import {
  encodeBase64Url,
  openVaultRootKeyForDevice,
  sealVaultRootKeyForDevice,
  signCanonicalCollaborationValue,
  verifyCanonicalCollaborationValue,
  zeroize,
} from '@kavrix/crypto';
import {
  canonicalJson,
  deviceCertificateSchema,
  deviceIdSchema,
  principalIdSchema,
} from '@kavrix/schemas';
import { z } from 'zod';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

const replacementFault = vi.hoisted(() => ({
  mode: 'none' as 'none' | 'before' | 'after',
}));

vi.mock('../src/filesystem.js', async (importOriginal) => {
  const actual = await importOriginal<typeof import('../src/filesystem.js')>();
  return {
    ...actual,
    replaceSecureFileWhileExclusive: async (
      ...args: Parameters<typeof actual.replaceSecureFileWhileExclusive>
    ) => {
      const mode = replacementFault.mode;
      replacementFault.mode = 'none';
      if (mode === 'before') throw new Error('simulated pre-replacement crash');
      await actual.replaceSecureFileWhileExclusive(...args);
      if (mode === 'after') throw new Error('simulated post-replacement crash');
    },
  };
});

import {
  createCertifiedDeviceIdentityFile,
  createPrincipalRootIdentityFile,
  exportPrincipalPublicIdentity,
  exportPrincipalPublicIdentityFile,
  openDeviceIdentityFile,
  openPrincipalRootIdentityFile,
  readAndVerifyPublicIdentityFile,
  rewrapDeviceIdentityFile,
  rewrapPrincipalRootIdentityFile,
  revokeDeviceCredential,
  verifyDeviceCertificate,
  verifyPublicIdentityExport,
  type OpenedDeviceIdentity,
  type OpenedPrincipalRootIdentity,
  type PrincipalIdentityExpectation,
} from '../src/collaboration-identity.js';
import { createSecureTestDirectory } from './secure-temporary-directory.js';

const CREATED_AT = '2026-08-29T10:00:00.000Z';
const LATER = '2026-08-29T11:00:00.000Z';
const EXPIRES_AT = '2027-08-29T10:00:00.000Z';
const principalId = principalIdSchema.parse('principal_alice');
const deviceA = deviceIdSchema.parse('device_alice_a');
const deviceB = deviceIdSchema.parse('device_alice_b');

let directory = '';

beforeEach(async () => {
  replacementFault.mode = 'none';
  directory = await createSecureTestDirectory(
    join(tmpdir(), 'kavrix-collaboration-identity-'),
  );
});

afterEach(async () => {
  replacementFault.mode = 'none';
  await rm(directory, { force: true, recursive: true });
});

function file(name: string): string {
  return join(directory, name);
}

function passphrase(value: string): Uint8Array {
  return new TextEncoder().encode(value);
}

function disposeRoot(root: OpenedPrincipalRootIdentity | undefined): void {
  zeroize(root?.rootSigningPrivateKey);
}

function disposeDevice(device: OpenedDeviceIdentity | undefined): void {
  zeroize(device?.signingPrivateKey);
  zeroize(device?.encryptionPrivateKey);
}

async function createRoot(
  rootPath = file('principal-root.kvi'),
): Promise<PrincipalIdentityExpectation> {
  const secret = passphrase('root-file-passphrase');
  try {
    return await createPrincipalRootIdentityFile(rootPath, {
      principalId,
      passphrase: secret,
      createdAt: CREATED_AT,
      expiresAt: EXPIRES_AT,
    });
  } finally {
    zeroize(secret);
  }
}

async function addDevice(
  expectation: PrincipalIdentityExpectation,
  id = deviceA,
  devicePath = file(`${id}.kvi`),
  expiresAt = EXPIRES_AT,
) {
  const rootSecret = passphrase('root-file-passphrase');
  const deviceSecret = passphrase('device-file-passphrase');
  try {
    return await createCertifiedDeviceIdentityFile(
      file('principal-root.kvi'),
      devicePath,
      {
        expectedPrincipal: expectation,
        principalRootPassphrase: rootSecret,
        devicePassphrase: deviceSecret,
        deviceId: id,
        createdAt: CREATED_AT,
        expiresAt,
      },
    );
  } finally {
    zeroize(rootSecret);
    zeroize(deviceSecret);
  }
}

describe('protected collaboration identity files', () => {
  it('creates separate root/device files and exports a verified public-only identity', async () => {
    const rootPath = file('principal-root.kvi');
    const devicePath = file(`${deviceA}.kvi`);
    const publicPath = file('alice.public.json');
    const rootSecret = passphrase('root-file-passphrase');
    const deviceSecret = passphrase('device-file-passphrase');
    const expectation = await createRoot(rootPath);
    let root: OpenedPrincipalRootIdentity | undefined;
    let device: OpenedDeviceIdentity | undefined;
    try {
      root = await openPrincipalRootIdentityFile(rootPath, rootSecret, expectation, {
        at: CREATED_AT,
      });
      const rootPrivate = encodeBase64Url(root.rootSigningPrivateKey);
      const created = await addDevice(expectation, deviceA, devicePath);
      await expect(
        verifyDeviceCertificate(created.certificate, expectation, {
          at: CREATED_AT,
        }),
      ).resolves.toEqual(created.certificate);

      device = await openDeviceIdentityFile(
        devicePath,
        deviceSecret,
        created.publicIdentity,
        expectation,
        { at: CREATED_AT },
      );
      const deviceSigningPrivate = encodeBase64Url(device.signingPrivateKey);
      const deviceEncryptionPrivate = encodeBase64Url(device.encryptionPrivateKey);
      const exported = await exportPrincipalPublicIdentityFile(
        rootPath,
        publicPath,
        rootSecret,
        expectation,
        { at: CREATED_AT },
      );
      await expect(
        readAndVerifyPublicIdentityFile(publicPath, expectation, {
          at: CREATED_AT,
        }),
      ).resolves.toEqual(exported);

      const publicText = await readFile(publicPath, 'utf8');
      const rootText = await readFile(rootPath, 'utf8');
      expect(publicText).not.toMatch(
        /(?:PrivateKey|passphrase|ciphertext|derivation|protection)/iu,
      );
      expect(publicText).not.toContain(rootPrivate);
      expect(publicText).not.toContain(deviceSigningPrivate);
      expect(publicText).not.toContain(deviceEncryptionPrivate);
      expect(rootText).not.toContain(deviceSigningPrivate);
      expect(rootText).not.toContain(deviceEncryptionPrivate);
      expect(Object.keys(exported).sort()).toEqual([
        'createdAt',
        'devices',
        'expiresAt',
        'format',
        'identityGeneration',
        'principalId',
        'protocolVersion',
        'rootSigningPublicKey',
        'selfSignature',
      ]);
    } finally {
      disposeDevice(device);
      disposeRoot(root);
      zeroize(rootSecret);
      zeroize(deviceSecret);
    }
  });

  it('rewraps both private files without changing identity keys or certificates', async () => {
    const rootPath = file('principal-root.kvi');
    const devicePath = file(`${deviceA}.kvi`);
    const expectation = await createRoot(rootPath);
    const created = await addDevice(expectation, deviceA, devicePath);
    const oldRoot = passphrase('root-file-passphrase');
    const newRoot = passphrase('new-root-file-passphrase');
    const oldDevice = passphrase('device-file-passphrase');
    const newDevice = passphrase('new-device-file-passphrase');
    let beforeRoot: OpenedPrincipalRootIdentity | undefined;
    let beforeDevice: OpenedDeviceIdentity | undefined;
    let afterRoot: OpenedPrincipalRootIdentity | undefined;
    let afterDevice: OpenedDeviceIdentity | undefined;
    try {
      beforeRoot = await openPrincipalRootIdentityFile(rootPath, oldRoot, expectation, {
        at: CREATED_AT,
      });
      beforeDevice = await openDeviceIdentityFile(
        devicePath,
        oldDevice,
        created.publicIdentity,
        expectation,
        { at: CREATED_AT },
      );
      const expectedRootKey = Uint8Array.from(beforeRoot.rootSigningPrivateKey);
      const expectedSigningKey = Uint8Array.from(beforeDevice.signingPrivateKey);
      const expectedEncryptionKey = Uint8Array.from(beforeDevice.encryptionPrivateKey);
      const rootBefore = await readFile(rootPath);
      const deviceBefore = await readFile(devicePath);
      try {
        await rewrapPrincipalRootIdentityFile(rootPath, oldRoot, newRoot, expectation, {
          at: CREATED_AT,
        });
        await rewrapDeviceIdentityFile(
          devicePath,
          oldDevice,
          newDevice,
          created.publicIdentity,
          expectation,
          { at: CREATED_AT },
        );
        await expect(
          openPrincipalRootIdentityFile(rootPath, oldRoot, expectation, {
            at: CREATED_AT,
          }),
        ).rejects.toMatchObject({ code: 'KEY_FILE_UNSAFE' });
        await expect(
          openDeviceIdentityFile(
            devicePath,
            oldDevice,
            created.publicIdentity,
            expectation,
            { at: CREATED_AT },
          ),
        ).rejects.toMatchObject({ code: 'KEY_FILE_UNSAFE' });
        afterRoot = await openPrincipalRootIdentityFile(
          rootPath,
          newRoot,
          expectation,
          { at: CREATED_AT },
        );
        afterDevice = await openDeviceIdentityFile(
          devicePath,
          newDevice,
          created.publicIdentity,
          expectation,
          { at: CREATED_AT },
        );
        expect(afterRoot.rootSigningPrivateKey).toEqual(expectedRootKey);
        expect(afterDevice.signingPrivateKey).toEqual(expectedSigningKey);
        expect(afterDevice.encryptionPrivateKey).toEqual(expectedEncryptionKey);
        expect(afterDevice.certificate).toEqual(created.certificate);
        expect(await readFile(rootPath)).not.toEqual(rootBefore);
        expect(await readFile(devicePath)).not.toEqual(deviceBefore);
      } finally {
        zeroize(expectedRootKey);
        zeroize(expectedSigningKey);
        zeroize(expectedEncryptionKey);
        zeroize(rootBefore);
        zeroize(deviceBefore);
      }
    } finally {
      disposeRoot(beforeRoot);
      disposeDevice(beforeDevice);
      disposeRoot(afterRoot);
      disposeDevice(afterDevice);
      zeroize(oldRoot);
      zeroize(newRoot);
      zeroize(oldDevice);
      zeroize(newDevice);
    }
  });

  it('maps wrong passphrases and authenticated-envelope tampering to one safe error', async () => {
    const rootPath = file('principal-root.kvi');
    const expectation = await createRoot(rootPath);
    const correct = passphrase('root-file-passphrase');
    const wrong = passphrase('wrong-passphrase');
    try {
      await expect(
        openPrincipalRootIdentityFile(rootPath, wrong, expectation, {
          at: CREATED_AT,
        }),
      ).rejects.toEqual(
        expect.objectContaining({
          code: 'KEY_FILE_UNSAFE',
          message: 'The portable key file is not safe to use.',
        }),
      );

      const envelope = JSON.parse(await readFile(rootPath, 'utf8')) as Record<
        string,
        unknown
      >;
      const ciphertext = String(envelope['ciphertext']);
      envelope['ciphertext'] =
        `${ciphertext[0] === 'A' ? 'B' : 'A'}${ciphertext.slice(1)}`;
      await import('node:fs/promises').then(({ writeFile }) =>
        writeFile(rootPath, canonicalJson(envelope), 'utf8'),
      );
      await expect(
        openPrincipalRootIdentityFile(rootPath, correct, expectation, {
          at: CREATED_AT,
        }),
      ).rejects.toEqual(
        expect.objectContaining({
          code: 'KEY_FILE_UNSAFE',
          message: 'The portable key file is not safe to use.',
        }),
      );
    } finally {
      zeroize(correct);
      zeroize(wrong);
    }
  });

  it('does not let a copied principal root sign or decrypt as its device', async () => {
    const rootPath = file('principal-root.kvi');
    const devicePath = file(`${deviceA}.kvi`);
    const expectation = await createRoot(rootPath);
    const created = await addDevice(expectation, deviceA, devicePath);
    const rootSecret = passphrase('root-file-passphrase');
    let root: OpenedPrincipalRootIdentity | undefined;
    try {
      root = await openPrincipalRootIdentityFile(rootPath, rootSecret, expectation, {
        at: CREATED_AT,
      });
      const proofSchema = z.object({ challenge: z.literal('device-proof') }).strict();
      const value = { challenge: 'device-proof' } as const;
      const forged = await signCanonicalCollaborationValue(
        'kavrix/test/device-proof/v1',
        value,
        proofSchema,
        root.rootSigningPrivateKey,
      );
      await expect(
        verifyCanonicalCollaborationValue(
          'kavrix/test/device-proof/v1',
          value,
          proofSchema,
          forged,
          created.certificate.signingPublicKey,
        ),
      ).resolves.toBe(false);

      const vaultRootKey = new Uint8Array(32).fill(17);
      try {
        const sealed = await sealVaultRootKeyForDevice(
          vaultRootKey,
          created.certificate.encryptionPublicKey,
        );
        await expect(
          openVaultRootKeyForDevice(
            sealed,
            created.certificate.encryptionPublicKey,
            root.rootSigningPrivateKey,
          ),
        ).rejects.toMatchObject({ name: 'AuthenticationError' });
      } finally {
        zeroize(vaultRootKey);
      }
    } finally {
      disposeRoot(root);
      zeroize(rootSecret);
    }
  });

  it('rejects revoked, expired, and principal/root-mismatched device identities', async () => {
    const rootPath = file('principal-root.kvi');
    const deviceAPath = file(`${deviceA}.kvi`);
    const deviceBPath = file(`${deviceB}.kvi`);
    const expectation = await createRoot(rootPath);
    await addDevice(expectation, deviceA, deviceAPath);
    const second = await addDevice(expectation, deviceB, deviceBPath);
    const rootSecret = passphrase('root-file-passphrase');
    const deviceSecret = passphrase('device-file-passphrase');
    let openedB: OpenedDeviceIdentity | undefined;
    try {
      const revoked = await revokeDeviceCredential(rootPath, {
        expectedPrincipal: expectation,
        passphrase: rootSecret,
        deviceId: deviceA,
        revokedAt: LATER,
        state: 'compromised',
      });
      expect(revoked.certificate.state).toBe('compromised');
      expect(revoked.publicIdentity?.devices.map((device) => device.deviceId)).toEqual([
        deviceB,
      ]);
      if (revoked.publicIdentity === undefined) throw new Error('Expected device B');
      await expect(
        openDeviceIdentityFile(
          deviceAPath,
          deviceSecret,
          revoked.publicIdentity,
          expectation,
          { at: LATER },
        ),
      ).rejects.toMatchObject({ code: 'KEY_FILE_UNSAFE' });
      openedB = await openDeviceIdentityFile(
        deviceBPath,
        deviceSecret,
        revoked.publicIdentity,
        expectation,
        { at: LATER },
      );
      expect(openedB.certificate.deviceId).toBe(deviceB);

      await expect(
        verifyDeviceCertificate(second.certificate, expectation, {
          at: '2028-08-29T10:00:00.000Z',
        }),
      ).rejects.toMatchObject({ code: 'KEY_FILE_UNSAFE' });
      const signature = second.certificate.rootSignature;
      const tamperedCertificate = deviceCertificateSchema.parse({
        ...second.certificate,
        rootSignature: `${signature[0] === 'A' ? 'B' : 'A'}${signature.slice(1)}`,
      });
      await expect(
        verifyDeviceCertificate(tamperedCertificate, expectation, { at: LATER }),
      ).rejects.toMatchObject({ code: 'KEY_FILE_UNSAFE' });
      await expect(
        verifyPublicIdentityExport(
          revoked.publicIdentity,
          {
            principalId: principalIdSchema.parse('principal_mallory'),
            rootSigningPublicKey: expectation.rootSigningPublicKey,
          },
          { at: LATER },
        ),
      ).rejects.toMatchObject({ code: 'KEY_FILE_UNSAFE' });
      await expect(
        verifyPublicIdentityExport(
          revoked.publicIdentity,
          {
            principalId: expectation.principalId,
            rootSigningPublicKey: second.certificate.signingPublicKey,
          },
          { at: LATER },
        ),
      ).rejects.toMatchObject({ code: 'KEY_FILE_UNSAFE' });
    } finally {
      disposeDevice(openedB);
      zeroize(rootSecret);
      zeroize(deviceSecret);
    }
  });

  it('resumes enrollment from the exact protected device published before root replacement', async () => {
    const rootPath = file('principal-root.kvi');
    const devicePath = file(`${deviceA}.kvi`);
    const expectation = await createRoot(rootPath);
    const rootSecret = passphrase('root-file-passphrase');
    const deviceSecret = passphrase('device-file-passphrase');
    let beforeRetry: OpenedPrincipalRootIdentity | undefined;
    let afterRetry: OpenedPrincipalRootIdentity | undefined;
    try {
      replacementFault.mode = 'before';
      await expect(
        createCertifiedDeviceIdentityFile(rootPath, devicePath, {
          expectedPrincipal: expectation,
          principalRootPassphrase: rootSecret,
          devicePassphrase: deviceSecret,
          deviceId: deviceA,
          createdAt: CREATED_AT,
          expiresAt: EXPIRES_AT,
        }),
      ).rejects.toMatchObject({ code: 'KEY_FILE_UNSAFE' });

      const publishedDevice = await readFile(devicePath);
      beforeRetry = await openPrincipalRootIdentityFile(
        rootPath,
        rootSecret,
        expectation,
        { at: CREATED_AT },
      );
      expect(beforeRetry.identityGeneration).toBe(1);
      expect(beforeRetry.devices).toEqual([]);

      const resumed = await createCertifiedDeviceIdentityFile(rootPath, devicePath, {
        expectedPrincipal: expectation,
        principalRootPassphrase: rootSecret,
        devicePassphrase: deviceSecret,
        deviceId: deviceA,
        createdAt: CREATED_AT,
        expiresAt: EXPIRES_AT,
      });

      expect(await readFile(devicePath)).toEqual(publishedDevice);
      afterRetry = await openPrincipalRootIdentityFile(
        rootPath,
        rootSecret,
        expectation,
        { at: CREATED_AT },
      );
      expect(afterRetry.identityGeneration).toBe(2);
      expect(afterRetry.devices).toEqual([resumed.certificate]);
      expect(resumed.publicIdentity.identityGeneration).toBe(2);
    } finally {
      disposeRoot(beforeRetry);
      disposeRoot(afterRetry);
      zeroize(rootSecret);
      zeroize(deviceSecret);
    }
  });

  it('retries idempotently when root replacement committed before the first call returned', async () => {
    const rootPath = file('principal-root.kvi');
    const devicePath = file(`${deviceA}.kvi`);
    const expectation = await createRoot(rootPath);
    const rootSecret = passphrase('root-file-passphrase');
    const deviceSecret = passphrase('device-file-passphrase');
    let root: OpenedPrincipalRootIdentity | undefined;
    try {
      replacementFault.mode = 'after';
      await expect(
        createCertifiedDeviceIdentityFile(rootPath, devicePath, {
          expectedPrincipal: expectation,
          principalRootPassphrase: rootSecret,
          devicePassphrase: deviceSecret,
          deviceId: deviceA,
          createdAt: CREATED_AT,
          expiresAt: EXPIRES_AT,
        }),
      ).rejects.toMatchObject({ code: 'KEY_FILE_UNSAFE' });

      const committedRoot = await readFile(rootPath);
      const publishedDevice = await readFile(devicePath);
      const resumed = await createCertifiedDeviceIdentityFile(rootPath, devicePath, {
        expectedPrincipal: expectation,
        principalRootPassphrase: rootSecret,
        devicePassphrase: deviceSecret,
        deviceId: deviceA,
        createdAt: CREATED_AT,
        expiresAt: EXPIRES_AT,
      });

      expect(await readFile(rootPath)).toEqual(committedRoot);
      expect(await readFile(devicePath)).toEqual(publishedDevice);
      expect(resumed.publicIdentity.identityGeneration).toBe(2);
      root = await openPrincipalRootIdentityFile(rootPath, rootSecret, expectation, {
        at: CREATED_AT,
      });
      expect(root.identityGeneration).toBe(2);
      expect(root.devices).toEqual([resumed.certificate]);
    } finally {
      disposeRoot(root);
      zeroize(rootSecret);
      zeroize(deviceSecret);
    }
  });

  it('rejects wrong protection or a differently requested certificate without overwriting an orphan', async () => {
    const rootPath = file('principal-root.kvi');
    const devicePath = file(`${deviceA}.kvi`);
    const expectation = await createRoot(rootPath);
    const rootSecret = passphrase('root-file-passphrase');
    const deviceSecret = passphrase('device-file-passphrase');
    const wrongDeviceSecret = passphrase('wrong-device-file-passphrase');
    try {
      replacementFault.mode = 'before';
      await expect(
        createCertifiedDeviceIdentityFile(rootPath, devicePath, {
          expectedPrincipal: expectation,
          principalRootPassphrase: rootSecret,
          devicePassphrase: deviceSecret,
          deviceId: deviceA,
          createdAt: CREATED_AT,
          expiresAt: EXPIRES_AT,
        }),
      ).rejects.toMatchObject({ code: 'KEY_FILE_UNSAFE' });
      const rootBefore = await readFile(rootPath);
      const deviceBefore = await readFile(devicePath);

      await expect(
        createCertifiedDeviceIdentityFile(rootPath, devicePath, {
          expectedPrincipal: expectation,
          principalRootPassphrase: rootSecret,
          devicePassphrase: wrongDeviceSecret,
          deviceId: deviceA,
          createdAt: CREATED_AT,
          expiresAt: EXPIRES_AT,
        }),
      ).rejects.toMatchObject({ code: 'KEY_FILE_UNSAFE' });
      await expect(
        createCertifiedDeviceIdentityFile(rootPath, devicePath, {
          expectedPrincipal: expectation,
          principalRootPassphrase: rootSecret,
          devicePassphrase: deviceSecret,
          deviceId: deviceB,
          createdAt: CREATED_AT,
          expiresAt: EXPIRES_AT,
        }),
      ).rejects.toMatchObject({ code: 'KEY_FILE_UNSAFE' });

      expect(await readFile(rootPath)).toEqual(rootBefore);
      expect(await readFile(devicePath)).toEqual(deviceBefore);
    } finally {
      zeroize(rootSecret);
      zeroize(deviceSecret);
      zeroize(wrongDeviceSecret);
    }
  });

  it('rejects replayed signed root and public identities below a caller-pinned generation', async () => {
    const rootPath = file('principal-root.kvi');
    const deviceAPath = file(`${deviceA}.kvi`);
    const deviceBPath = file(`${deviceB}.kvi`);
    const publicPath = file('alice.public.json');
    const expectation = await createRoot(rootPath);
    const first = await addDevice(expectation, deviceA, deviceAPath);
    const rootSecret = passphrase('root-file-passphrase');
    const deviceSecret = passphrase('device-file-passphrase');
    const replacementRootSecret = passphrase('replacement-root-file-passphrase');
    let equalRoot: OpenedPrincipalRootIdentity | undefined;
    let currentDevice: OpenedDeviceIdentity | undefined;
    try {
      await exportPrincipalPublicIdentityFile(
        rootPath,
        publicPath,
        rootSecret,
        expectation,
        { at: CREATED_AT },
      );
      const staleRoot = await readFile(rootPath);
      const second = await addDevice(expectation, deviceB, deviceBPath);
      expect(second.publicIdentity.identityGeneration).toBe(3);
      await writeFile(rootPath, staleRoot);

      await expect(
        openPrincipalRootIdentityFile(rootPath, rootSecret, expectation, {
          at: CREATED_AT,
          minimumIdentityGeneration: 3,
        }),
      ).rejects.toMatchObject({ code: 'KEY_FILE_UNSAFE' });
      equalRoot = await openPrincipalRootIdentityFile(
        rootPath,
        rootSecret,
        expectation,
        { at: CREATED_AT, minimumIdentityGeneration: 2 },
      );
      expect(equalRoot.identityGeneration).toBe(2);

      await expect(
        verifyPublicIdentityExport(first.publicIdentity, expectation, {
          at: CREATED_AT,
          minimumIdentityGeneration: 3,
        }),
      ).rejects.toMatchObject({ code: 'KEY_FILE_UNSAFE' });
      await expect(
        verifyPublicIdentityExport(first.publicIdentity, expectation, {
          at: CREATED_AT,
          minimumIdentityGeneration: 2,
        }),
      ).resolves.toEqual(first.publicIdentity);
      await expect(
        verifyPublicIdentityExport(second.publicIdentity, expectation, {
          at: CREATED_AT,
          minimumIdentityGeneration: 3,
        }),
      ).resolves.toEqual(second.publicIdentity);
      await expect(
        readAndVerifyPublicIdentityFile(publicPath, expectation, {
          at: CREATED_AT,
          minimumIdentityGeneration: 3,
        }),
      ).rejects.toMatchObject({ code: 'KEY_FILE_UNSAFE' });
      await expect(
        exportPrincipalPublicIdentity(rootPath, rootSecret, expectation, {
          at: CREATED_AT,
          minimumIdentityGeneration: 3,
        }),
      ).rejects.toMatchObject({ code: 'KEY_FILE_UNSAFE' });

      await expect(
        rewrapPrincipalRootIdentityFile(
          rootPath,
          rootSecret,
          replacementRootSecret,
          expectation,
          { at: CREATED_AT, minimumIdentityGeneration: 3 },
        ),
      ).rejects.toMatchObject({ code: 'KEY_FILE_UNSAFE' });
      await expect(
        rewrapDeviceIdentityFile(
          deviceAPath,
          deviceSecret,
          replacementRootSecret,
          first.publicIdentity,
          expectation,
          { at: CREATED_AT, minimumIdentityGeneration: 3 },
        ),
      ).rejects.toMatchObject({ code: 'KEY_FILE_UNSAFE' });
      await expect(
        createCertifiedDeviceIdentityFile(rootPath, deviceBPath, {
          expectedPrincipal: expectation,
          principalRootPassphrase: rootSecret,
          devicePassphrase: deviceSecret,
          deviceId: deviceB,
          createdAt: CREATED_AT,
          expiresAt: EXPIRES_AT,
          minimumIdentityGeneration: 3,
        }),
      ).rejects.toMatchObject({ code: 'KEY_FILE_UNSAFE' });
      await expect(
        revokeDeviceCredential(rootPath, {
          expectedPrincipal: expectation,
          passphrase: rootSecret,
          deviceId: deviceA,
          revokedAt: LATER,
          minimumIdentityGeneration: 3,
        }),
      ).rejects.toMatchObject({ code: 'KEY_FILE_UNSAFE' });
      await expect(
        openDeviceIdentityFile(
          deviceAPath,
          deviceSecret,
          first.publicIdentity,
          expectation,
          { at: CREATED_AT, minimumIdentityGeneration: 3 },
        ),
      ).rejects.toMatchObject({ code: 'KEY_FILE_UNSAFE' });
      currentDevice = await openDeviceIdentityFile(
        deviceAPath,
        deviceSecret,
        second.publicIdentity,
        expectation,
        { at: CREATED_AT, minimumIdentityGeneration: 3 },
      );
      expect(currentDevice.certificate.deviceId).toBe(deviceA);
    } finally {
      disposeRoot(equalRoot);
      disposeDevice(currentDevice);
      zeroize(rootSecret);
      zeroize(deviceSecret);
      zeroize(replacementRootSecret);
    }
  });

  it('inherits hardened file checks and rejects multiply-linked or unsafe-mode roots', async () => {
    const rootPath = file('principal-root.kvi');
    const linkedPath = file('linked-root.kvi');
    const expectation = await createRoot(rootPath);
    const rootSecret = passphrase('root-file-passphrase');
    try {
      await link(rootPath, linkedPath);
      await expect(
        openPrincipalRootIdentityFile(rootPath, rootSecret, expectation, {
          at: CREATED_AT,
        }),
      ).rejects.toMatchObject({ code: 'KEY_FILE_UNSAFE' });
      await rm(linkedPath);
      if (process.platform !== 'win32') {
        await chmod(rootPath, 0o644);
        await expect(
          openPrincipalRootIdentityFile(rootPath, rootSecret, expectation, {
            at: CREATED_AT,
          }),
        ).rejects.toMatchObject({ code: 'KEY_FILE_UNSAFE' });
      }
    } finally {
      zeroize(rootSecret);
    }
  });
});
