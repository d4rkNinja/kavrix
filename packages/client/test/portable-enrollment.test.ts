import { afterEach, describe, expect, it } from 'vitest';

import {
  createPortableKeySlot,
  formatPortableKey,
  generatePortableKey,
} from '@kavrix/crypto';
import {
  apiBearerTokenSchema,
  inviteRedeemResponseSchema,
  keySlotIdSchema,
  timestampSchema,
  vaultIdSchema,
  vaultRecordSchema,
} from '@kavrix/schemas';

import {
  ControlPlaneClient,
  PortableKeyValidationError,
  unlockRedeemedVaultWithPortableKey,
} from '../src/index.js';
import { encryptedFixture } from './fixtures.js';
import {
  readRequest,
  startLoopbackServer,
  type LoopbackServer,
} from './loopback-server.js';

const expiresAt = timestampSchema.parse('2026-08-10T00:10:00.000Z');
const servers: LoopbackServer[] = [];

afterEach(async () => {
  await Promise.all(servers.splice(0).map((server) => server.close()));
});

describe('portable-key validation before enrollment', () => {
  it('selects the matching active current slot and returns an owned original VRK', async () => {
    const portableKey = generatePortableKey();
    const formattedPortableKey = formatPortableKey(portableKey);
    const fixture = await encryptedFixture({ portableKey });
    const otherPortableKey = generatePortableKey();
    const otherSlot = await createPortableKeySlot(
      {
        vaultId: fixture.vaultId,
        slotId: keySlotIdSchema.parse('slot.other-portable'),
        schemaVersion: fixture.vault.schemaVersion,
        keyVersion: fixture.vault.currentKeyVersion,
        createdAt: fixture.vault.createdAt,
      },
      otherPortableKey,
      fixture.rootKey,
    );
    portableKey.fill(0);
    otherPortableKey.fill(0);
    const vault = vaultRecordSchema.parse({
      ...fixture.vault,
      keySlots: [otherSlot, ...fixture.vault.keySlots],
    });
    const response = inviteRedeemResponseSchema.parse({
      vaultId: fixture.vaultId,
      expiresAt,
      vault,
    });

    const unlocked = await unlockRedeemedVaultWithPortableKey(
      response,
      formattedPortableKey,
    );
    expect(unlocked).not.toBe(fixture.rootKey);
    expect(unlocked).toEqual(fixture.rootKey);
    unlocked.fill(0);
    fixture.rootKey.fill(0);
  });

  it('fails generically for wrong keys, tampering, and cross-vault responses', async () => {
    const portableKey = generatePortableKey();
    const formattedPortableKey = formatPortableKey(portableKey);
    const fixture = await encryptedFixture({ portableKey });
    portableKey.fill(0);
    const response = inviteRedeemResponseSchema.parse({
      vaultId: fixture.vaultId,
      expiresAt,
      vault: fixture.vault,
    });
    const wrongKey = generatePortableKey();
    const formattedWrongKey = formatPortableKey(wrongKey);
    wrongKey.fill(0);
    const tamperedVault = tamperPortableSlot(fixture.vault);
    const candidates = [
      () => unlockRedeemedVaultWithPortableKey(response, formattedWrongKey),
      () =>
        unlockRedeemedVaultWithPortableKey(
          { ...response, vault: tamperedVault },
          formattedPortableKey,
        ),
      () =>
        unlockRedeemedVaultWithPortableKey(
          { ...response, vaultId: vaultIdSchema.parse('vault.crossed') },
          formattedPortableKey,
        ),
    ];
    for (const candidate of candidates) {
      const error = await candidate().catch((failure: unknown) => failure);
      expect(error).toBeInstanceOf(PortableKeyValidationError);
      expect(String(error)).not.toContain(formattedPortableKey);
      expect(String(error)).not.toContain(formattedWrongKey);
      expect(JSON.stringify(error)).not.toContain(formattedPortableKey);
    }
    fixture.rootKey.fill(0);
  });

  it('keeps portable, recovery, and VRK material outside redemption HTTP', async () => {
    const portableKey = generatePortableKey();
    const formattedPortableKey = formatPortableKey(portableKey);
    const fixture = await encryptedFixture({ portableKey });
    portableKey.fill(0);
    const rootKeyCanary = Buffer.from(fixture.rootKey).toString('base64url');
    const recoveryCanary = 'cvr1_RECOVERY-CANARY-MUST-REMAIN-LOCAL';
    const inviteToken = apiBearerTokenSchema.parse(
      Buffer.alloc(32, 21).toString('base64url'),
    );
    const enrollmentSuccessor = Uint8Array.from(Buffer.alloc(32, 22));
    const captured: string[] = [];
    let completeHits = 0;
    const responseBody = inviteRedeemResponseSchema.parse({
      vaultId: fixture.vaultId,
      expiresAt,
      vault: fixture.vault,
    });
    const server = await trackedServer(async (request, response) => {
      const body = await readRequest(request);
      captured.push(
        JSON.stringify({ url: request.url, headers: request.headers, body }),
      );
      if (request.url === '/v1/enrollments/complete') completeHits += 1;
      response.statusCode = 200;
      response.setHeader('content-type', 'application/json');
      response.end(JSON.stringify(responseBody));
    });
    const client = new ControlPlaneClient({
      baseUrl: server.url,
      allowInsecureLoopbackDevelopment: true,
    });
    const redemption = await client.redeemInvite(
      inviteToken,
      enrollmentSuccessor,
      fixture.vaultId,
    );
    const wrongKey = generatePortableKey();
    const formattedWrongKey = formatPortableKey(wrongKey);
    wrongKey.fill(0);
    await expect(
      unlockRedeemedVaultWithPortableKey(redemption, formattedWrongKey),
    ).rejects.toBeInstanceOf(PortableKeyValidationError);
    expect(completeHits).toBe(0);
    await expect(
      unlockRedeemedVaultWithPortableKey(
        { ...redemption, vault: tamperPortableSlot(redemption.vault) },
        formattedPortableKey,
      ),
    ).rejects.toBeInstanceOf(PortableKeyValidationError);
    await expect(
      unlockRedeemedVaultWithPortableKey(
        { ...redemption, vaultId: vaultIdSchema.parse('vault.crossed-http') },
        formattedPortableKey,
      ),
    ).rejects.toBeInstanceOf(PortableKeyValidationError);
    expect(completeHits).toBe(0);

    const unlocked = await unlockRedeemedVaultWithPortableKey(
      redemption,
      formattedPortableKey,
    );
    expect(unlocked).toEqual(fixture.rootKey);
    expect(completeHits).toBe(0);
    const inspection = captured.join('');
    for (const canary of [
      formattedPortableKey,
      formattedWrongKey,
      recoveryCanary,
      rootKeyCanary,
    ]) {
      expect(inspection).not.toContain(canary);
    }
    unlocked.fill(0);
    fixture.rootKey.fill(0);
  });
});

async function trackedServer(
  handler: Parameters<typeof startLoopbackServer>[0],
): Promise<LoopbackServer> {
  const server = await startLoopbackServer(handler);
  servers.push(server);
  return server;
}

function tamperPortableSlot(
  vault: ReturnType<typeof vaultRecordSchema.parse>,
): ReturnType<typeof vaultRecordSchema.parse> {
  const portableSlot = vault.keySlots.find((slot) => slot.type === 'portable-key');
  if (portableSlot?.type !== 'portable-key') {
    throw new Error('Expected a portable slot fixture.');
  }
  const ciphertext = Buffer.from(portableSlot.wrappedRootKey.ciphertext, 'base64url');
  ciphertext[0] = (ciphertext[0] ?? 0) ^ 1;
  try {
    return vaultRecordSchema.parse({
      ...vault,
      keySlots: vault.keySlots.map((slot) =>
        slot.id === portableSlot.id
          ? {
              ...slot,
              wrappedRootKey: {
                ...slot.wrappedRootKey,
                ciphertext: ciphertext.toString('base64url'),
              },
            }
          : slot,
      ),
    });
  } finally {
    ciphertext.fill(0);
  }
}
