import { describe, expect, it } from 'vitest';

import {
  associatedDataSchema,
  type AeadEnvelope,
  type AssociatedData,
} from '@kavrix/schemas';

import {
  AuthenticationError,
  canonicalAssociatedData,
  encryptAead,
  generateItemKey,
} from '../src/index.js';
import { decryptAead } from '../src/aead.js';
import {
  groupId,
  itemPayloadAad,
  mutateBase64Url,
  otherGroupId,
  otherItemId,
  otherVaultId,
} from './helpers.js';

const plaintext = new TextEncoder().encode('unique-plaintext-canary-7ac19783');

const fixtureBase = {
  version: 1,
  schemaVersion: 2,
  keyVersion: 3,
  vaultId: 'v',
} as const;

// Golden bytes implement docs/security-testing.md:75-90. Any change requires an
// AAD-version migration review; these values must never be refreshed from the encoder.
const canonicalAadFixtures = [
  {
    name: 'vault-preferences',
    aad: {
      ...fixtureBase,
      entityType: 'vault-preferences',
      entityId: 'v',
      purpose: 'vault-preferences',
    },
    expectedHex:
      '00000010637265647661756c742f6161642f7631000000010000000176000000117661756c742d707265666572656e63657300000001760000000000117661756c742d707265666572656e6365730000000200000003',
  },
  {
    name: 'group',
    aad: {
      ...fixtureBase,
      entityType: 'group',
      entityId: 'g',
      purpose: 'group-payload',
    },
    expectedHex:
      '00000010637265647661756c742f6161642f76310000000100000001760000000567726f7570000000016700000000000d67726f75702d7061796c6f61640000000200000003',
  },
  {
    name: 'item',
    aad: {
      ...fixtureBase,
      entityType: 'item',
      entityId: 'i',
      groupId: 'g',
      purpose: 'item-payload',
    },
    expectedHex:
      '00000010637265647661756c742f6161642f7631000000010000000176000000046974656d0000000169010000000167000000000c6974656d2d7061796c6f61640000000200000003',
  },
  {
    name: 'attachment',
    aad: {
      ...fixtureBase,
      entityType: 'attachment',
      entityId: 'a',
      groupId: 'g',
      parentId: 'i',
      purpose: 'attachment-metadata',
    },
    expectedHex:
      '00000010637265647661756c742f6161642f76310000000100000001760000000a6174746163686d656e740000000161010000000167010000000169000000136174746163686d656e742d6d657461646174610000000200000003',
  },
  {
    name: 'attachment-chunk',
    aad: {
      ...fixtureBase,
      entityType: 'attachment-chunk',
      entityId: 'a',
      groupId: 'g',
      parentId: 'i',
      purpose: 'attachment-chunk',
    },
    expectedHex:
      '00000010637265647661756c742f6161642f7631000000010000000176000000106174746163686d656e742d6368756e6b0000000161010000000167010000000169000000106174746163686d656e742d6368756e6b0000000200000003',
  },
  {
    name: 'audit-event',
    aad: {
      ...fixtureBase,
      entityType: 'audit-event',
      entityId: 'e',
      purpose: 'audit-event',
    },
    expectedHex:
      '00000010637265647661756c742f6161642f76310000000100000001760000000b61756469742d6576656e74000000016500000000000b61756469742d6576656e740000000200000003',
  },
  {
    name: 'history',
    aad: {
      ...fixtureBase,
      entityType: 'history',
      entityId: 'h',
      groupId: 'g',
      parentId: 'i',
      purpose: 'history-event',
    },
    expectedHex:
      '00000010637265647661756c742f6161642f763100000001000000017600000007686973746f727900000001680100000001670100000001690000000d686973746f72792d6576656e740000000200000003',
  },
  {
    name: 'device-label',
    aad: {
      ...fixtureBase,
      entityType: 'device-label',
      entityId: 'd',
      purpose: 'device-label',
    },
    expectedHex:
      '00000010637265647661756c742f6161642f76310000000100000001760000000c6465766963652d6c6162656c000000016400000000000c6465766963652d6c6162656c0000000200000003',
  },
  {
    name: 'wrapped-root-key',
    aad: {
      ...fixtureBase,
      entityType: 'wrapped-root-key',
      entityId: 's',
      purpose: 'vrk-slot',
    },
    expectedHex:
      '00000010637265647661756c742f6161642f763100000001000000017600000010777261707065642d726f6f742d6b6579000000017300000000000876726b2d736c6f740000000200000003',
  },
  {
    name: 'wrapped-group-key',
    aad: {
      ...fixtureBase,
      entityType: 'wrapped-group-key',
      entityId: 'g',
      purpose: 'group-key',
    },
    expectedHex:
      '00000010637265647661756c742f6161642f763100000001000000017600000011777261707065642d67726f75702d6b6579000000016700000000000967726f75702d6b65790000000200000003',
  },
  {
    name: 'wrapped-item-key',
    aad: {
      ...fixtureBase,
      entityType: 'wrapped-item-key',
      entityId: 'i',
      groupId: 'g',
      purpose: 'item-key',
    },
    expectedHex:
      '00000010637265647661756c742f6161642f763100000001000000017600000010777261707065642d6974656d2d6b6579000000016901000000016700000000086974656d2d6b65790000000200000003',
  },
  {
    name: 'wrapped-attachment-key',
    aad: {
      ...fixtureBase,
      entityType: 'wrapped-attachment-key',
      entityId: 'a',
      groupId: 'g',
      parentId: 'i',
      purpose: 'attachment-key',
    },
    expectedHex:
      '00000010637265647661756c742f6161642f763100000001000000017600000016777261707065642d6174746163686d656e742d6b657900000001610100000001670100000001690000000e6174746163686d656e742d6b65790000000200000003',
  },
] as const;

type InspectedOptionalId =
  { readonly marker: 0 } | { readonly marker: 1; readonly value: string };

function fixtureAad(
  name: (typeof canonicalAadFixtures)[number]['name'],
): AssociatedData {
  const fixture = canonicalAadFixtures.find((candidate) => candidate.name === name);
  if (fixture === undefined) {
    throw new Error(`Missing canonical AAD fixture: ${name}`);
  }
  return associatedDataSchema.parse(fixture.aad);
}

function inspectOptionalIds(bytes: Uint8Array): {
  readonly groupId: InspectedOptionalId;
  readonly parentId: InspectedOptionalId;
} {
  const buffer = Buffer.from(bytes);
  let offset = 0;
  const readLengthPrefixed = (): string => {
    const length = buffer.readUInt32BE(offset);
    offset += 4;
    const value = buffer.subarray(offset, offset + length).toString('ascii');
    offset += length;
    return value;
  };
  const readOptionalId = (): InspectedOptionalId => {
    const marker = buffer.readUInt8(offset);
    offset += 1;
    if (marker === 0) {
      return { marker };
    }
    if (marker === 1) {
      return { marker, value: readLengthPrefixed() };
    }
    throw new Error(`Unexpected optional-ID marker: ${String(marker)}`);
  };

  readLengthPrefixed();
  offset += 4;
  readLengthPrefixed();
  readLengthPrefixed();
  readLengthPrefixed();
  return { groupId: readOptionalId(), parentId: readOptionalId() };
}

const unknownDiscriminantCases: readonly [
  string,
  (envelope: AeadEnvelope) => AeadEnvelope,
][] = [
  [
    'envelope version',
    (envelope) => ({ ...envelope, version: 2 }) as unknown as AeadEnvelope,
  ],
  [
    'envelope algorithm',
    (envelope) =>
      ({ ...envelope, algorithm: 'unknown-aead' }) as unknown as AeadEnvelope,
  ],
  [
    'AAD version',
    (envelope) =>
      ({
        ...envelope,
        aad: { ...envelope.aad, version: 2 },
      }) as unknown as AeadEnvelope,
  ],
  [
    'AAD entity type',
    (envelope) =>
      ({
        ...envelope,
        aad: { ...envelope.aad, entityType: 'unknown-entity' },
      }) as unknown as AeadEnvelope,
  ],
];

describe('authenticated envelopes', () => {
  it('round-trips an authenticated envelope', async () => {
    const key = generateItemKey();
    const aad = itemPayloadAad();
    const envelope = await encryptAead(plaintext, key, aad);
    await expect(decryptAead(envelope, key, aad)).resolves.toEqual(plaintext);
    expect(envelope).toMatchObject({
      version: 1,
      algorithm: 'xchacha20-poly1305-ietf',
      keyVersion: 1,
    });
    expect(JSON.stringify(envelope)).not.toContain('unique-plaintext-canary-7ac19783');
  });

  it.each(['nonce', 'ciphertext', 'authenticationTag'] as const)(
    'rejects modified %s without returning plaintext',
    async (field) => {
      const key = generateItemKey();
      const envelope = await encryptAead(plaintext, key, itemPayloadAad());
      const tampered = {
        ...envelope,
        [field]: mutateBase64Url(envelope[field]),
      };
      await expect(decryptAead(tampered, key, itemPayloadAad())).rejects.toBeInstanceOf(
        AuthenticationError,
      );
    },
  );

  it('returns the generic failure for a wrong key', async () => {
    const envelope = await encryptAead(plaintext, generateItemKey(), itemPayloadAad());
    await expect(
      decryptAead(envelope, generateItemKey(), itemPayloadAad()),
    ).rejects.toEqual(new AuthenticationError());
  });

  it.each(unknownDiscriminantCases)(
    'returns the same generic failure for an unknown %s',
    async (_name, mutateEnvelope) => {
      const key = generateItemKey();
      const aad = itemPayloadAad();
      const envelope = await encryptAead(plaintext, key, aad);
      await expect(decryptAead(mutateEnvelope(envelope), key, aad)).rejects.toEqual(
        new AuthenticationError(),
      );
    },
  );

  it.each(canonicalAadFixtures)(
    'matches the reviewed canonical AAD v1 golden for $name',
    ({ aad, expectedHex }) => {
      const parsed = associatedDataSchema.parse(aad);
      expect(Buffer.from(canonicalAssociatedData(parsed)).toString('hex')).toBe(
        expectedHex,
      );
    },
  );

  it('encodes explicit absent and present optional-ID markers', () => {
    expect(
      inspectOptionalIds(canonicalAssociatedData(fixtureAad('vault-preferences'))),
    ).toEqual({ groupId: { marker: 0 }, parentId: { marker: 0 } });
    expect(inspectOptionalIds(canonicalAssociatedData(fixtureAad('item')))).toEqual({
      groupId: { marker: 1, value: 'g' },
      parentId: { marker: 0 },
    });
  });

  it.each(['attachment', 'history'] as const)(
    'encodes both optional IDs as present for %s',
    (name) => {
      expect(inspectOptionalIds(canonicalAssociatedData(fixtureAad(name)))).toEqual({
        groupId: { marker: 1, value: 'g' },
        parentId: { marker: 1, value: 'i' },
      });
    },
  );

  it('separates the collision pair (entityId="a", groupId="bc") and (entityId="ab", groupId="c")', () => {
    const left = associatedDataSchema.parse({
      ...fixtureBase,
      entityType: 'item',
      entityId: 'a',
      groupId: 'bc',
      purpose: 'item-payload',
    });
    const right = associatedDataSchema.parse({
      ...fixtureBase,
      entityType: 'item',
      entityId: 'ab',
      groupId: 'c',
      purpose: 'item-payload',
    });

    expect(canonicalAssociatedData(left)).not.toEqual(canonicalAssociatedData(right));
  });

  it('prefixes a legal 128-character ID with 00000080', () => {
    const entityId = 'a'.repeat(128);
    const aad = associatedDataSchema.parse({
      ...fixtureBase,
      entityType: 'group',
      entityId,
      purpose: 'group-payload',
    });
    const encodedId = Buffer.concat([
      Buffer.from('00000080', 'hex'),
      Buffer.from(entityId, 'ascii'),
    ]);

    expect(Buffer.from(canonicalAssociatedData(aad)).includes(encodedId)).toBe(true);
  });

  it.each([
    ['empty', ''],
    ['non-ASCII', 'é'],
  ] as const)('rejects a %s identity before canonical encoding', (_name, entityId) => {
    const invalid = {
      ...fixtureBase,
      entityType: 'group',
      entityId,
      purpose: 'group-payload',
    };

    expect(associatedDataSchema.safeParse(invalid).success).toBe(false);
    expect(() =>
      canonicalAssociatedData(invalid as unknown as AssociatedData),
    ).toThrow();
  });

  it.each([
    ['vault', { vaultId: otherVaultId }],
    ['group', { groupId: otherGroupId }],
    ['item', { entityId: otherItemId }],
    ['purpose', { purpose: 'history-event' }],
    ['schema version', { schemaVersion: 2 }],
  ] as const)('rejects %s context swapping', async (_name, aadChange) => {
    const key = generateItemKey();
    const envelope = await encryptAead(plaintext, key, itemPayloadAad());
    const tampered = {
      ...envelope,
      aad: { ...envelope.aad, ...aadChange },
    };
    await expect(
      decryptAead(tampered as unknown as AeadEnvelope, key, itemPayloadAad()),
    ).rejects.toBeInstanceOf(AuthenticationError);
  });

  it('authenticates both copies of key version', async () => {
    const key = generateItemKey();
    const envelope = await encryptAead(plaintext, key, itemPayloadAad());
    await expect(
      decryptAead(
        { ...envelope, keyVersion: 2 } as unknown as AeadEnvelope,
        key,
        itemPayloadAad(),
      ),
    ).rejects.toBeInstanceOf(AuthenticationError);
    await expect(
      decryptAead(
        {
          ...envelope,
          keyVersion: 2,
          aad: { ...envelope.aad, keyVersion: 2 },
        } as unknown as AeadEnvelope,
        key,
        itemPayloadAad(),
      ),
    ).rejects.toBeInstanceOf(AuthenticationError);
  });

  it('does not accept a valid item ciphertext under another item or group', async () => {
    const key = generateItemKey();
    const envelope = await encryptAead(plaintext, key, itemPayloadAad());
    const movedItem = {
      ...envelope,
      aad: { ...envelope.aad, entityId: otherItemId },
    };
    const movedGroup = {
      ...envelope,
      aad: { ...envelope.aad, groupId: otherGroupId },
    };
    await expect(
      decryptAead(movedItem as unknown as AeadEnvelope, key, itemPayloadAad()),
    ).rejects.toBeInstanceOf(AuthenticationError);
    await expect(
      decryptAead(movedGroup as unknown as AeadEnvelope, key, itemPayloadAad()),
    ).rejects.toBeInstanceOf(AuthenticationError);
    expect(envelope.aad.groupId).toBe(groupId);
  });
});
