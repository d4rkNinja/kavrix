import { createHmac, hkdfSync } from 'node:crypto';

import {
  constantTimeEqual,
  decodeBase64Url,
  encodeBase64Url,
  requireByteLength,
  zeroize,
} from '@kavrix/crypto';
import {
  keySlotIdSchema,
  sha256DigestSchema,
  vaultIdSchema,
  vaultRevisionSchema,
  type KeySlotId,
  type Sha256Digest,
  type VaultId,
  type VaultRevision,
} from '@kavrix/schemas';

import { PortableKeyFileError } from './errors.js';
import { readSecureFile, writeSecureFile } from './filesystem.js';

const FORMAT = 'kavrix-revision-anchor';
const VERSION = 1;
const DOMAIN = 'kavrix/revision-anchor/v1';
const ROOT_KEY_BYTES = 32;
const TAG_BYTES = 32;
const MAX_FILE_BYTES = 16_384;
const ANCHOR_KDF_SALT = new Uint8Array(32);
const ANCHOR_KDF_INFO = Buffer.from('kavrix/revision-anchor/hmac-key/v1', 'ascii');

export type RevisionAnchor = Readonly<{
  vaultId: VaultId;
  keySlotId: KeySlotId;
  revision: VaultRevision;
  metadataDigest: Sha256Digest;
}>;

type RevisionAnchorEnvelope = RevisionAnchor &
  Readonly<{
    format: typeof FORMAT;
    version: typeof VERSION;
    authenticationTag: string;
  }>;

export async function writeRevisionAnchor(
  path: string,
  rootKey: Uint8Array,
  anchor: RevisionAnchor,
  mode: 'create' | 'replace',
): Promise<void> {
  requireByteLength(rootKey, ROOT_KEY_BYTES, 'vault root key');
  validateAnchor(anchor);
  let message: Uint8Array | undefined;
  let tag: Uint8Array | undefined;
  let serialized: Uint8Array | undefined;
  try {
    message = anchorMessage(anchor);
    tag = hmac(rootKey, message);
    const envelope: RevisionAnchorEnvelope = {
      format: FORMAT,
      version: VERSION,
      vaultId: anchor.vaultId,
      keySlotId: anchor.keySlotId,
      revision: anchor.revision,
      metadataDigest: anchor.metadataDigest,
      authenticationTag: encodeBase64Url(tag),
    };
    serialized = Buffer.from(JSON.stringify(envelope) + '\n', 'ascii');
    await writeSecureFile(path, serialized, mode);
  } finally {
    zeroize(message);
    zeroize(tag);
    zeroize(serialized);
  }
}

export async function readRevisionAnchor(
  path: string,
  rootKey: Uint8Array,
  expectedBinding: Pick<RevisionAnchor, 'vaultId' | 'keySlotId'>,
): Promise<RevisionAnchor> {
  requireByteLength(rootKey, ROOT_KEY_BYTES, 'vault root key');
  const file = await readSecureFile(path, MAX_FILE_BYTES);
  let message: Uint8Array | undefined;
  let suppliedTag: Uint8Array | undefined;
  let expectedTag: Uint8Array | undefined;
  try {
    const envelope = parseEnvelope(JSON.parse(file.toString('utf8')) as unknown);
    if (
      envelope.vaultId !== expectedBinding.vaultId ||
      envelope.keySlotId !== expectedBinding.keySlotId
    ) {
      throw invalidAnchor();
    }
    message = anchorMessage(envelope);
    suppliedTag = decodeBase64Url(envelope.authenticationTag, {
      exactBytes: TAG_BYTES,
    });
    expectedTag = hmac(rootKey, message);
    if (!constantTimeEqual(suppliedTag, expectedTag)) {
      throw invalidAnchor();
    }
    return {
      vaultId: envelope.vaultId,
      keySlotId: envelope.keySlotId,
      revision: envelope.revision,
      metadataDigest: envelope.metadataDigest,
    };
  } catch {
    throw invalidAnchor();
  } finally {
    file.fill(0);
    zeroize(message);
    zeroize(suppliedTag);
    zeroize(expectedTag);
  }
}

export async function copyRevisionAnchor(
  sourcePath: string,
  destinationPath: string,
  mode: 'create' | 'replace',
): Promise<void> {
  const contents = await readSecureFile(sourcePath, MAX_FILE_BYTES);
  try {
    await writeSecureFile(destinationPath, contents, mode);
  } finally {
    contents.fill(0);
  }
}

export async function validateRevisionAnchorFile(path: string): Promise<void> {
  const contents = await readSecureFile(path, MAX_FILE_BYTES);
  contents.fill(0);
}

function hmac(rootKey: Uint8Array, message: Uint8Array): Uint8Array {
  const anchorKey = new Uint8Array(
    hkdfSync('sha256', rootKey, ANCHOR_KDF_SALT, ANCHOR_KDF_INFO, ROOT_KEY_BYTES),
  );
  try {
    return Uint8Array.from(createHmac('sha256', anchorKey).update(message).digest());
  } finally {
    zeroize(anchorKey);
  }
}

function anchorMessage(
  anchor: Pick<RevisionAnchor, 'vaultId' | 'keySlotId' | 'revision' | 'metadataDigest'>,
): Uint8Array {
  return Buffer.from(
    JSON.stringify({
      domain: DOMAIN,
      format: FORMAT,
      version: VERSION,
      vaultId: anchor.vaultId,
      keySlotId: anchor.keySlotId,
      revision: anchor.revision,
      metadataDigest: anchor.metadataDigest,
    }),
    'utf8',
  );
}

function parseEnvelope(value: unknown): RevisionAnchorEnvelope {
  if (typeof value !== 'object' || value === null || Array.isArray(value)) {
    throw invalidAnchor();
  }
  const record = value as Record<string, unknown>;
  const keys = [
    'format',
    'version',
    'vaultId',
    'keySlotId',
    'revision',
    'metadataDigest',
    'authenticationTag',
  ];
  if (
    Object.keys(record).length !== keys.length ||
    keys.some((key) => !Object.hasOwn(record, key))
  ) {
    throw invalidAnchor();
  }
  if (record['format'] !== FORMAT || record['version'] !== VERSION) {
    throw invalidAnchor();
  }
  try {
    const vaultId = vaultIdSchema.parse(record['vaultId']);
    const keySlotId = keySlotIdSchema.parse(record['keySlotId']);
    const revision = vaultRevisionSchema.parse(record['revision']);
    const metadataDigest = sha256DigestSchema.parse(record['metadataDigest']);
    if (typeof record['authenticationTag'] !== 'string') throw invalidAnchor();
    return {
      format: FORMAT,
      version: VERSION,
      vaultId,
      keySlotId,
      revision,
      metadataDigest,
      authenticationTag: record['authenticationTag'],
    };
  } catch {
    throw invalidAnchor();
  }
}

function validateAnchor(anchor: RevisionAnchor): void {
  vaultIdSchema.parse(anchor.vaultId);
  keySlotIdSchema.parse(anchor.keySlotId);
  vaultRevisionSchema.parse(anchor.revision);
  sha256DigestSchema.parse(anchor.metadataDigest);
}

function invalidAnchor(): PortableKeyFileError {
  return new PortableKeyFileError('KEY_FILE_UNSAFE');
}
