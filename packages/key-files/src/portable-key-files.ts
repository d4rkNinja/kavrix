import {
  parsePortableKeyFile,
  parseProtectedPortableKeyFile,
  serializePortableKeyFile,
  serializeProtectedPortableKeyFile,
  zeroize,
  type ParsedPortableKeyFile,
  type PortableKey,
  type PortableKeyFileBinding,
} from '@kavrix/crypto';

import { readSecureFile, writeSecureFile } from './filesystem.js';

export type PortableKeyFileProtection =
  | { readonly kind: 'unprotected' }
  | { readonly kind: 'passphrase'; readonly passphrase: Uint8Array };

export type PortableKeyFileWriteOptions = Readonly<{
  mode?: 'create' | 'replace';
  protection: PortableKeyFileProtection;
}>;

export async function writePortableKeyFile(
  path: string,
  key: Uint8Array,
  binding: PortableKeyFileBinding,
  options: PortableKeyFileWriteOptions,
): Promise<void> {
  const ownedKey = Uint8Array.from(key);
  const ownedPassphrase =
    options.protection.kind === 'passphrase'
      ? Uint8Array.from(options.protection.passphrase)
      : undefined;
  let serialized: Uint8Array | undefined;
  try {
    serialized =
      options.protection.kind === 'unprotected'
        ? serializePortableKeyFile(ownedKey, binding)
        : await serializeProtectedPortableKeyFile(
            ownedKey,
            ownedPassphrase as Uint8Array,
            binding,
          );
    await writeSecureFile(path, serialized, options.mode ?? 'create');
  } finally {
    zeroize(serialized);
    zeroize(ownedPassphrase);
    zeroize(ownedKey);
  }
}

export async function readPortableKeyFile(
  path: string,
  protection: PortableKeyFileProtection,
  expectedBinding?: PortableKeyFileBinding,
): Promise<ParsedPortableKeyFile> {
  const ownedPassphrase =
    protection.kind === 'passphrase'
      ? Uint8Array.from(protection.passphrase)
      : undefined;
  let file: Uint8Array | undefined;
  try {
    file = await readSecureFile(path);
    return protection.kind === 'unprotected'
      ? parsePortableKeyFile(file, expectedBinding)
      : await parseProtectedPortableKeyFile(
          file,
          ownedPassphrase as Uint8Array,
          expectedBinding,
        );
  } finally {
    zeroize(file);
    zeroize(ownedPassphrase);
  }
}

export type { ParsedPortableKeyFile, PortableKey, PortableKeyFileBinding };
