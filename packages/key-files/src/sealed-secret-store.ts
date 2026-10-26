import { createHash, hkdfSync, randomBytes } from 'node:crypto';
import { mkdir } from 'node:fs/promises';
import { join } from 'node:path';

import {
  createPassphraseDerivation,
  decodeBase64Url,
  derivePassphraseKek,
  zeroize,
} from '@kavrix/crypto';
import { passphraseDerivationSchema } from '@kavrix/schemas';
import sodium from 'libsodium-wrappers';

import { PortableKeyFileError } from './errors.js';
import {
  deleteSecureFile,
  hardenExistingSecureDirectory,
  readSecureFile,
  writeSecureFile,
} from './filesystem.js';

/**
 * Passphrase-sealed replacement for the native OS credential store.
 *
 * This exists because the published npm package is dependency-free and cannot
 * load `@napi-rs/keyring`. It is deliberately *not* a plaintext fallback: every
 * secret is sealed with XChaCha20-Poly1305 under an Argon2id-derived key that
 * only ever exists in memory for the lifetime of one command. Losing the
 * passphrase means losing the sealed material, which is the intended property.
 */
const MAGIC = Uint8Array.of(0x43, 0x56, 0x53, 0x53);
const FORMAT_VERSION = 1;
const ALGORITHM_XCHACHA20_POLY1305 = 1;
const NONCE_BYTES = 24;
const TAG_BYTES = 16;
const HEADER_BYTES = MAGIC.byteLength + 2 + NONCE_BYTES + TAG_BYTES;
const PARAMS_BASENAME = 'store-params.v1.json';
const SEAL_SUFFIX = '.seal';
const MAX_SECRET_BYTES = 8192;

/** Distinct from `credvault/portable-key-file/*`, so envelopes cannot be swapped. */
const AAD_DOMAIN = 'credvault/sealed-secret/v1';
const SUBKEY_INFO = 'credvault/v1/sealed-secret-subkey';

/**
 * Service and account names are caller-supplied but are interpolated straight
 * into cryptographic domain separators, so an ambiguous label would create an
 * ambiguous binding rather than an error. One short, NUL-free, printable
 * charset is the contract; anything else is refused before any key material
 * exists.
 */
const ENTRY_LABEL_PATTERN = /^[A-Za-z0-9._@:+-]{1,64}$/;

function assertEntryLabels(service: string, account: string): void {
  if (!ENTRY_LABEL_PATTERN.test(service) || !ENTRY_LABEL_PATTERN.test(account)) {
    throw new PortableKeyFileError('KEY_FILE_UNSAFE');
  }
}

function entryDigest(service: string, account: string): string {
  return createHash('sha256')
    .update(`${AAD_DOMAIN}\u0000${service}\u0000${account}`, 'utf8')
    .digest('hex');
}

function associatedData(service: string, account: string): Uint8Array {
  return Buffer.from(
    `${AAD_DOMAIN}\u0000${String(FORMAT_VERSION)}\u0000${service}\u0000${account}`,
    'utf8',
  );
}

function subkey(masterKek: Uint8Array, service: string, account: string): Uint8Array {
  const salt = Buffer.from(entryDigest(service, account), 'hex');
  const derived = new Uint8Array(
    hkdfSync('sha256', masterKek, salt, Buffer.from(SUBKEY_INFO, 'ascii'), 32),
  );
  zeroize(salt);
  return derived;
}

function corrupted(): PortableKeyFileError {
  return new PortableKeyFileError('KEY_FILE_UNSAFE');
}

export interface SealedSecretStoreOptions {
  /** Directory that holds the derivation parameters and one file per account. */
  readonly directory: string;
  /**
   * Supplies the master passphrase. Invoked at most once per store instance and
   * the returned bytes are zeroized as soon as the key is derived.
   */
  readonly passphrase: () => Promise<Uint8Array>;
}

export class SealedSecretStore {
  readonly #directory: string;
  readonly #passphrase: () => Promise<Uint8Array>;
  #masterKek: Promise<Uint8Array> | undefined;

  public constructor(options: SealedSecretStoreOptions) {
    this.#directory = options.directory;
    this.#passphrase = options.passphrase;
  }

  /** Best-effort zeroization of the derived key held for this process. */
  public async close(): Promise<void> {
    const pending = this.#masterKek;
    this.#masterKek = undefined;
    if (pending === undefined) return;
    try {
      zeroize(await pending);
    } catch {
      /* A failed derivation holds no key material to clear. */
    }
  }

  public async store(
    service: string,
    account: string,
    secret: Uint8Array,
  ): Promise<void> {
    assertEntryLabels(service, account);
    if (secret.byteLength === 0 || secret.byteLength > MAX_SECRET_BYTES) {
      throw new PortableKeyFileError('KEY_FILE_OPERATION_FAILED');
    }
    const key = subkey(await this.#master(), service, account);
    const nonce = randomBytes(NONCE_BYTES);
    const aad = associatedData(service, account);
    try {
      await sodium.ready;
      const sealed = sodium.crypto_aead_xchacha20poly1305_ietf_encrypt_detached(
        secret,
        aad,
        null,
        nonce,
        key,
      );
      const file = new Uint8Array(HEADER_BYTES + sealed.ciphertext.byteLength);
      let offset = 0;
      file.set(MAGIC, offset);
      offset += MAGIC.byteLength;
      file[offset] = FORMAT_VERSION;
      offset += 1;
      file[offset] = ALGORITHM_XCHACHA20_POLY1305;
      offset += 1;
      file.set(nonce, offset);
      offset += NONCE_BYTES;
      file.set(sealed.mac, offset);
      offset += TAG_BYTES;
      file.set(sealed.ciphertext, offset);
      try {
        await this.#write(this.#pathFor(service, account), file);
      } finally {
        zeroize(file);
      }
    } finally {
      zeroize(key);
      zeroize(nonce);
      zeroize(aad);
    }
  }

  public async load(service: string, account: string): Promise<Uint8Array | null> {
    assertEntryLabels(service, account);
    let file: Buffer;
    try {
      file = await readSecureFile(this.#pathFor(service, account));
    } catch (error) {
      if (
        error instanceof PortableKeyFileError &&
        error.code === 'KEY_FILE_NOT_FOUND'
      ) {
        return null;
      }
      throw error;
    }
    if (
      file.byteLength <= HEADER_BYTES ||
      !MAGIC.every((value, index) => file[index] === value) ||
      file[MAGIC.byteLength] !== FORMAT_VERSION ||
      file[MAGIC.byteLength + 1] !== ALGORITHM_XCHACHA20_POLY1305
    ) {
      zeroize(file);
      throw corrupted();
    }
    const key = subkey(await this.#master(), service, account);
    const aad = associatedData(service, account);
    try {
      let offset = MAGIC.byteLength + 2;
      const nonce = file.subarray(offset, offset + NONCE_BYTES);
      offset += NONCE_BYTES;
      const tag = file.subarray(offset, offset + TAG_BYTES);
      offset += TAG_BYTES;
      const ciphertext = file.subarray(offset);
      await sodium.ready;
      return sodium.crypto_aead_xchacha20poly1305_ietf_decrypt_detached(
        null,
        ciphertext,
        tag,
        aad,
        nonce,
        key,
      );
    } catch {
      throw corrupted();
    } finally {
      zeroize(key);
      zeroize(aad);
      zeroize(file);
    }
  }

  public async delete(service: string, account: string): Promise<void> {
    assertEntryLabels(service, account);
    try {
      // Deletion goes through the quarantine-rename primitive: the exact file
      // is identity-rechecked (regular, singly linked, bounded) before it is
      // unlinked, so a replaced path or a hard link can never widen deletion.
      await deleteSecureFile(this.#pathFor(service, account));
    } catch (error) {
      if (
        error instanceof PortableKeyFileError &&
        error.code === 'KEY_FILE_NOT_FOUND'
      ) {
        // An absent entry — or an absent store directory — is already deleted.
        return;
      }
      throw error;
    }
  }

  /**
   * `writeSecureFile` separates creation from replacement so neither mode has to
   * tolerate an ambiguous target; the store picks whichever applies.
   */
  async #write(path: string, contents: Uint8Array): Promise<void> {
    try {
      await writeSecureFile(path, contents, 'create');
      return;
    } catch (error) {
      if (
        !(error instanceof PortableKeyFileError) ||
        error.code !== 'KEY_FILE_ALREADY_EXISTS'
      ) {
        throw error;
      }
    }
    await writeSecureFile(path, contents, 'replace');
  }

  #pathFor(service: string, account: string): string {
    return join(this.#directory, `${entryDigest(service, account)}${SEAL_SUFFIX}`);
  }

  /**
   * The secure-file layer requires a user-only directory, so the store owns
   * provisioning rather than trusting whatever permissions it inherits.
   *
   * `ensureSecureDirectory` cannot be used here because it never creates the
   * parent chain, and the store directory may sit several levels deep under
   * the user profile. The recursive creation is therefore followed by the
   * package's re-hardening primitive: it refuses symlinks and reparse points,
   * binds the POSIX chmod to the captured inode instead of the pathname, and
   * re-verifies strict owner-only access on both platforms.
   */
  async #ensureDirectory(): Promise<void> {
    try {
      await mkdir(this.#directory, { recursive: true, mode: 0o700 });
      await hardenExistingSecureDirectory(this.#directory);
    } catch (error) {
      if (error instanceof PortableKeyFileError) throw error;
      throw new PortableKeyFileError('KEY_FILE_UNSAFE');
    }
  }

  #master(): Promise<Uint8Array> {
    this.#masterKek ??= this.#deriveMaster();
    return this.#masterKek;
  }

  async #deriveMaster(): Promise<Uint8Array> {
    const derivation = await this.#loadOrCreateDerivation();
    const passphrase = await this.#passphrase();
    try {
      return await derivePassphraseKek(passphrase, derivation);
    } finally {
      zeroize(passphrase);
    }
  }

  async #loadOrCreateDerivation(): Promise<
    ReturnType<typeof createPassphraseDerivation>
  > {
    await this.#ensureDirectory();
    const path = join(this.#directory, PARAMS_BASENAME);
    try {
      const raw = await readSecureFile(path);
      try {
        return parseDerivation(JSON.parse(raw.toString('utf8')));
      } finally {
        zeroize(raw);
      }
    } catch (error) {
      if (
        !(error instanceof PortableKeyFileError) ||
        error.code !== 'KEY_FILE_NOT_FOUND'
      ) {
        throw error;
      }
    }
    const created = createPassphraseDerivation();
    await writeSecureFile(path, Buffer.from(JSON.stringify(created), 'utf8'), 'create');
    return created;
  }
}

function parseDerivation(
  value: unknown,
): ReturnType<typeof createPassphraseDerivation> {
  try {
    const parsed = passphraseDerivationSchema.parse(value);
    const salt = decodeBase64Url(parsed.salt, { exactBytes: 16 });
    zeroize(salt);
    return parsed;
  } catch {
    throw corrupted();
  }
}

/**
 * Adapts the sealed store to the same entry shape the native keychain exposes,
 * so `NativeKeychain`, `NativeSessionCredentials`, and `NativeProtectedSyncState`
 * can run unchanged over either backend.
 */
export function sealedEntryFactory(store: SealedSecretStore): (
  service: string,
  account: string,
) => {
  setSecret(secret: Uint8Array): Promise<void>;
  getSecret(): Promise<Uint8Array | null>;
  deleteCredential(): Promise<void>;
} {
  return (service, account) => ({
    setSecret: (secret) => store.store(service, account, secret),
    getSecret: () => store.load(service, account),
    deleteCredential: () => store.delete(service, account),
  });
}
