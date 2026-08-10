import type * as CryptoModule from '@kavrix/crypto';

import { z } from 'zod';

import { CliKeyFileCreationError, CliUsageError } from './errors.js';
import {
  acquiredSecretSchema,
  type AcquiredSecret,
  type SecretInputPort,
} from './secret-input.js';

const MAX_PATH_CHARACTERS = 32_768;
export const MIN_PROTECTED_KEY_FILE_PASSPHRASE_BYTES = 12;
const MAX_PASSPHRASE_BYTES = 1_048_576;
const UNBOUND_KEY_FILE = Object.freeze({ kind: 'unbound' as const });

const keyCreateOptionsSchema = z
  .object({
    file: z
      .string()
      .min(1)
      .max(MAX_PATH_CHARACTERS)
      .refine((value) =>
        Array.from(value).every((character) => {
          const codePoint = character.codePointAt(0);
          return codePoint !== undefined && codePoint > 31 && codePoint !== 127;
        }),
      ),
    protectWithPassphrase: z.boolean().optional().default(false),
    passphraseStdin: z.boolean().optional().default(false),
  })
  .strict();

export async function executePortableKeyFileCreation(
  secrets: SecretInputPort,
  options: Readonly<Record<string, unknown>>,
): Promise<void> {
  const parsed = keyCreateOptionsSchema.safeParse(options);
  if (!parsed.success) {
    throw new CliUsageError('The portable key file request is invalid.');
  }
  if (parsed.data.passphraseStdin && !parsed.data.protectWithPassphrase) {
    throw new CliUsageError('--passphrase-stdin requires --protect-with-passphrase.');
  }

  let passphrase: Uint8Array | undefined;
  let portableKey: Uint8Array | undefined;
  let crypto: typeof CryptoModule | undefined;
  try {
    if (parsed.data.protectWithPassphrase) {
      const confirmed = await readConfirmedPassphrase(
        secrets,
        parsed.data.passphraseStdin,
      );
      passphrase = confirmed.passphrase;
      crypto = confirmed.crypto;
    }
    crypto ??= await import('@kavrix/crypto');
    const keyFiles = await import('@kavrix/key-files');
    portableKey = crypto.generatePortableKey();
    try {
      await keyFiles.writePortableKeyFile(
        parsed.data.file,
        portableKey,
        UNBOUND_KEY_FILE,
        {
          mode: 'create',
          protection:
            passphrase === undefined
              ? { kind: 'unprotected' }
              : { kind: 'passphrase', passphrase },
        },
      );
    } catch (error) {
      if (error instanceof keyFiles.PortableKeyFileError) {
        throw new CliKeyFileCreationError();
      }
      throw error;
    }
  } finally {
    crypto?.zeroize(portableKey);
    crypto?.zeroize(passphrase);
  }
}

async function readConfirmedPassphrase(
  secrets: SecretInputPort,
  fromStdin: boolean,
): Promise<Readonly<{ passphrase: Uint8Array; crypto: typeof CryptoModule }>> {
  let values: readonly AcquiredSecret[];
  try {
    const received = await secrets.readBatch({
      kinds: ['passphrase', 'passphrase'],
      fromStdin,
      requireEnd: fromStdin,
    });
    const parsed = z.array(acquiredSecretSchema).length(2).safeParse(received);
    if (!parsed.success) throw new CliUsageError('Passphrase input is invalid.');
    values = parsed.data;
  } catch (error) {
    if (error instanceof CliUsageError) throw error;
    throw new CliUsageError('Passphrase input could not be read.');
  }

  const first = values[0];
  const second = values[1];
  if (first === undefined || second === undefined) {
    throw new CliUsageError('Passphrase input is invalid.');
  }
  const crypto = await import('@kavrix/crypto');
  const firstBytes = new TextEncoder().encode(first);
  const secondBytes = new TextEncoder().encode(second);
  try {
    if (
      firstBytes.byteLength < MIN_PROTECTED_KEY_FILE_PASSPHRASE_BYTES ||
      secondBytes.byteLength < MIN_PROTECTED_KEY_FILE_PASSPHRASE_BYTES ||
      firstBytes.byteLength > MAX_PASSPHRASE_BYTES ||
      secondBytes.byteLength > MAX_PASSPHRASE_BYTES ||
      !crypto.constantTimeEqual(firstBytes, secondBytes)
    ) {
      throw new CliUsageError('Passphrase confirmation did not match.');
    }
    return { passphrase: firstBytes, crypto };
  } catch (error) {
    crypto.zeroize(firstBytes);
    throw error;
  } finally {
    crypto.zeroize(secondBytes);
  }
}
