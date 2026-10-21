import { randomFillSync } from 'node:crypto';

import { generateSecret } from '@kavrix/core';
import {
  DEFAULT_GENERATED_SECRET_LENGTH,
  secretGenerationRequestSchema,
  type SecretGenerationRequest,
} from '@kavrix/schemas';

import { LocalCliError } from './cli-error.js';
import {
  readDatabaseFlatSecrets,
  rejectUnboundDatabaseProfile,
  usesDatabaseContainer,
  withDatabaseFlatVault,
} from './database-flat-commands.js';
import { CodedCliError } from './execution/exit-codes.js';
import {
  flatOptions,
  validateImportedName,
  type DatabaseVaultRoutingOptions,
} from './import-env-command-impl.js';

export type GenerateCommandOptions = DatabaseVaultRoutingOptions &
  Readonly<{
    length?: string;
    format?: string;
    lowercase?: boolean;
    uppercase?: boolean;
    digits?: boolean;
    symbols?: boolean;
    excludeAmbiguous?: boolean;
    reveal?: boolean;
    overwrite?: boolean;
    json?: boolean;
  }>;

function usage(message: string): CodedCliError {
  return new CodedCliError('USAGE_ERROR', message);
}

/** Builds and validates one generation request from command flags. */
export function generationRequestFromOptions(
  options: GenerateCommandOptions,
): SecretGenerationRequest {
  const lengthText = options.length ?? String(DEFAULT_GENERATED_SECRET_LENGTH);
  if (!/^\d{1,4}$/u.test(lengthText)) {
    throw usage('--length must be a whole number from 8 to 1024.');
  }
  const result = secretGenerationRequestSchema.safeParse({
    format: options.format ?? 'password',
    length: Number(lengthText),
    lowercase: options.lowercase !== false,
    uppercase: options.uppercase !== false,
    digits: options.digits !== false,
    symbols: options.symbols !== false,
    excludeAmbiguous: options.excludeAmbiguous === true,
  });
  if (!result.success) {
    const field = result.error.issues[0]?.path[0];
    if (field === 'length')
      throw usage('--length must be a whole number from 8 to 1024.');
    if (field === 'format' && options.format !== undefined) {
      if (!['password', 'hex', 'base64url'].includes(options.format)) {
        throw usage('--format must be password, hex, or base64url.');
      }
    }
    throw usage(
      'A password needs at least one character class; remove one of the --no-* flags.',
    );
  }
  return result.data;
}

const csprng = (target: Uint8Array): void => {
  randomFillSync(target);
};

export async function handleGenerate(
  name: string | undefined,
  options: GenerateCommandOptions,
): Promise<void> {
  const request = generationRequestFromOptions(options);
  if (name === undefined && options.reveal !== true) {
    throw usage(
      'Pass a credential name to store the generated secret, or --reveal to print it.',
    );
  }
  if (name !== undefined && options.reveal === true) {
    throw usage(
      'Choose one: a credential name stores the secret without showing it; --reveal prints it without storing.',
    );
  }
  if (name === undefined) {
    const generated = generateSecret(request, csprng);
    if (options.json === true) {
      process.stdout.write(
        JSON.stringify({
          value: generated.value,
          format: request.format,
          length: request.length,
          entropyBits: generated.entropyBits,
        }) + '\n',
      );
      return;
    }
    process.stdout.write(generated.value + '\n');
    return;
  }
  validateImportedName(name);
  const flat = flatOptions(options);
  await rejectUnboundDatabaseProfile(flat, 'generate');
  if (!(await usesDatabaseContainer(flat))) {
    throw new LocalCliError(
      'generate requires a database-container profile to store a secret; use --reveal to print one instead.',
    );
  }
  const secrets = await readDatabaseFlatSecrets(flat, []);
  let entropyBits = 0;
  let overwritten = false;
  await withDatabaseFlatVault(flat, secrets, async (session, vaultId) => {
    await session.updateVault(vaultId, (payload) => {
      overwritten = Object.hasOwn(payload.records, name);
      if (overwritten && options.overwrite !== true) {
        throw new LocalCliError(
          `Credential already exists: ${name}. Re-run with --overwrite to replace it.`,
        );
      }
      // Generate inside the authenticated update so a failed unlock never
      // leaves a fresh secret behind in this process.
      const generated = generateSecret(request, csprng);
      entropyBits = generated.entropyBits;
      payload.records[name] = {
        value: generated.value,
        updatedAt: new Date().toISOString(),
      };
      return payload;
    });
  });
  if (options.json === true) {
    process.stdout.write(
      JSON.stringify({
        stored: true,
        name,
        format: request.format,
        length: request.length,
        entropyBits,
        overwritten,
      }) + '\n',
    );
    return;
  }
  process.stdout.write(
    `Generated a ${String(request.length)}-character ${request.format} secret (about ${String(entropyBits)} bits) and stored it as ${name}. The value was not displayed.\n`,
  );
}
