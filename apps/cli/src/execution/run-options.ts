import { environmentVariableNameSchema } from '@kavrix/schemas';

import { invalidConfiguration } from './exit-codes.js';
import type { DatabaseFlatCommandOptions } from '../database-flat-commands.js';

/** Options accepted by `kavrix run`. */
export type RunCliOptions = DatabaseFlatCommandOptions &
  Readonly<{
    secretMappings?: readonly string[] | undefined;
    environmentName?: string | undefined;
    config?: string | undefined;
    noConfig?: boolean | undefined;
    policyIds?: readonly string[] | undefined;
    grantRefs?: readonly string[] | undefined;
    json?: boolean | undefined;
    executableAndArgs: readonly string[];
  }>;

/** One validated destination-variable to credential-name mapping. */
export type ResolvedMapping = Readonly<{ destination: string; secret: string }>;

export function parseSecretMappings(
  rawValues: readonly string[],
): readonly ResolvedMapping[] {
  return rawValues.map((raw) => {
    const separator = raw.indexOf('=');
    if (separator <= 0 || separator === raw.length - 1) {
      throw invalidMapping(raw);
    }
    const destination = raw.slice(0, separator);
    const secret = raw.slice(separator + 1);
    if (!environmentVariableNameSchema.safeParse(destination).success) {
      throw invalidMapping(raw);
    }
    if (
      secret.length === 0 ||
      secret.length > 256 ||
      // Control characters are invalid in credential references by contract.
      // eslint-disable-next-line no-control-regex
      /[\u0000-\u001f\u007f]/u.test(secret)
    ) {
      throw invalidMapping(raw);
    }
    return { destination, secret };
  });
}

function invalidMapping(raw: string): Error {
  return invalidConfiguration(
    `--secret expects DESTINATION_VARIABLE=CREDENTIAL_NAME (received '${safeSample(raw)}').`,
  );
}

function safeSample(value: string): string {
  return value.length > 64 ? `${value.slice(0, 61)}...` : value;
}

/** Merges mapping sources; later sources override earlier identical destinations. */
export function mergeMappings(
  ...sources: readonly (readonly ResolvedMapping[])[]
): readonly ResolvedMapping[] {
  const merged = new Map<string, string>();
  for (const source of sources) {
    for (const mapping of source) {
      const existing = merged.get(mapping.destination);
      if (existing !== undefined && existing !== mapping.secret) {
        throw invalidConfiguration(
          `Destination variable '${mapping.destination}' maps to conflicting credentials.`,
        );
      }
      merged.set(mapping.destination, mapping.secret);
    }
  }
  return [...merged].map(([destination, secret]) => ({ destination, secret }));
}

/** Builds a bounded, control-character-free preview of child arguments for audit. */
export function auditArgvPreview(
  argv: readonly string[],
): readonly string[] | undefined {
  if (argv.length === 0) return undefined;
  return argv.slice(0, 8).map((argument) => {
    // Strip terminal control sequences from untrusted argv previews.
    // eslint-disable-next-line no-control-regex
    const stripped = argument.replace(/[\u0000-\u001f\u007f]/gu, '?');
    return stripped.length > 64 ? `${stripped.slice(0, 61)}...` : stripped;
  });
}
