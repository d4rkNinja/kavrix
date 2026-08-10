import { z } from 'zod';

import type { MongoApiServerConfig } from './server.js';
import { isExplicitIpOrCidr } from './trusted-proxy.js';

const environmentKeys = {
  mongodbUri: 'KAVRIX_MONGODB_URI',
  databaseName: 'KAVRIX_DATABASE_NAME',
  environment: 'KAVRIX_API_ENVIRONMENT',
  host: 'KAVRIX_API_HOST',
  port: 'KAVRIX_API_PORT',
  trustedProxy: 'KAVRIX_API_TRUSTED_PROXIES',
  bodyLimit: 'KAVRIX_API_BODY_LIMIT_BYTES',
  vaultBootstrapEnabled: 'KAVRIX_API_BOOTSTRAP_ENABLED',
  shutdownTimeoutMs: 'KAVRIX_API_SHUTDOWN_TIMEOUT_MS',
} as const;

const knownKeys = new Set<string>(Object.values(environmentKeys));

const decimalIntegerSchema = z
  .string()
  .regex(/^(?:0|[1-9][0-9]*)$/u)
  .transform(Number);

const trustedProxyEntrySchema = z.string().refine(isExplicitIpOrCidr);

const serviceEnvironmentSchema = z
  .object({
    mongodbUri: z
      .string()
      .min(1)
      .max(4_096)
      .regex(/^mongodb(?:\+srv)?:\/\//u)
      .refine(hasNoControlCharacters),
    databaseName: z
      .string()
      .min(1)
      .max(64)
      .regex(/^[^/\\. "$*<>:|?]+$/u)
      .default('kavrix'),
    environment: z.enum(['development', 'production', 'test']).default('production'),
    host: z
      .string()
      .min(1)
      .max(253)
      .regex(/^[A-Za-z0-9._:-]+$/u)
      .default('127.0.0.1'),
    port: decimalIntegerSchema.pipe(z.number().int().min(1).max(65_535)).default(3_000),
    trustedProxy: z
      .string()
      .min(1)
      .max(4_096)
      .transform((value) => value.split(',').map((entry) => entry.trim()))
      .pipe(z.array(trustedProxyEntrySchema).min(1))
      .optional(),
    bodyLimit: decimalIntegerSchema
      .pipe(
        z
          .number()
          .int()
          .min(1_024)
          .max(64 * 1_024 * 1_024),
      )
      .optional(),
    vaultBootstrapEnabled: z
      .enum(['true', 'false'])
      .transform((value) => value === 'true')
      .default(false),
    shutdownTimeoutMs: decimalIntegerSchema
      .pipe(z.number().int().min(100).max(300_000))
      .default(15_000),
  })
  .strict();

type ServiceEnvironment = z.infer<typeof serviceEnvironmentSchema>;
type EnvironmentSetting =
  (typeof environmentKeys)[keyof typeof environmentKeys] | 'KAVRIX_API_*';

export interface MongoApiServiceConfig {
  readonly server: MongoApiServerConfig;
  readonly shutdownTimeoutMs: number;
}

export class ApiServiceConfigurationError extends Error {
  public readonly setting: EnvironmentSetting;

  public constructor(setting: EnvironmentSetting) {
    super('Invalid Kavrix API service configuration');
    this.name = 'ApiServiceConfigurationError';
    this.setting = setting;
  }
}

/** Parses only the documented service variables; values never appear in errors. */
export function parseMongoApiServiceEnvironment(
  environment: Readonly<Record<string, string | undefined>>,
): MongoApiServiceConfig {
  if (
    Object.keys(environment).some(
      (key) => key.startsWith('KAVRIX_API_') && !knownKeys.has(key),
    )
  ) {
    throw new ApiServiceConfigurationError('KAVRIX_API_*');
  }

  const parsed = serviceEnvironmentSchema.safeParse({
    mongodbUri: environment[environmentKeys.mongodbUri],
    databaseName: environment[environmentKeys.databaseName],
    environment: environment[environmentKeys.environment],
    host: environment[environmentKeys.host],
    port: environment[environmentKeys.port],
    trustedProxy: environment[environmentKeys.trustedProxy],
    bodyLimit: environment[environmentKeys.bodyLimit],
    vaultBootstrapEnabled: environment[environmentKeys.vaultBootstrapEnabled],
    shutdownTimeoutMs: environment[environmentKeys.shutdownTimeoutMs],
  });
  if (!parsed.success) {
    const issue = parsed.error.issues[0];
    throw new ApiServiceConfigurationError(
      issue === undefined ? 'KAVRIX_API_*' : settingForIssue(issue),
    );
  }
  return toServiceConfig(parsed.data);
}

function toServiceConfig(environment: ServiceEnvironment): MongoApiServiceConfig {
  return {
    server: {
      mongodbUri: environment.mongodbUri,
      databaseName: environment.databaseName,
      environment: environment.environment,
      host: environment.host,
      port: environment.port,
      ...(environment.trustedProxy === undefined
        ? {}
        : { trustedProxy: environment.trustedProxy }),
      ...(environment.bodyLimit === undefined
        ? {}
        : { bodyLimit: environment.bodyLimit }),
      vaultBootstrapEnabled: environment.vaultBootstrapEnabled,
    },
    shutdownTimeoutMs: environment.shutdownTimeoutMs,
  };
}

function settingForIssue(issue: z.core.$ZodIssue): EnvironmentSetting {
  const field = issue.path[0];
  if (typeof field !== 'string' || !(field in environmentKeys)) {
    return 'KAVRIX_API_*';
  }
  return environmentKeys[field as keyof typeof environmentKeys];
}

function hasNoControlCharacters(value: string): boolean {
  for (const character of value) {
    const codePoint = character.codePointAt(0);
    if (codePoint !== undefined && (codePoint < 32 || codePoint === 127)) return false;
  }
  return true;
}
