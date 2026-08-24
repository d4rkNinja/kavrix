import { z } from 'zod';

import {
  AEAD_AUTHENTICATION_TAG_BASE64URL_CHARS,
  AEAD_NONCE_BASE64URL_CHARS,
} from './encrypted-records.js';
import { OPAQUE_ID_PATTERN_SOURCE, grantIdSchema } from './identifiers.js';
import { base64UrlSchema, slugSchema, timestampSchema } from './primitives.js';
/**
 * Credential execution policy contracts: permission entries, project
 * configuration, temporary grants, runtime audit events, machine decisions,
 * and the sealed local authorization-state envelope. These types are the single
 * canonical vocabulary shared by the CLI, the runner boundary, and tests.
 */

export const MAX_CREDENTIAL_REFERENCE_CHARS = 256;
export const MAX_COMMANDS_PER_ENTRY = 64;
export const MAX_HASHES_PER_ENTRY = 32;
export const MAX_STORED_POLICIES = 128;
export const MAX_STORED_GRANTS = 128;
export const MAX_RUNTIME_AUDIT_EVENTS = 512;
export const MAX_PROJECT_POLICIES = 128;
export const MAX_PROJECT_ENVIRONMENTS = 32;
export const MAX_SECRETS_PER_ENVIRONMENT = 64;
export const MAX_PROJECT_AGENTS = 32;
export const MAX_PERMISSIONS_PER_AGENT = 64;
export const MAX_CONFIRMATION_TOKENS = 16;
export const MAX_ARGV_PREVIEW_ENTRIES = 8;
export const MAX_ARGV_PREVIEW_CHARS = 64;
export const MAX_POLICY_DURATION_MS = 30 * 24 * 60 * 60 * 1000;
export const MAX_AUTHORIZATION_STATE_BYTES = 512 * 1024;

const RESERVED_CREDENTIAL_REFERENCES = new Set([
  '__proto__',
  'constructor',
  'prototype',
]);

/** Reference to one credential name inside the selected vault. */
export const credentialReferenceSchema = z
  .string()
  .min(1)
  .max(MAX_CREDENTIAL_REFERENCE_CHARS)
  // Control characters are rejected deliberately; they cannot appear in safe references.
  // eslint-disable-next-line no-control-regex
  .refine((value) => !/[\u0000-\u001f\u007f]/u.test(value), {
    message: 'Credential references must not contain control characters',
  })
  .refine((value) => value.trim() === value, {
    message: 'Credential references must not start or end with whitespace',
  })
  .refine((value) => !RESERVED_CREDENTIAL_REFERENCES.has(value), {
    message: 'Credential reference is reserved',
  });

/** Non-secret environment or project label used in configuration files. */
export const environmentNameSchema = z
  .string()
  .min(1)
  .max(64)
  .regex(/^[A-Za-z0-9][A-Za-z0-9._-]*$/u, 'Invalid environment name');

export const ENVIRONMENT_VARIABLE_NAME_PATTERN_SOURCE =
  '^[A-Za-z_][A-Za-z0-9_]{0,127}$';

/** Destination variable name for injected values; portable across platforms. */
export const environmentVariableNameSchema = z
  .string()
  .regex(
    new RegExp(ENVIRONMENT_VARIABLE_NAME_PATTERN_SOURCE),
    'Invalid environment variable name',
  );

/**
 * Bare executable name as it may appear on PATH. Path separators, whitespace,
 * and shell metacharacters are rejected so a command entry can never smuggle
 * arguments or shell syntax into an authorized executable name.
 */
export const commandNameSchema = z
  .string()
  .min(1)
  .max(128)
  .regex(
    /^[A-Za-z0-9][A-Za-z0-9._+-]*$/u,
    'Command names must be bare executable names',
  );

/** First-argument token used by confirmation requirements. */
export const commandTokenSchema = z
  .string()
  .min(1)
  .max(64)
  .regex(/^[A-Za-z0-9][A-Za-z0-9._=+-]*$/u, 'Invalid command token');

const opaquePattern = new RegExp(OPAQUE_ID_PATTERN_SOURCE);

/** Unbranded opaque identifier shape for map keys and cross-references. */
export const opaqueIdentifierSchema = z
  .string()
  .min(1)
  .max(128)
  .regex(opaquePattern, 'Must be an opaque identifier');

/** Lowercase hexadecimal SHA-256 digest of an executable file. */
export const sha256HexDigestSchema = z
  .string()
  .regex(/^[0-9a-f]{64}$/u, 'Must be a lowercase hex SHA-256 digest');

export const DURATION_PATTERN_SOURCE = '^([1-9][0-9]{0,6})([smhd])$';

const durationPattern = new RegExp(DURATION_PATTERN_SOURCE);

/** Bounded human duration (`15m`, `12h`, `7d`) used for TTLs. */
export const durationSchema = z.string().regex(durationPattern, 'Invalid duration');

/**
 * Converts a validated duration to milliseconds, or returns undefined when the
 * value exceeds the supported maximum. Lexical validity alone does not imply
 * representability, so callers must treat undefined as invalid configuration.
 */
export function parseDurationToMs(value: string): number | undefined {
  if (!durationPattern.test(value)) return undefined;
  const match = durationPattern.exec(value);
  const amountText = match?.[1];
  const unit = match?.[2];
  if (amountText === undefined || unit === undefined) return undefined;
  const amount = Number(amountText);
  if (!Number.isSafeInteger(amount) || amount <= 0) return undefined;
  const multiplier = UNIT_MULTIPLIERS[unit];
  if (multiplier === undefined) return undefined;
  const totalMs = amount * multiplier;
  return totalMs <= MAX_POLICY_DURATION_MS ? totalMs : undefined;
}

const UNIT_MULTIPLIERS: Readonly<Record<string, number>> = Object.freeze({
  s: 1_000,
  m: 60_000,
  h: 3_600_000,
  d: 86_400_000,
});

/**
 * Confirmation requirement: `true` always asks; an array asks only when the
 * first argument of the resolved command equals one of the listed tokens.
 */
export const confirmationRequirementSchema = z.union([
  z.boolean(),
  z.array(commandTokenSchema).min(1).max(MAX_CONFIRMATION_TOKENS),
]);

export const positiveMaxUsesSchema = z.number().int().min(1).max(1_000_000);

/** Bounded path string for working-directory restrictions on permission entries. */
export const workingDirectorySchema = z
  .string()
  .min(1)
  .max(1_024)
  // Control characters are rejected deliberately; they cannot appear in paths.
  // eslint-disable-next-line no-control-regex
  .refine((value) => !/[\u0000-\u001f\u007f]/u.test(value), {
    message: 'Working directories must not contain control characters',
  });

/**
 * One reusable permission binding shared by stored policies, project-file
 * policies, and agent firewall permissions. A deny entry carries no allowlist
 * fields; every other entry names exactly one secret and at least one command.
 */
export const permissionEntrySchema = z
  .object({
    secret: credentialReferenceSchema.optional(),
    commands: z.array(commandNameSchema).min(1).max(MAX_COMMANDS_PER_ENTRY).optional(),
    hashes: z.record(commandNameSchema, sha256HexDigestSchema).optional(),
    env: environmentVariableNameSchema.optional(),
    reveal: z.boolean().optional(),
    ttl: durationSchema.optional(),
    maxUses: positiveMaxUsesSchema.optional(),
    requireConfirmation: confirmationRequirementSchema.optional(),
    /** Restricts use to invocations whose working directory is inside this directory subtree. */
    workingDirectory: workingDirectorySchema.optional(),
    deny: z.boolean().optional(),
  })
  .strict()
  .superRefine((entry, context) => {
    const deny = entry.deny === true;
    if (!deny) {
      if (entry.secret === undefined) {
        context.addIssue({
          code: 'custom',
          message: 'A permission entry requires a secret reference unless it denies',
          path: ['secret'],
        });
      }
      if (entry.commands === undefined) {
        context.addIssue({
          code: 'custom',
          message: 'A permission entry requires at least one allowed command',
          path: ['commands'],
        });
      }
    } else {
      for (const field of [
        'commands',
        'hashes',
        'ttl',
        'maxUses',
        'requireConfirmation',
        'workingDirectory',
      ] as const) {
        if (entry[field] !== undefined) {
          context.addIssue({
            code: 'custom',
            message: 'A deny entry must not carry allowlist fields',
            path: [field],
          });
        }
      }
    }
    if (entry.hashes === undefined || entry.commands === undefined) return;
    const commands = new Set(entry.commands);
    for (const pinned of Object.keys(entry.hashes)) {
      if (!commands.has(pinned)) {
        context.addIssue({
          code: 'custom',
          message: 'Executable pins must reference listed commands',
          path: ['hashes'],
        });
        return;
      }
    }
  });

export type PermissionEntry = z.infer<typeof permissionEntrySchema>;

/**
 * Renames documented snake_case aliases (`require_confirmation`, `max_uses`)
 * on one permission entry. User-authored YAML uses either spelling; persisted
 * state is always written canonically in camelCase.
 */
export function normalizePermissionEntryAliases(value: unknown): unknown {
  if (!isPlainObject(value)) return value;
  let renamed = false;
  const output: Record<string, unknown> = {};
  for (const [key, entryValue] of Object.entries(value)) {
    if (key === 'require_confirmation') {
      output['requireConfirmation'] ??= entryValue;
      renamed = true;
      continue;
    }
    if (key === 'max_uses') {
      output['maxUses'] ??= entryValue;
      renamed = true;
      continue;
    }
    output[key] = entryValue;
  }
  return renamed ? output : value;
}

function isPlainObject(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

/**
 * Applies permission-entry alias normalization across every known container of
 * a project configuration document before strict validation.
 */
export function normalizeProjectConfigAliases(input: unknown): unknown {
  if (!isPlainObject(input)) return input;
  let document: Record<string, unknown> = input;
  let changed = false;

  const policies = normalizedMap(document['policies']);
  if (policies.changed) {
    document = { ...document, policies: policies.map };
    changed = true;
  }

  if (isPlainObject(document['agents'])) {
    const agents: Record<string, unknown> = {};
    let agentsChanged = false;
    for (const [agentId, agent] of Object.entries(document['agents'])) {
      if (!isPlainObject(agent)) {
        agents[agentId] = agent;
        continue;
      }
      const permissions = normalizedMap(agent['permissions']);
      if (permissions.changed) {
        agents[agentId] = { ...agent, ['permissions']: permissions.map };
        agentsChanged = true;
        continue;
      }
      agents[agentId] = agent;
    }
    if (agentsChanged) {
      document = { ...document, agents };
      changed = true;
    }
  }

  if (isPlainObject(document['environments'])) {
    const environments: Record<string, unknown> = {};
    let environmentsChanged = false;
    for (const [environmentId, environment] of Object.entries(
      document['environments'],
    )) {
      if (!isPlainObject(environment)) {
        environments[environmentId] = environment;
        continue;
      }
      const policies = normalizedMap(environment['policies']);
      if (policies.changed) {
        environments[environmentId] = { ...environment, ['policies']: policies.map };
        environmentsChanged = true;
        continue;
      }
      environments[environmentId] = environment;
    }
    if (environmentsChanged) {
      document = { ...document, environments };
      changed = true;
    }
  }

  return changed ? document : input;
}

function normalizedMap(
  mapValue: unknown,
): Readonly<{ changed: boolean; map: unknown }> {
  if (!isPlainObject(mapValue)) return { changed: false, map: mapValue };
  const next: Record<string, unknown> = {};
  let changed = false;
  for (const [key, entry] of Object.entries(mapValue)) {
    const normalized = normalizePermissionEntryAliases(entry);
    if (normalized !== entry) changed = true;
    next[key] = normalized;
  }
  return changed ? { changed: true, map: next } : { changed: false, map: mapValue };
}

export const projectEnvironmentSchema = z
  .object({
    secrets: z
      .record(environmentVariableNameSchema, credentialReferenceSchema)
      .optional(),
    policies: z.record(opaqueIdentifierSchema, permissionEntrySchema).optional(),
  })
  .strict()
  .superRefine((environment, context) => {
    if (
      (environment.secrets === undefined
        ? 0
        : Object.keys(environment.secrets).length) > MAX_SECRETS_PER_ENVIRONMENT
    ) {
      context.addIssue({
        code: 'custom',
        message: 'An environment defines too many secret mappings',
        path: ['secrets'],
      });
    }
    if (
      (environment.policies === undefined
        ? 0
        : Object.keys(environment.policies).length) > MAX_PERMISSIONS_PER_AGENT
    ) {
      context.addIssue({
        code: 'custom',
        message: 'An environment defines too many policies',
        path: ['policies'],
      });
    }
  });

export const projectAgentSchema = z
  .object({
    permissions: z.record(opaqueIdentifierSchema, permissionEntrySchema),
  })
  .strict()
  .superRefine((agent, context) => {
    if (Object.keys(agent.permissions).length < 1) {
      context.addIssue({
        code: 'custom',
        message: 'An agent requires at least one permission entry',
        path: ['permissions'],
      });
    }
    if (Object.keys(agent.permissions).length > MAX_PERMISSIONS_PER_AGENT) {
      context.addIssue({
        code: 'custom',
        message: 'An agent defines too many permission entries',
        path: ['permissions'],
      });
    }
  });

/**
 * Non-secret project file (`kavrix.yaml`). It may contain credential
 * references, permission definitions, and routing only; strict parsing fails
 * closed on unknown keys so plaintext secret values can never be silently
 * accepted into a recognized field.
 */
export const projectConfigDocumentSchema = z
  .object({
    version: z.literal(1),
    project: slugSchema.optional(),
    environments: z.record(environmentNameSchema, projectEnvironmentSchema).optional(),
    policies: z.record(opaqueIdentifierSchema, permissionEntrySchema).optional(),
    agents: z.record(opaqueIdentifierSchema, projectAgentSchema).optional(),
  })
  .strict()
  .superRefine((document, context) => {
    if (
      (document.environments === undefined
        ? 0
        : Object.keys(document.environments).length) > MAX_PROJECT_ENVIRONMENTS
    ) {
      context.addIssue({
        code: 'custom',
        message: 'The project file defines too many environments',
        path: ['environments'],
      });
    }
    if (
      (document.agents === undefined ? 0 : Object.keys(document.agents).length) >
      MAX_PROJECT_AGENTS
    ) {
      context.addIssue({
        code: 'custom',
        message: 'The project file defines too many agents',
        path: ['agents'],
      });
    }
    const policyCount =
      (document.policies === undefined ? 0 : Object.keys(document.policies).length) +
      Object.values(document.environments ?? {}).reduce(
        (total, environment) =>
          total +
          (environment.policies === undefined
            ? 0
            : Object.keys(environment.policies).length),
        0,
      );
    if (policyCount > MAX_PROJECT_POLICIES) {
      context.addIssue({
        code: 'custom',
        message: 'The project file defines too many policies',
        path: ['policies'],
      });
    }
  });

export type ProjectEnvironment = z.infer<typeof projectEnvironmentSchema>;
export type ProjectAgent = z.infer<typeof projectAgentSchema>;
export type ProjectConfigDocument = z.infer<typeof projectConfigDocumentSchema>;

export const grantActorSchema = z.enum(['user', 'agent']);

/** One temporary, consumable authorization for one credential. */
export const grantRecordSchema = z
  .object({
    grantId: grantIdSchema,
    secret: credentialReferenceSchema,
    actor: grantActorSchema,
    commands: z.array(commandNameSchema).min(1).max(MAX_COMMANDS_PER_ENTRY),
    hashes: z.record(commandNameSchema, sha256HexDigestSchema).optional(),
    env: environmentVariableNameSchema.optional(),
    createdByPolicyId: opaqueIdentifierSchema.optional(),
    agentPermissionKey: opaqueIdentifierSchema.optional(),
    createdAt: timestampSchema,
    expiresAt: timestampSchema.optional(),
    maxUses: positiveMaxUsesSchema.optional(),
    usedCount: z.number().int().nonnegative(),
    lastUsedAt: timestampSchema.optional(),
    revokedAt: timestampSchema.optional(),
  })
  .strict()
  .superRefine((grant, context) => {
    if (grant.maxUses !== undefined && grant.usedCount > grant.maxUses) {
      context.addIssue({
        code: 'custom',
        message: 'A grant cannot record more uses than its maximum',
        path: ['usedCount'],
      });
    }
    if (grant.expiresAt !== undefined && grant.expiresAt <= grant.createdAt) {
      context.addIssue({
        code: 'custom',
        message: 'A grant must expire after it was created',
        path: ['expiresAt'],
      });
    }
    if (grant.revokedAt !== undefined && grant.revokedAt < grant.createdAt) {
      context.addIssue({
        code: 'custom',
        message: 'A grant cannot be revoked before it was created',
        path: ['revokedAt'],
      });
    }
    if (grant.hashes === undefined) return;
    const commands = new Set(grant.commands);
    for (const pinned of Object.keys(grant.hashes)) {
      if (!commands.has(pinned)) {
        context.addIssue({
          code: 'custom',
          message: 'Executable pins must reference granted commands',
          path: ['hashes'],
        });
        return;
      }
    }
  });

export type GrantActor = z.infer<typeof grantActorSchema>;
export type GrantRecord = z.infer<typeof grantRecordSchema>;

export const storedPolicyRecordSchema = z
  .object({
    definition: permissionEntrySchema,
    createdAt: timestampSchema,
  })
  .strict();

export type StoredPolicyRecord = z.infer<typeof storedPolicyRecordSchema>;

export const ALLOW_DECISION_REASONS = Object.freeze([
  'no-applicable-policy',
  'policy-allowed',
  'grant-allowed',
] as const);

export const CONFIRM_DECISION_REASONS = Object.freeze([
  'confirmation-required',
] as const);

export const DENY_DECISION_REASONS = Object.freeze([
  'policy-denied',
  'command-not-allowed',
  'hash-mismatch',
  'expired',
  'exhausted',
  'revoked',
  'reveal-forbidden-by-policy',
  'confirmation-declined',
  'confirmation-unavailable',
  'executable-unresolved',
  'executable-refused',
  'clock-invalid',
  'state-corrupt',
  'no-injection-mapping',
  'working-directory-mismatch',
  'invalid-request',
] as const);

export const authorizationReasonSchema = z.enum([
  ...ALLOW_DECISION_REASONS,
  ...CONFIRM_DECISION_REASONS,
  ...DENY_DECISION_REASONS,
]);

export type AuthorizationReason = z.infer<typeof authorizationReasonSchema>;

/** Closed machine-readable outcome of one authorization evaluation. */
export const authorizationDecisionSchema = z.discriminatedUnion('outcome', [
  z
    .object({
      outcome: z.literal('allow'),
      reason: z.enum(ALLOW_DECISION_REASONS),
      policyId: opaqueIdentifierSchema.optional(),
      grantId: opaqueIdentifierSchema.optional(),
      secret: credentialReferenceSchema.optional(),
    })
    .strict(),
  z
    .object({
      outcome: z.literal('confirm'),
      reason: z.enum(CONFIRM_DECISION_REASONS),
      policyId: opaqueIdentifierSchema.optional(),
      secret: credentialReferenceSchema.optional(),
    })
    .strict(),
  z
    .object({
      outcome: z.literal('deny'),
      reason: z.enum(DENY_DECISION_REASONS),
      policyId: opaqueIdentifierSchema.optional(),
      grantId: opaqueIdentifierSchema.optional(),
      secret: credentialReferenceSchema.optional(),
    })
    .strict(),
]);

export type AuthorizationDecision = z.infer<typeof authorizationDecisionSchema>;

export const runtimeAuditActorSchema = z.enum(['user', 'agent']);

export const runtimeAuditActionSchema = z.enum([
  'unlock',
  'policy-created',
  'policy-updated',
  'policy-removed',
  'grant-created',
  'grant-revoked',
  'grant-expired',
  'grant-exhausted',
  'authorization-allowed',
  'authorization-denied',
  'reveal-attempted',
  'reveal-denied',
  'confirmation-requested',
  'confirmation-granted',
  'confirmation-declined',
  'execution-completed',
]);

const sanitizedPreviewTextSchema = z
  .string()
  .min(1)
  .max(MAX_ARGV_PREVIEW_CHARS)
  // Audit previews must never smuggle terminal control sequences.
  // eslint-disable-next-line no-control-regex
  .refine((value) => !/[\u0000-\u001f\u007f]/u.test(value), {
    message: 'Audit preview text must not contain control characters',
  });

/**
 * One security-relevant audit event. Every field is bounded metadata; no
 * schema in this family can carry plaintext credential values.
 */
export const runtimeAuditEventSchema = z
  .object({
    seq: z.number().int().positive(),
    occurredAt: timestampSchema,
    actor: runtimeAuditActorSchema,
    action: runtimeAuditActionSchema,
    policyId: opaqueIdentifierSchema.optional(),
    grantId: opaqueIdentifierSchema.optional(),
    permissionKey: opaqueIdentifierSchema.optional(),
    secret: credentialReferenceSchema.optional(),
    command: commandNameSchema.optional(),
    argvPreview: z
      .array(sanitizedPreviewTextSchema)
      .max(MAX_ARGV_PREVIEW_ENTRIES)
      .optional(),
    exitCode: z.number().int().min(-0x80000000).max(0x7fffffff).optional(),
    reason: authorizationReasonSchema.optional(),
  })
  .strict();

export type RuntimeAuditActor = z.infer<typeof runtimeAuditActorSchema>;
export type RuntimeAuditAction = z.infer<typeof runtimeAuditActionSchema>;
export type RuntimeAuditEvent = z.infer<typeof runtimeAuditEventSchema>;

export const authorizationScopeKindSchema = z.enum(['database', 'vault']);

export type AuthorizationScopeKind = z.infer<typeof authorizationScopeKindSchema>;

export const authorizationStateDomainSchema = z.literal(
  'kavrix/authorization-state/v1',
);

/** Exact authenticated context bound into the sealed state envelope. */
export const authorizationEnvelopeContextSchema = z
  .object({
    domain: authorizationStateDomainSchema,
    scopeKind: authorizationScopeKindSchema,
    scopeId: opaqueIdentifierSchema,
    sequence: z.number().int().nonnegative(),
  })
  .strict();

export type AuthorizationEnvelopeContext = z.infer<
  typeof authorizationEnvelopeContextSchema
>;

/** Plaintext inner document protected by the sealed envelope. */
export const authorizationStateDocumentSchema = z
  .object({
    version: z.literal(1),
    policies: z.record(opaqueIdentifierSchema, storedPolicyRecordSchema),
    grants: z.record(grantIdSchema, grantRecordSchema),
    audit: z.array(runtimeAuditEventSchema).max(MAX_RUNTIME_AUDIT_EVENTS),
  })
  .strict()
  .superRefine((state, context) => {
    if (Object.keys(state.policies).length > MAX_STORED_POLICIES) {
      context.addIssue({
        code: 'custom',
        message: 'The authorization state holds too many policies',
        path: ['policies'],
      });
    }
    if (Object.keys(state.grants).length > MAX_STORED_GRANTS) {
      context.addIssue({
        code: 'custom',
        message: 'The authorization state holds too many grants',
        path: ['grants'],
      });
    }
  });

export type AuthorizationStateDocument = z.infer<
  typeof authorizationStateDocumentSchema
>;

export const authorizationStateFormatSchema = z.literal('kavrix-authorization-state');

/**
 * Sealed outer wire document persisted beside a key file. The nonce,
 * ciphertext, and tag authenticate the exact scope identity and monotonic
 * sequence through the envelope context; any byte change fails decryption.
 */
export const authorizationStateEnvelopeSchema = z
  .object({
    format: authorizationStateFormatSchema,
    version: z.literal(1),
    scopeKind: authorizationScopeKindSchema,
    scopeId: opaqueIdentifierSchema,
    sequence: z.number().int().nonnegative(),
    createdAt: timestampSchema,
    updatedAt: timestampSchema,
    nonce: base64UrlSchema.length(AEAD_NONCE_BASE64URL_CHARS),
    ciphertext: base64UrlSchema,
    authenticationTag: base64UrlSchema.length(AEAD_AUTHENTICATION_TAG_BASE64URL_CHARS),
  })
  .strict();

export type AuthorizationStateEnvelope = z.infer<
  typeof authorizationStateEnvelopeSchema
>;

// ---- Agent firewall broker wire protocol -----------------------------------

const BASE64_CHUNK_PATTERN =
  /^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/u;

export const MAX_BROKER_ARGV_ENTRIES = 128;
export const MAX_BROKER_ARG_CHARS = 8_192;
export const MAX_BROKER_FRAME_BYTES = 2 * 1024 * 1024;

/** One client request to execute an authorized operation through the broker. */
export const agentBrokerRequestSchema = z
  .object({
    v: z.literal(1),
    token: z.string().min(32).max(256),
    op: z.literal('exec'),
    permission: opaqueIdentifierSchema,
    argv: z
      .array(z.string().min(1).max(MAX_BROKER_ARG_CHARS))
      .min(1)
      .max(MAX_BROKER_ARGV_ENTRIES),
  })
  .strict();

export type AgentBrokerRequest = z.infer<typeof agentBrokerRequestSchema>;

/** Frames streamed from broker to client. */
export const agentBrokerDecisionFrameSchema = z
  .object({
    v: z.literal(1),
    event: z.literal('decision'),
    outcome: z.enum(['allow', 'deny']),
    reason: authorizationReasonSchema,
  })
  .strict();

export const agentBrokerOutputFrameSchema = z
  .object({
    v: z.literal(1),
    event: z.enum(['stdout', 'stderr']),
    data: z.string().regex(BASE64_CHUNK_PATTERN, 'Frames carry standard base64'),
  })
  .strict();

export const agentBrokerExitFrameSchema = z
  .object({
    v: z.literal(1),
    event: z.literal('exit'),
    exitCode: z.number().int().min(-0x80000000).max(0x7fffffff).nullable(),
    signal: z.string().min(1).max(32).nullable(),
  })
  .strict();

export const agentBrokerServerFrameSchema = z.discriminatedUnion('event', [
  agentBrokerDecisionFrameSchema,
  agentBrokerOutputFrameSchema,
  agentBrokerExitFrameSchema,
]);

export type AgentBrokerServerFrame = z.infer<typeof agentBrokerServerFrameSchema>;

/** Frames streamed from client to broker while the authorized child runs. */
export const agentBrokerClientFrameSchema = z.discriminatedUnion('event', [
  z
    .object({
      v: z.literal(1),
      event: z.literal('stdin'),
      data: z.string().regex(BASE64_CHUNK_PATTERN),
    })
    .strict(),
  z.object({ v: z.literal(1), event: z.literal('close-stdin') }).strict(),
]);

export type AgentBrokerClientFrame = z.infer<typeof agentBrokerClientFrameSchema>;
