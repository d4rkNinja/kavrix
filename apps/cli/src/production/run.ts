import {
  VaultFieldAccessService,
  VaultReadSession,
  type ResolvedCredentialField,
  type VaultReadSourcePort,
} from '@kavrix/client';
import type { VaultRootKey } from '@kavrix/crypto';
import {
  RUNNER_LIMITS,
  runSecureCommand,
  type EnvironmentMapping,
} from '@kavrix/runner';
import {
  secretValueSchema,
  type FieldScalarValue,
  type VaultId,
} from '@kavrix/schemas';

import type { CliRunResult } from '../contracts.js';
import { CliUsageError } from '../errors.js';
import type { CliRunRequest } from '../mutation-contracts.js';

export type ProductionRunOptions = Readonly<{
  source: VaultReadSourcePort;
  vaultId: VaultId;
  rootKey: VaultRootKey;
  cwd: string;
  signal?: AbortSignal;
}>;

/**
 * Composes the unlocked read session, the shared field release rules, and the
 * shell-free executor.
 *
 * Released values reach the child only through its prepared environment. The
 * executable and argument list are taken verbatim from the parsed request and
 * are never derived from a field value, so a mapped secret cannot reach argv;
 * the executor refuses the whole request if one is present anyway.
 */
export async function executeProductionRun(
  options: ProductionRunOptions,
  request: CliRunRequest,
): Promise<CliRunResult> {
  const readSession = new VaultReadSession(options.source, options.vaultId);
  await readSession.unlock(options.rootKey);
  const environment: EnvironmentMapping[] = [];
  const secretNames: string[] = [];
  try {
    const access = new VaultFieldAccessService(readSession);
    // Sequential on purpose: the first refused mapping stops the run before any
    // further field is decrypted.
    for (const mapping of request.environment) {
      const resolved = await access.resolve({
        groupQuery: mapping.groupQuery,
        credentialQuery: mapping.credentialQuery,
        fieldQuery: mapping.fieldQuery,
        ...(mapping.index === undefined ? {} : { index: mapping.index }),
      });
      if (resolved.secret) secretNames.push(mapping.name);
      environment.push([mapping.name, environmentScalar(resolved)]);
    }

    const result = await runSecureCommand({
      executable: request.executable,
      arguments: request.arguments,
      cwd: options.cwd,
      environment,
      inheritEnvironment: request.inherit,
      output: {
        mode: 'capture',
        maxBytes: request.maxOutputBytes ?? RUNNER_LIMITS.defaultCaptureBytes,
      },
      ...(request.timeoutMs === undefined ? {} : { timeoutMs: request.timeoutMs }),
      ...(options.signal === undefined ? {} : { signal: options.signal }),
    });

    return {
      executable: request.executable,
      exitCode: result.exitCode,
      signal: result.signal,
      termination: result.termination,
      outputTruncated: result.outputTruncated,
      environmentNames: request.environment.map((mapping) => mapping.name),
      secretNames,
      stdout: decodeAndClear(result.stdout),
      stderr: decodeAndClear(result.stderr),
    };
  } finally {
    // Drops this composer's references to released plaintext. The executor owns
    // the copies it hands to the child and clears them itself.
    environment.length = 0;
    readSession.lock();
  }
}

/**
 * Presents one released value to the runner. A field the vault classifies as
 * secret is presented as a secret scalar even when its stored kind is not, so
 * the executor's output redaction covers exactly what the vault protects. The
 * child receives the same bytes either way, because the runner renders a text
 * and a secret scalar identically.
 */
function environmentScalar(field: ResolvedCredentialField): FieldScalarValue {
  if (!field.secret) return field.value;
  const secret = secretValueSchema.safeParse(scalarText(field.value));
  if (!secret.success) {
    throw new CliUsageError('The selected field value is too large to inject.');
  }
  return { kind: 'secret', value: secret.data };
}

/**
 * Mirrors how the runner renders a scalar into an environment value, so the
 * reclassification above cannot change the bytes the child observes.
 */
function scalarText(value: FieldScalarValue): string {
  switch (value.kind) {
    case 'text':
    case 'secret':
      return value.value;
    case 'number':
      return String(value.value);
    case 'boolean':
      return value.value ? 'true' : 'false';
    case 'environment-entry':
      return value.value.value;
    case 'attachment-reference':
    case 'item-reference':
      // Unreachable: the release rules refuse reference kinds before this point.
      throw new CliUsageError('The selected field cannot be injected.');
  }
}

/**
 * Decodes one already-redacted capture and clears its buffer. The decoded string
 * cannot be zeroized, so the buffer is cleared to avoid keeping a second copy of
 * child output alive after the command returns.
 */
function decodeAndClear(capture: Buffer | undefined): string {
  if (capture === undefined) return '';
  const text = capture.toString('utf8');
  capture.fill(0);
  return text;
}
