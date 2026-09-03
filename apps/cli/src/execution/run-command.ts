import type { ChildProcess } from 'node:child_process';

import { zeroize } from '@kavrix/crypto';
import {
  authorizationReasonSchema,
  type ProjectConfigDocument,
  environmentVariableNameSchema,
  secretValueSchema,
  type AuthorizationReason,
  type GrantRecord,
  type PermissionEntry,
} from '@kavrix/schemas';
import { RunnerError, runSecureCommand, type EnvironmentMapping } from '@kavrix/runner';

import {
  closeDatabaseFlatVault,
  openDatabaseFlatVault,
  readDatabaseFlatSecrets,
  usesDatabaseContainer,
} from '../database-flat-commands.js';
import { AuthorizationState, nowIso } from './authorization-state.js';
import { requestApproval } from './confirm.js';
import {
  CodedCliError,
  authorizationDenied,
  confirmationRequired,
  grantInvalid,
  invalidConfiguration,
} from './exit-codes.js';
import { resolveExecutable } from './executable.js';
import {
  canonicalizeDirectory,
  evaluateGrantUse,
  evaluatePermission,
  executionWindowMs,
  type EvaluationContext,
} from './engine.js';
import {
  environmentMappings,
  loadProjectConfig,
  projectPolicies,
} from './project-config.js';
import {
  auditArgvPreview,
  mergeMappings,
  parseSecretMappings,
  type ResolvedMapping,
  type RunCliOptions,
} from './run-options.js';
import { effectiveExitCode, forwardableSignals } from './signals.js';

export interface RunOutcome {
  readonly ran: boolean;
  readonly decision: Readonly<{
    outcome: 'allow' | 'deny' | 'declined' | 'unavailable';
    reason: string;
    policyId?: string;
    grantId?: string;
  }>;
  readonly executable: Readonly<{
    request: string;
    displayName?: string;
    path?: string;
  }>;
  readonly exitCode: number | null;
  readonly signal: NodeJS.Signals | null;
  readonly termination: string;
  readonly stdout?: string;
  readonly stderr?: string;
  readonly outputTruncated?: boolean;
}

const INHERITED_ENVIRONMENT_NAMES = [
  'PATH',
  'PATHEXT',
  'SystemRoot',
  'WINDIR',
  'COMSPEC',
  'TEMP',
  'TMP',
  'HOME',
  'USERPROFILE',
] as const;

const JSON_CAPTURE_MAX_BYTES = 64 * 1024;

class MissingCredentialError extends Error {
  public readonly credentialName: string;

  public constructor(name: string) {
    super(`Credential '${name}' was not found.`);
    this.credentialName = name;
  }
}

interface UnlockedScope {
  readonly values: ReadonlyMap<string, string>;
  readonly authzKey: Uint8Array;
  readonly keyFile: string;
  readonly scopeId: string;
}

interface ResolvedGrantRef {
  readonly ref: string;
  readonly grant: GrantRecord;
}

/**
 * Executes one child process whose environment carries only explicitly
 * requested credentials. Grants are resolved and every referenced credential
 * is verified before anything is consumed; grant uses are reserved under the
 * sealed-state lock immediately before spawn; decrypted values exist in memory
 * only for the lifetime of the request and are wiped (best effort) afterwards.
 */
export async function executeRun(options: RunCliOptions): Promise<RunOutcome> {
  const targetArguments = options.executableAndArgs;
  if (targetArguments.length === 0 || (targetArguments[0] ?? '').length === 0) {
    throw invalidConfiguration('A command is required after `--`.');
  }
  const targetRequest = targetArguments[0] ?? '';
  const targetRest = targetArguments.slice(1);

  if (!(await usesDatabaseContainer(options))) {
    const { databaseProfileBindingState } =
      await import('../database-flat-commands.js');
    const state = await databaseProfileBindingState(options);
    if (state === 'unbound') {
      throw invalidConfiguration(
        'The selected datastore profile is not bound to a database; run `kavrix db init` for that profile before `kavrix run`.',
      );
    }
    throw invalidConfiguration(
      'kavrix run requires a database profile; create one with `kavrix db profile add`.',
    );
  }

  const explicitMappings = parseSecretMappings(options.secretMappings ?? []);
  const configDocument =
    options.noConfig === true ? null : await loadOptionalProjectConfig(options.config);
  const configuredMappings: readonly ResolvedMapping[] =
    configDocument !== null && options.environmentName !== undefined
      ? environmentMappings(configDocument, options.environmentName).map(
          ([destination, secret]) => ({ destination, secret }),
        )
      : [];
  const mappings = mergeMappings(configuredMappings, explicitMappings);

  const policyNames = options.policyIds ?? [];
  const grantRefs = options.grantRefs ?? [];

  const flatSecrets = await readDatabaseFlatSecrets(options, []);
  const handle = await openDatabaseFlatVault(options, flatSecrets);
  let unlocked: UnlockedScope;
  let resolvedGrants: readonly ResolvedGrantRef[];
  try {
    // Resolve grant references against the sealed state first so the exact
    // credential set is known before any vault inspection or consumption.
    const authzKey = handle.session.authorizationStateKey();
    const state = await AuthorizationState.open(handle.profile.keyFile, authzKey, {
      scopeKind: 'database',
      scopeId: handle.session.databaseId,
    });
    try {
      const snapshot = await state.read();
      resolvedGrants = grantRefs.map((ref) => {
        const located = locateGrant(snapshot.grants, ref);
        if (located === undefined) {
          throw grantInvalid(`No active grant matches '${ref}'.`);
        }
        return { ref, grant: located };
      });
      const neededNames = new Set<string>([
        ...mappings.map((mapping) => mapping.secret),
        ...resolvedGrants.map((resolved) => resolved.grant.secret),
      ]);
      const values = new Map<string, string>();
      let missingName: string | undefined;
      await handle.session.inspectVault(handle.vaultId, (payload) => {
        const missing: string[] = [];
        for (const name of neededNames) {
          const record = payload.records[name];
          if (record === undefined) missing.push(name);
          else values.set(name, record.value);
        }
        missingName = missing[0];
      });
      // Session callbacks must not throw: failures are surfaced after inspection
      // so the session can close cleanly and map codes without translation.
      if (missingName !== undefined) throw new MissingCredentialError(missingName);
      unlocked = {
        values,
        authzKey,
        keyFile: handle.profile.keyFile,
        scopeId: handle.session.databaseId,
      };
    } catch (error) {
      if (error instanceof MissingCredentialError) {
        throw new CodedCliError('CREDENTIAL_MISSING', error.message);
      }
      throw error;
    } finally {
      // Zeroes this probe's key copy; the caller reopens the state with the
      // original bytes for the authorize-and-spawn phase.
      state.close();
    }
  } catch (error) {
    if (error instanceof MissingCredentialError) {
      throw new CodedCliError('CREDENTIAL_MISSING', error.message);
    }
    throw error;
  } finally {
    await closeDatabaseFlatVault(handle);
  }

  const state = await openStateSafely(unlocked);
  try {
    return await authorizeAndSpawn(
      options,
      { request: targetRequest, args: targetRest },
      mappings,
      policyNames,
      resolvedGrants,
      unlocked.values,
      configDocument,
      state,
    );
  } finally {
    state.close();
  }
}

async function openStateSafely(unlocked: UnlockedScope): Promise<AuthorizationState> {
  try {
    return await AuthorizationState.open(unlocked.keyFile, unlocked.authzKey, {
      scopeKind: 'database',
      scopeId: unlocked.scopeId,
    });
  } catch (error) {
    zeroize(unlocked.authzKey);
    throw error;
  }
}

async function loadOptionalProjectConfig(
  explicitPath: string | undefined,
): Promise<ProjectConfigDocumentLike | null> {
  if (explicitPath !== undefined)
    return (await loadProjectConfig(explicitPath)).document;
  for (const candidate of DEFAULT_CONFIG_CANDIDATES) {
    try {
      return (await loadProjectConfig(candidate)).document;
    } catch (error) {
      if (isMissingConfig(error)) continue;
      throw error;
    }
  }
  return null;
}

function isMissingConfig(error: unknown): boolean {
  return error instanceof Error && error.message.includes('could not be read');
}

const DEFAULT_CONFIG_CANDIDATES = ['kavrix.yaml', 'kavrix.yml', 'kavrix.json'] as const;

interface RunTarget {
  readonly request: string;
  readonly args: readonly string[];
}

type ProjectConfigDocumentLike = ProjectConfigDocument;

async function authorizeAndSpawn(
  options: RunCliOptions,
  target: RunTarget,
  mappings: readonly ResolvedMapping[],
  policyNames: readonly string[],
  resolvedGrants: readonly ResolvedGrantRef[],
  values: ReadonlyMap<string, string>,
  configDocument: ProjectConfigDocumentLike | null,
  state: AuthorizationState,
): Promise<RunOutcome> {
  const platform = process.platform;
  const jsonMode = options.json === true;
  const argvPreview = auditArgvPreview(target.args);

  const resolution = await resolveExecutable(target.request);
  if (resolution.status === 'unresolved') {
    return await denyExecution(
      state,
      'user',
      'executable-unresolved',
      undefined,
      authorizationDenied(`'${target.request}' could not be resolved on PATH.`),
    );
  }
  if (resolution.status === 'refused') {
    return await denyExecution(
      state,
      'user',
      'executable-refused',
      undefined,
      authorizationDenied(
        `'${target.request}' is a Windows command script; Kavrix refuses .bat/.cmd/.com targets because launching them requires shell argument re-parsing. Invoke the underlying executable directly.`,
      ),
    );
  }

  const context: EvaluationContext = {
    platform,
    facts: {
      displayName: resolution.displayName,
      sha256: resolution.sha256,
      firstArgument: target.args[0],
    },
    nowIso: nowIso(),
    cwdRealPath: canonicalizeDirectory(process.cwd()),
  };

  const snapshot = await state.read();

  const selectedPolicies = policyNames.map((policyId) => {
    const entry = findPolicy(snapshot, configDocument, policyId);
    if (entry === undefined) {
      throw invalidConfiguration(`Policy '${policyId}' is not defined.`);
    }
    return { policyId, entry };
  });

  // Stored deny entries block every use of their credential, attached or not.
  // A selected policy's credential is involved even when the policy is being
  // used as a process-only gate with no explicit environment mapping. This
  // keeps real execution aligned with metadata-only policy simulation.
  const involvedSecrets = new Set<string>([
    ...mappings.map((mapping) => mapping.secret),
    ...resolvedGrants.map((resolved) => resolved.grant.secret),
    ...selectedPolicies.flatMap(({ entry }) =>
      entry.secret === undefined ? [] : [entry.secret],
    ),
  ]);
  for (const [storedId, record] of Object.entries(snapshot.policies)) {
    const entry = record.definition;
    if (
      entry.deny === true &&
      entry.secret !== undefined &&
      involvedSecrets.has(entry.secret)
    ) {
      return await denyExecution(
        state,
        'user',
        'policy-denied',
        storedId,
        authorizationDenied(
          `Credential '${entry.secret}' is denied by policy '${storedId}'.`,
        ),
        entry.secret,
      );
    }
  }

  let ttlCapMs: number | undefined;
  const confirmations: { policyId: string; entry: PermissionEntry }[] = [];
  for (const { policyId, entry } of selectedPolicies) {
    const decision = evaluatePermission(entry, context);
    if (decision.outcome === 'deny') {
      return await denyExecution(
        state,
        'user',
        decision.reason,
        policyId,
        authorizationDenied(denyMessage(decision.reason, policyId)),
        entry.secret,
      );
    }
    if (decision.outcome === 'confirm') {
      confirmations.push({ policyId, entry });
    }
    const window = executionWindowMs(entry);
    if (window === 'invalid') {
      throw invalidConfiguration(
        `Policy '${policyId}' declares a TTL above the supported maximum.`,
      );
    }
    if (window !== undefined) {
      ttlCapMs = ttlCapMs === undefined ? window : Math.min(ttlCapMs, window);
    }
  }

  // When the caller opts into policy-gated execution, every explicitly mapped
  // credential must be covered by at least one selected policy. Otherwise a
  // policy for a less-sensitive credential could be presented while injecting
  // a different credential into the authorized process.
  if (selectedPolicies.length > 0) {
    const coveredSecrets = new Set(
      selectedPolicies.flatMap(({ entry }) =>
        entry.secret === undefined ? [] : [entry.secret],
      ),
    );
    const uncovered = mappings.find((mapping) => !coveredSecrets.has(mapping.secret));
    if (uncovered !== undefined) {
      return await denyExecution(
        state,
        'user',
        'invalid-request',
        selectedPolicies[0]?.policyId,
        authorizationDenied(
          `Credential '${uncovered.secret}' is not covered by a selected policy.`,
        ),
        uncovered.secret,
      );
    }
  }

  for (const resolved of resolvedGrants) {
    const evaluation = evaluateGrantUse(resolved.grant, context);
    if (evaluation.status === 'denied') {
      const coded =
        evaluation.reason === 'command-not-allowed' ||
        evaluation.reason === 'hash-mismatch'
          ? authorizationDenied(grantDenyMessage(evaluation.reason))
          : grantInvalid(grantDenyMessage(evaluation.reason));
      return await denyExecution(
        state,
        'user',
        evaluation.reason,
        undefined,
        coded,
        resolved.grant.secret,
      );
    }
  }

  for (const confirmation of confirmations) {
    const approval = await requestApproval({
      actor: 'user',
      ...(confirmation.entry.secret === undefined
        ? {}
        : { secret: confirmation.entry.secret }),
      executable: resolution.displayName,
      argumentsPreview: argvPreview ?? [],
    });
    await state.recordEvent({
      actor: 'user',
      action:
        approval === 'granted'
          ? 'confirmation-granted'
          : approval === 'declined'
            ? 'confirmation-declined'
            : 'confirmation-requested',
      policyId: confirmation.policyId,
      ...(confirmation.entry.secret === undefined
        ? {}
        : { secret: confirmation.entry.secret }),
      command: resolution.displayName,
      ...(argvPreview === undefined ? {} : { argvPreview: [...argvPreview] }),
    });
    if (approval !== 'granted') {
      throw confirmationRequired(
        approval === 'declined'
          ? 'Operation declined by the operator.'
          : 'Interactive confirmation is required but no terminal is available.',
      );
    }
  }

  // Injection planning is pure validation: it runs before any grant use is
  // consumed so a missing credential or invalid destination can never burn a
  // use. Grants without an explicit environment variable inject under a name
  // derived from the credential reference, matching `run --grant <secret>`.
  const injections = buildInjections(
    mappings,
    resolvedGrants.map((r) => r.grant),
    values,
  );

  for (const resolved of resolvedGrants) {
    await state.consumeGrantUse(resolved.grant.grantId, {
      executable: resolution.displayName,
      argvPreview,
    });
  }

  // Policy-gated runs record their allowance explicitly (grant consumption
  // already audits itself), so every credential use is traceable.
  if (policyNames.length > 0) {
    const primaryPolicy = policyNames[0] ?? '';
    const gatedEntry = findPolicy(snapshot, configDocument, primaryPolicy);
    await state.recordEvent({
      actor: 'user',
      action: 'authorization-allowed',
      ...(primaryPolicy.length > 0 ? { policyId: primaryPolicy } : {}),
      ...(gatedEntry?.secret === undefined ? {} : { secret: gatedEntry.secret }),
      command: resolution.displayName,
      ...(argvPreview === undefined ? {} : { argvPreview: [...argvPreview] }),
    });
  }

  const childRef: { current: ChildProcess | null } = { current: null };
  const forwardSignals = forwardableSignals(platform);
  const handlers = new Map<NodeJS.Signals, () => void>();
  for (const signalName of forwardSignals) {
    const handler = (): void => {
      childRef.current?.kill(signalName);
    };
    handlers.set(signalName, handler);
    process.on(signalName, handler);
  }

  let result;
  try {
    result = await runSecureCommand({
      executable: resolution.absolutePath,
      arguments: [...target.args],
      cwd: process.cwd(),
      environment: injections,
      inheritEnvironment: [...INHERITED_ENVIRONMENT_NAMES],
      input: jsonMode ? 'ignore' : 'inherit',
      output: jsonMode
        ? { mode: 'capture', maxBytes: JSON_CAPTURE_MAX_BYTES }
        : { mode: 'inherit' },
      ...(ttlCapMs === undefined ? {} : { timeoutMs: ttlCapMs }),
      onSpawn(child) {
        childRef.current = child;
      },
    });
  } catch (error) {
    if (error instanceof RunnerError && error.code === 'RUNNER_ENVIRONMENT_REJECTED') {
      throw invalidConfiguration(
        'A destination variable conflicts with a protected runtime variable.',
      );
    }
    throw authorizationDenied('The authorized executable could not be started.');
  } finally {
    for (const [signalName, handler] of handlers) {
      process.off(signalName, handler);
    }
  }

  const exitCode = effectiveExitCode(result);

  try {
    await state.recordEvent({
      actor: 'user',
      action: 'execution-completed',
      command: resolution.displayName,
      ...(argvPreview === undefined ? {} : { argvPreview: [...argvPreview] }),
      exitCode,
      ...(resolvedGrants[0] === undefined
        ? {}
        : { grantId: resolvedGrants[0].grant.grantId }),
    });
  } catch (error) {
    process.stderr.write(
      `kavrix: warning: the execution completed but the audit event failed: ${describeError(error)}\n`,
    );
  }

  const primaryPolicy = policyNames[0];
  const primaryGrant = resolvedGrants[0]?.grant.grantId;
  return {
    ran: true,
    decision: {
      outcome: 'allow',
      reason:
        primaryGrant !== undefined
          ? 'grant-allowed'
          : primaryPolicy !== undefined
            ? 'policy-allowed'
            : 'no-applicable-policy',
      ...(primaryPolicy === undefined ? {} : { policyId: primaryPolicy }),
      ...(primaryGrant === undefined ? {} : { grantId: primaryGrant }),
    },
    executable: {
      request: target.request,
      displayName: resolution.displayName,
      path: resolution.absolutePath,
    },
    exitCode,
    signal: result.signal,
    termination: result.termination,
    ...(jsonMode
      ? {
          stdout: decodeSanitized(result.stdout),
          stderr: decodeSanitized(result.stderr),
          outputTruncated: result.outputTruncated,
        }
      : {}),
  };
}

async function denyExecution(
  state: AuthorizationState,
  actor: 'user' | 'agent',
  reason: string,
  policyId: string | undefined,
  error: CodedCliError,
  secret?: string,
): Promise<never> {
  try {
    await state.recordEvent({
      actor,
      action: 'authorization-denied',
      ...(policyId === undefined ? {} : { policyId }),
      ...(secret === undefined ? {} : { secret }),
      reason: asAuditReason(reason),
    });
  } catch (auditError) {
    process.stderr.write(
      `kavrix: warning: denial audit event failed: ${describeError(auditError)}\n`,
    );
  }
  throw error;
}

function findPolicy(
  snapshot: { policies: Readonly<Record<string, { definition: PermissionEntry }>> },
  configDocument: ProjectConfigDocumentLike | null,
  policyId: string,
): PermissionEntry | undefined {
  const stored = snapshot.policies[policyId];
  if (stored !== undefined) return stored.definition;
  if (configDocument !== null) {
    return projectPolicies(configDocument).get(policyId);
  }
  return undefined;
}

function locateGrant(
  grants: Readonly<Record<string, GrantRecord>>,
  reference: string,
): GrantRecord | undefined {
  // An explicit grant id resolves even when revoked or exhausted so the
  // evaluator can report the precise denial reason.
  const direct = grants[reference];
  if (direct !== undefined) return direct;
  const matches = Object.values(grants).filter(
    (candidate) => candidate.secret === reference && candidate.revokedAt === undefined,
  );
  if (matches.length > 1) {
    throw grantInvalid(`Multiple active grants match '${reference}'; use a grant id.`);
  }
  return matches[0];
}

type Injection = EnvironmentMapping;

/**
 * Derives the destination variable used when a grant declares no explicit
 * environment variable: non-alphanumeric runs collapse to underscores and the
 * result is uppercased, so `production/database` injects as
 * `PRODUCTION_DATABASE`. Returns undefined when no portable name can be
 * derived; callers must then fail closed and ask for an explicit mapping.
 */
export function deriveInjectionName(secret: string): string | undefined {
  const derived = secret
    .replace(/[^A-Za-z0-9]+/gu, '_')
    .replace(/^([0-9])/u, '_$1')
    .toUpperCase();
  return environmentVariableNameSchema.safeParse(derived).success ? derived : undefined;
}

function buildInjections(
  mappings: readonly ResolvedMapping[],
  grants: readonly GrantRecord[],
  values: ReadonlyMap<string, string>,
): readonly Injection[] {
  const planned = new Map<string, string>();
  for (const mapping of mappings) planned.set(mapping.destination, mapping.secret);
  for (const grant of grants) {
    if (grant.env !== undefined && grant.env.length > 0) {
      addPlannedInjection(planned, grant.env, grant.secret);
      continue;
    }
    // The documented bare form (`run --grant <secret>`) must inject the
    // credential; resolve its destination up front or fail closed before any
    // use is consumed.
    const destination = deriveInjectionName(grant.secret);
    if (destination === undefined) {
      throw invalidConfiguration(
        `Credential '${grant.secret}' cannot be mapped to an environment variable automatically; issue the grant with --env or pass --secret VARIABLE='${grant.secret}'.`,
      );
    }
    addPlannedInjection(planned, destination, grant.secret);
  }
  const injections: Injection[] = [];
  for (const [destination, secret] of planned) {
    const value = values.get(secret);
    if (value === undefined) {
      throw new CodedCliError(
        'CREDENTIAL_MISSING',
        `Credential '${secret}' was not found.`,
      );
    }
    injections.push([
      destination,
      { kind: 'secret', value: secretValueSchema.parse(value) },
    ]);
  }
  return injections;
}

export function addPlannedInjection(
  planned: Map<string, string>,
  destination: string,
  secret: string,
): void {
  if (!environmentVariableNameSchema.safeParse(destination).success) {
    throw invalidConfiguration(`Destination variable '${destination}' is invalid.`);
  }
  const existing = planned.get(destination);
  if (existing !== undefined && existing !== secret) {
    throw invalidConfiguration(
      `Destination variable '${destination}' maps to conflicting credentials.`,
    );
  }
  planned.set(destination, secret);
}

function decodeSanitized(buffer: Buffer | undefined): string {
  if (buffer === undefined) return '';
  // Strip terminal control sequences from captured child output.
  const sanitized = buffer
    .toString('utf8')
    // eslint-disable-next-line no-control-regex
    .replace(/[\u0000-\u0008\u000b\u000c\u000e-\u001f\u007f]/gu, '?');
  return sanitized;
}

export function denyMessage(reason: string, policyId: string): string {
  switch (reason) {
    case 'command-not-allowed':
      return `Policy '${policyId}' does not allow this executable.`;
    case 'hash-mismatch':
      return `The executable hash does not match the pin recorded by policy '${policyId}'.`;
    default:
      return `Denied by policy '${policyId}' (${reason}).`;
  }
}

export function grantDenyMessage(reason: string): string {
  switch (reason) {
    case 'expired':
      return 'The temporary grant has expired.';
    case 'exhausted':
      return 'The temporary grant has no remaining uses.';
    case 'revoked':
      return 'The temporary grant has been revoked.';
    case 'clock-invalid':
      return 'The system clock appears to be set before this grant was issued.';
    case 'command-not-allowed':
      return 'The temporary grant does not allow this executable.';
    case 'hash-mismatch':
      return 'The executable hash does not match the grant pin.';
    default:
      return `Denied (${reason}).`;
  }
}

export function asAuditReason(reason: string): AuthorizationReason | undefined {
  return (authorizationReasonSchema.options as readonly string[]).includes(reason)
    ? (reason as AuthorizationReason)
    : undefined;
}

export function describeError(error: unknown): string {
  return error instanceof Error ? error.message : String(error);
}
