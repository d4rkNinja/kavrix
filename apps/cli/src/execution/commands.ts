/**
 * Action-time implementation barrel for the credential-execution commands.
 *
 * `execution/register.ts` builds commander shapes synchronously on every
 * invocation and must stay light, so its `.action` callbacks and the
 * `requireExecutablePassThrough` pre-action hook dynamically import this
 * module. Everything heavy that the registration module used to consume at
 * action time lives here: the execute* implementations (which transitively
 * pull @kavrix/schemas, crypto, storage, the database session, the runner,
 * and YAML project configuration), the shared guard plumbing, the JSON/human
 * output helpers, and the verbatim `reportJsonFailure` implementation that
 * the top-level CLI error handler imports. Nothing in this module may be
 * imported statically by the registration module.
 */

import type { Command } from 'commander';

import { executeAgentExec, executeAgentRun } from './agent-command.js';
import { executeAudit } from './audit-command.js';
import { executionFlatOptions, extractMergedOptions } from './cli-options.js';
import { DatabaseSessionError } from '../database-session.js';
import {
  CLI_EXIT_CODES,
  CodedCliError,
  cliErrorCodeForSessionFailure,
  invalidConfiguration,
  markJsonReported,
  toErrorEnvelope,
  wasJsonReported,
} from './exit-codes.js';
import { isCodedCliError } from './coded-error.js';
import {
  executeGrantCreate,
  executeGrantList,
  executeGrantRevoke,
  executeGrantShow,
  executePolicyCheck,
  executePolicyCreate,
  executePolicyDiff,
  executePolicyExplain,
  executePolicyLint,
  executePolicyList,
  executePolicySnapshot,
  executePolicyRemove,
  executePolicyShow,
  executePolicySuggest,
} from './policy-command.js';
import { executeRun } from './run-command.js';

// Explicit re-export surface: the heavy command implementations behind the
// registration module's action callbacks, kept in one reviewable list.
export {
  executeAgentExec,
  executeAgentRun,
  executeAudit,
  executeGrantCreate,
  executeGrantList,
  executeGrantRevoke,
  executeGrantShow,
  executePolicyCheck,
  executePolicyCreate,
  executePolicyDiff,
  executePolicyExplain,
  executePolicyLint,
  executePolicyList,
  executePolicyRemove,
  executePolicyShow,
  executePolicySuggest,
  executeRun,
};

// ---- run -------------------------------------------------------------------

export async function executeRunAction(args: readonly unknown[]): Promise<void> {
  const command = args.at(-1) as Command;
  const merged = extractMergedOptions(command);
  let outcome: { readonly exitCode: number | null } | undefined;
  await guard(merged['json'] === true, async () => {
    // `allowUnknownOption` can leave `--no-config` / `--environment` in
    // leftovers instead of option values; recover them fail-closed.
    const recovered = recoverSwallowedRunOptions(command.args);
    const environmentName =
      optString(merged['environment']) ?? recovered.environmentName;
    if (recovered.environmentRequested && environmentName === undefined) {
      throw invalidConfiguration(
        '--environment requires a project file and cannot be combined with --no-config.',
      );
    }
    const executed = await executeRun({
      ...executionFlatOptions(merged),
      secretMappings: asStrings(merged['secret']),
      ...(environmentName === undefined ? {} : { environmentName }),
      ...(optString(merged['config']) === undefined
        ? {}
        : { config: optString(merged['config']) }),
      // Commander treats `--no-config` as the negation of `--config <path>`,
      // so the parse result is `{ config: false }` rather than `{ noConfig: true }`.
      noConfig:
        merged['noConfig'] === true || merged['config'] === false || recovered.noConfig,
      policyIds: asStrings(merged['policy']),
      grantRefs: asStrings(merged['grant']),
      json: merged['json'] === true,
      executableAndArgs: recovered.executableAndArgs,
    });
    outcome = executed;
    return executed;
  });
  // A supervisor's own exit status mirrors the supervised child exactly.
  if (
    outcome !== undefined &&
    typeof outcome.exitCode === 'number' &&
    outcome.exitCode !== 0
  ) {
    process.exitCode = outcome.exitCode;
  }
}

// ---- policy ----------------------------------------------------------------

export async function executePolicyCreateAction(
  args: readonly unknown[],
): Promise<void> {
  const command = args.at(-1) as Command;
  const merged = extractMergedOptions(command);
  await guard(merged['json'] === true, () =>
    executePolicyCreate(policyDefinitionOptions(merged, positionalId(command.args[0]))),
  );
}

export async function executePolicyCheckAction(
  args: readonly unknown[],
): Promise<void> {
  const command = args.at(-1) as Command;
  const merged = extractMergedOptions(command);
  let outcome: 'allow' | 'deny' | 'confirm' | undefined;
  await guard(merged['json'] === true, async () => {
    const result = await executePolicyCheck({
      ...executionFlatOptions(merged),
      policyId: positionalId(command.args[0]),
      executableAndArgs: command.args.slice(1),
    });
    outcome = result.outcome;
    return result;
  });
  if (outcome === 'deny') process.exitCode = CLI_EXIT_CODES.authorizationDenied;
  if (outcome === 'confirm') {
    process.exitCode = CLI_EXIT_CODES.confirmationRequired;
  }
}

export async function executePolicyExplainAction(
  args: readonly unknown[],
): Promise<void> {
  const command = args.at(-1) as Command;
  const merged = extractMergedOptions(command);
  await guard(merged['json'] === true, () =>
    executePolicyExplain({
      ...executionFlatOptions(merged),
      policyId: positionalId(command.args[0]),
      executableAndArgs: command.args.slice(1),
    }),
  );
}

export async function executePolicyLintAction(args: readonly unknown[]): Promise<void> {
  const command = args.at(-1) as Command;
  const merged = extractMergedOptions(command);
  let errors = 0;
  await guard(merged['json'] === true, async () => {
    const result = await executePolicyLint(executionFlatOptions(merged));
    errors = result.errors;
    return result;
  });
  if (errors > 0) process.exitCode = CLI_EXIT_CODES.invalidConfiguration;
}

export async function executePolicyDiffAction(args: readonly unknown[]): Promise<void> {
  const command = args.at(-1) as Command;
  const merged = extractMergedOptions(command);
  await guard(merged['json'] === true, () =>
    executePolicyDiff(policyDefinitionOptions(merged, positionalId(command.args[0]))),
  );
}

export async function executePolicySuggestAction(
  args: readonly unknown[],
): Promise<void> {
  const command = args.at(-1) as Command;
  const merged = extractMergedOptions(command);
  const limit = optString(merged['limit']);
  await guard(merged['json'] === true, () =>
    executePolicySuggest({
      ...executionFlatOptions(merged),
      ...(limit === undefined ? {} : { limit: parseLimit(limit) }),
    }),
  );
}

export async function executePolicyListAction(args: readonly unknown[]): Promise<void> {
  const list = args.at(-1) as Command;
  await guardOrRender(list, args, async () =>
    executePolicyList(
      executionFlatOptions(extractMergedOptions(args.at(-1) as Command)),
    ),
  );
}

export async function executePolicySnapshotAction(
  args: readonly unknown[],
): Promise<void> {
  const command = args.at(-1) as Command;
  const merged = extractMergedOptions(command);
  await guard(merged['json'] === true, () =>
    executePolicySnapshot(executionFlatOptions(merged)),
  );
}

export async function executePolicyShowAction(args: readonly unknown[]): Promise<void> {
  const command = args.at(-1) as Command;
  const merged = extractMergedOptions(command);
  await guardOrRender(command, args, async () =>
    executePolicyShow({
      ...executionFlatOptions(merged),
      policyId: requirePositional(command.args[0], 'policy id'),
    }),
  );
}

export async function executePolicyRemoveAction(
  args: readonly unknown[],
): Promise<void> {
  const command = args.at(-1) as Command;
  const merged = extractMergedOptions(command);
  await guardOrRender(command, args, async () =>
    executePolicyRemove({
      ...executionFlatOptions(merged),
      policyId: requirePositional(command.args[0], 'policy id'),
    }),
  );
}

function policyDefinitionOptions(
  merged: Readonly<Record<string, unknown>>,
  id: string,
): Parameters<typeof executePolicyCreate>[0] {
  const rawConfirmation = merged['requireConfirmation'];
  const confirmation =
    rawConfirmation === undefined
      ? undefined
      : typeof rawConfirmation === 'boolean'
        ? rawConfirmation
        : typeof rawConfirmation === 'string'
          ? parseConfirmationSpec(rawConfirmation)
          : undefined;
  return {
    ...executionFlatOptions(merged),
    id,
    ...(optString(merged['secret']) === undefined
      ? {}
      : { secret: optString(merged['secret']) }),
    commands: asStrings(merged['command']),
    hashes: asStrings(merged['hash']),
    ...(optString(merged['env']) === undefined
      ? {}
      : { env: optString(merged['env']) }),
    reveal: merged['reveal'] === true ? true : undefined,
    deny: merged['deny'] === true ? true : undefined,
    ...(optString(merged['ttl']) === undefined
      ? {}
      : { ttl: optString(merged['ttl']) }),
    ...(optString(merged['workdir']) === undefined
      ? {}
      : { workdir: optString(merged['workdir']) }),
    ...(typeof merged['maxUses'] === 'number' ? { maxUses: merged['maxUses'] } : {}),
    ...(confirmation === undefined ? {} : { requireConfirmation: confirmation }),
  };
}

// ---- grant -----------------------------------------------------------------

export async function executeGrantCreateAction(
  args: readonly unknown[],
): Promise<void> {
  const command = args.at(-1) as Command;
  const merged = extractMergedOptions(command);
  const secret = requirePositional(command.args[0], 'credential name');
  await guard(merged['json'] === true, () =>
    executeGrantCreate({
      ...executionFlatOptions(merged),
      secret,
      commands: asStrings(merged['command']),
      hashes: asStrings(merged['hash']),
      ...(optString(merged['env']) === undefined
        ? {}
        : { env: optString(merged['env']) }),
      ttl: requireTtl(merged['ttl']),
      ...(typeof merged['maxUses'] === 'number' ? { maxUses: merged['maxUses'] } : {}),
    }),
  );
}

export async function executeGrantListAction(args: readonly unknown[]): Promise<void> {
  const command = args.at(-1) as Command;
  await guardOrRender(command, args, async () =>
    executeGrantList(executionFlatOptions(extractMergedOptions(command))),
  );
}

export async function executeGrantShowAction(args: readonly unknown[]): Promise<void> {
  const command = args.at(-1) as Command;
  const merged = extractMergedOptions(command);
  await guard(merged['json'] === true, () =>
    executeGrantShow({
      ...executionFlatOptions(merged),
      grantId: requirePositional(command.args[0], 'grant id'),
    }),
  );
}

export async function executeGrantRevokeAction(
  args: readonly unknown[],
): Promise<void> {
  const command = args.at(-1) as Command;
  const merged = extractMergedOptions(command);
  await guard(merged['json'] === true, () =>
    executeGrantRevoke({
      ...executionFlatOptions(merged),
      grantId: requirePositional(command.args[0], 'grant id'),
    }),
  );
}

// Bare `kavrix grant <secret>` behaves like `grant create` per the product spec.
export async function executeGrantAction(args: readonly unknown[]): Promise<void> {
  const command = args.at(-1) as Command;
  const operands = [...command.args].filter((value) => typeof value === 'string');
  const first = operands[0];
  if (first === undefined || first.length === 0) {
    process.stderr.write(
      'Specify a secret, or use `kavrix grant create|list|show|revoke`.\n',
    );
    process.exitCode = 2;
    return;
  }
  const merged = extractMergedOptions(command);
  await guard(merged['json'] === true, () =>
    executeGrantCreate({
      ...executionFlatOptions(merged),
      secret: first,
      commands: asStrings(merged['command']),
      hashes: asStrings(merged['hash']),
      ...(optString(merged['env']) === undefined
        ? {}
        : { env: optString(merged['env']) }),
      ttl: requireTtl(merged['ttl']),
      ...(typeof merged['maxUses'] === 'number' ? { maxUses: merged['maxUses'] } : {}),
    }),
  );
}

// ---- executable pass-through guard ------------------------------------------

/**
 * Pre-action guard body for commands that require a literal `--` executable
 * pass-through. The light registration module registers the hook and awaits
 * this through a dynamic import; commander awaits pre-action hooks before
 * dispatching the action, so failures propagate exactly as before.
 */
export function assertExecutablePassThrough(actionCommand: Command): void {
  const rawArguments = invocationArguments(actionCommand);
  const delimiter = rawArguments.indexOf('--');
  if (delimiter < 0) {
    throw policyUsageError(
      actionCommand,
      'A literal `--` separator is required before the executable.',
    );
  }
  const executableAndArgs = rawArguments.slice(delimiter + 1);
  const executable = executableAndArgs[0];
  if (executable === undefined || executable.length === 0) {
    throw policyUsageError(actionCommand, 'An executable is required after `--`.');
  }
  const parsedExecutableAndArgs = actionCommand.args.slice(1);
  if (
    executableAndArgs.length !== parsedExecutableAndArgs.length ||
    executableAndArgs.some(
      (argument, index) => argument !== parsedExecutableAndArgs[index],
    )
  ) {
    throw policyUsageError(
      actionCommand,
      'The literal `--` separator must appear immediately before the executable.',
    );
  }
}

function policyUsageError(command: Command, message: string): CodedCliError {
  return new CodedCliError(
    'USAGE_ERROR',
    `error: ${message}\n\n${command.helpInformation().trimEnd()}`,
  );
}

function rootCommand(command: Command): Command {
  let current = command;
  while (current.parent !== null) current = current.parent;
  return current;
}

function invocationArguments(command: Command): readonly string[] {
  const root = rootCommand(command) as Command & { readonly rawArgs?: unknown };
  const rawArguments = root.rawArgs;
  return Array.isArray(rawArguments) &&
    rawArguments.every((argument) => typeof argument === 'string')
    ? rawArguments
    : [];
}

// ---- audit -----------------------------------------------------------------

export async function executeAuditAction(args: readonly unknown[]): Promise<void> {
  const command = args.at(-1) as Command;
  const merged = extractMergedOptions(command);
  const limitRaw = optString(merged['limit']);
  await guardOrRender(command, args, async () =>
    executeAudit({
      ...executionFlatOptions(merged),
      ...(limitRaw === undefined ? {} : { limit: parseLimit(limitRaw) }),
    }),
  );
}

// ---- agent -----------------------------------------------------------------

export async function executeAgentRunAction(args: readonly unknown[]): Promise<void> {
  const command = args.at(-1) as Command;
  const merged = extractMergedOptions(command);
  let summary: { readonly exitCode: number } | undefined;
  await guard(merged['json'] === true, async () => {
    const ran = await executeAgentRun({
      ...executionFlatOptions(merged),
      agentName: requireOptionString(merged['agent'], '--agent'),
      ...(optString(merged['config']) === undefined
        ? {}
        : { config: optString(merged['config']) }),
      dryRun: merged['dryRun'] === true,
      json: merged['json'] === true,
      executableAndArgs: [...command.args],
    });
    summary = ran as { readonly exitCode: number };
    return ran;
  });
  if (summary !== undefined && summary.exitCode !== 0) {
    process.exitCode = summary.exitCode;
  }
}

export async function executeAgentExecAction(args: readonly unknown[]): Promise<void> {
  const command = args.at(-1) as Command;
  const merged = extractMergedOptions(command);
  const permission = requirePositional(command.args[0], 'permission');
  await guard(merged['json'] === true, () =>
    executeAgentExec({
      permission,
      dryRun: merged['dryRun'] === true,
      ...(optString(merged['config']) === undefined
        ? {}
        : { config: optString(merged['config']) }),
      executableAndArgs: command.args.slice(1),
    }),
  );
}

// ---- shared plumbing -------------------------------------------------------

async function guard(
  jsonRequested: boolean,
  operation: () => Promise<unknown>,
): Promise<void> {
  try {
    const result = await operation();
    if (jsonRequested) emitJson(result);
    else renderHuman(result);
  } catch (error) {
    if (jsonRequested) reportJsonFailure(error);
    throw error;
  }
}

/**
 * Writes the stable `--json` error envelope once and marks the failure so
 * the top-level CLI does not also print a human duplicate on stderr.
 */
export function reportJsonFailure(error: unknown): boolean {
  if (wasJsonReported(error)) return true;
  if (isCodedCliError(error)) {
    emitJson(toErrorEnvelope(error.errorCode, singleLine(error.message)));
    markJsonReported(error);
    return true;
  }
  if (error instanceof DatabaseSessionError) {
    emitJson(
      toErrorEnvelope(
        cliErrorCodeForSessionFailure(error.code),
        singleLine(error.message),
      ),
    );
    markJsonReported(error);
    return true;
  }
  return false;
}

async function guardOrRender(
  command: Command,
  _args: readonly unknown[],
  operation: () => Promise<unknown>,
): Promise<void> {
  void _args;
  const jsonRequested = extractMergedOptions(command)['json'] === true;
  await guard(jsonRequested, operation);
}

// ---- output and parsing helpers ---------------------------------------------

export function emitJson(value: unknown): void {
  // JSON.stringify can return undefined for unsupported top-level values even
  // though the TypeScript declaration exposes only its usual string result.
  const serialized = JSON.stringify(value) as string | undefined;
  // JSON.stringify escapes C0 characters inside strings, but leaves DEL and
  // C1 controls literal. Escape the full terminal-control range at the final
  // output boundary so hostile values cannot execute in a consuming terminal.
  const safeSerialized =
    serialized === undefined
      ? serialized
      : serialized.replace(
          // eslint-disable-next-line no-control-regex
          /[\u0000-\u001f\u007f-\u009f]/gu,
          (character) => `\\u${character.charCodeAt(0).toString(16).padStart(4, '0')}`,
        );
  process.stdout.write(`${safeSerialized ?? 'undefined'}\n`);
}

export function renderHuman(value: unknown): void {
  if (isRunOutcome(value) || isAgentRunSummary(value)) {
    // The child owns the terminal; supervisors stay silent on success.
    return;
  }
  if (isRecord(value)) {
    const nestedKey = ['checks', 'changes', 'findings', 'suggestions'].find((key) =>
      Array.isArray(value[key]),
    );
    if (nestedKey !== undefined) {
      const summary = formatRecordLine(value);
      if (summary.length > 0) process.stdout.write(`${summary}\n`);
      renderRecordLines((value[nestedKey] as unknown[]).filter(isRecord));
      return;
    }
  }
  renderRecordLines(flattenRecords(value));
}

function isRunOutcome(value: unknown): boolean {
  return (
    typeof value === 'object' &&
    value !== null &&
    'ran' in value &&
    'executable' in value
  );
}

function isAgentRunSummary(value: unknown): boolean {
  return typeof value === 'object' && value !== null && 'allowedRequests' in value;
}

export function flattenRecords(value: unknown): readonly Record<string, unknown>[] {
  if (Array.isArray(value)) return value.filter(isRecord);
  if (!isRecord(value)) return [];
  for (const key of [
    'policies',
    'grants',
    'events',
    'checks',
    'changes',
    'findings',
    'suggestions',
  ]) {
    const nested = value[key];
    if (Array.isArray(nested)) return nested.filter(isRecord);
  }
  if (
    'grantId' in value ||
    'id' in value ||
    'removed' in value ||
    'saved' in value ||
    'granted' in value ||
    'revoked' in value ||
    'total' in value
  ) {
    return [value];
  }
  return [value];
}

export function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

export function renderRecordLines(records: readonly Record<string, unknown>[]): void {
  for (const record of records) {
    process.stdout.write(`${formatRecordLine(record)}\n`);
  }
}

export function formatRecordLine(record: Record<string, unknown>): string {
  if (isRecord(record['decision'])) {
    const decision = record['decision'];
    return [
      named('policy', record['policyId']),
      named('credential', record['secret']),
      named('command', record['command']),
      named('outcome', decision['outcome']),
      named('reason', decision['reason']),
      named('ttlMs', record['executionWindowMs']),
      'credentialRead=false',
    ]
      .filter((part) => part.length > 0)
      .join(' ');
  }
  if (typeof record['outcome'] === 'string' && 'policyId' in record) {
    return [
      named('policy', record['policyId']),
      named('credential', record['secret']),
      named('command', record['command']),
      named('outcome', record['outcome']),
      named('reason', record['reason']),
      named('ttlMs', record['executionWindowMs']),
      'credentialRead=false',
    ]
      .filter((part) => part.length > 0)
      .join(' ');
  }
  if (typeof record['order'] === 'number' && typeof record['kind'] === 'string') {
    return [
      `#${text(record['order'])}`,
      text(record['kind']),
      named('status', record['status']),
      named('effect', record['effect']),
      named('policy', record['policyId']),
      named('related', record['relatedPolicyId']),
      named('expected', record['expected']),
      named('actual', record['actual']),
      text(record['note']),
    ]
      .filter((part) => part.length > 0)
      .join(' ');
  }
  if (typeof record['field'] === 'string' && 'impact' in record) {
    return [
      text(record['field']),
      named('impact', record['impact']),
      named('before', record['before']),
      named('after', record['after']),
    ]
      .filter((part) => part.length > 0)
      .join(' ');
  }
  if (typeof record['category'] === 'string' && 'severity' in record) {
    return [
      text(record['severity']).toUpperCase(),
      text(record['category']),
      named('code', record['code']),
      `${text(record['targetType'])}=${text(record['targetId'])}`,
      named('related', record['relatedIds']),
      text(record['message']),
    ]
      .filter((part) => part.length > 0)
      .join(' ');
  }
  if (typeof record['suggestionId'] === 'string') {
    return [
      text(record['suggestionId']),
      named('policy', record['policyId']),
      named('credential', record['secret']),
      named('current', record['currentCommands']),
      named('proposed', record['proposedCommands']),
      named('uses', record['observedUses']),
      'review=true',
      'confidence=low',
    ]
      .filter((part) => part.length > 0)
      .join(' ');
  }
  if ('checkedPolicies' in record && 'checkedGrants' in record) {
    return [
      named('policies', record['checkedPolicies']),
      named('grants', record['checkedGrants']),
      named('errors', record['errors']),
      named('warnings', record['warnings']),
    ]
      .filter((part) => part.length > 0)
      .join(' ');
  }
  if (typeof record['operation'] === 'string' && 'changed' in record) {
    return [
      text(record['id']),
      named('operation', record['operation']),
      named('changed', record['changed']),
    ]
      .filter((part) => part.length > 0)
      .join(' ');
  }
  if ('reviewOnly' in record && 'coverage' in record) {
    return [
      named('auditEvents', record['retainedAuditEvents']),
      named('positiveEvents', record['positiveAuthorizationEvents']),
      named('coverage', record['coverage']),
      'reviewOnly=true',
    ]
      .filter((part) => part.length > 0)
      .join(' ');
  }
  if (typeof record['occurredAt'] === 'string') {
    const parts = [
      text(record['occurredAt']),
      `actor=${text(record['actor']) || '?'}`,
      `action=${text(record['action']) || '?'}`,
      named('policy', record['policyId']),
      named('permission', record['permissionKey']),
      named('credential', record['secret']),
      named('command', record['command']),
      named('reason', record['reason']),
      named('exit', record['exitCode']),
    ].filter((part) => part.length > 0);
    return parts.join(' ');
  }
  const provenance = isRecord(record['provenance']) ? record['provenance'] : {};
  const parts = [
    text(record['id']) || text(record['grantId']),
    text(record['secret']),
    Array.isArray(record['commands'])
      ? record['commands'].map((entry) => text(entry)).join(',')
      : '',
    named('status', record['status']),
    record['reveal'] === true ? 'reveal=true' : '',
    record['deny'] === true ? 'DENY' : '',
    named('ttl', record['ttl']),
    named('maxUses', record['maxUses']),
    named('remainingUses', record['remainingUses']),
    named('expires', record['expiresAt']),
    named('expiresInMs', record['expiresInMs']),
    named('actor', record['actor']),
    named('hashes', record['hashes']),
    named('env', record['env']),
    named('createdByPolicy', provenance['createdByPolicyId']),
    named('agentPermission', provenance['agentPermissionKey']),
  ].filter((part) => part.length > 0);
  return parts.join('  ');
}

export function text(value: unknown): string {
  if (typeof value === 'string') return safeTerminalText(value);
  if (typeof value === 'number') return String(value);
  if (typeof value === 'boolean') return String(value);
  return '';
}

export function named(name: string, value: unknown): string {
  const rendered =
    Array.isArray(value) || isRecord(value)
      ? safeTerminalText(JSON.stringify(value))
      : text(value);
  return rendered.length === 0 ? '' : `${name}=${rendered}`;
}

function asStrings(value: unknown): readonly string[] {
  return Array.isArray(value) ? value.map((entry) => String(entry)) : [];
}

/**
 * Pulls `--no-config` / `--environment` off leftover tokens that Commander
 * treated as unknown, without stealing child arguments after `--` or the
 * executable.
 */
function recoverSwallowedRunOptions(args: readonly string[]): {
  noConfig: boolean;
  environmentName: string | undefined;
  environmentRequested: boolean;
  executableAndArgs: string[];
} {
  let noConfig = false;
  let environmentName: string | undefined;
  let environmentRequested = false;
  let index = 0;
  while (index < args.length) {
    const token = args[index] ?? '';
    if (token === '--') {
      index += 1;
      break;
    }
    if (token === '--no-config') {
      noConfig = true;
      index += 1;
      continue;
    }
    if (token === '--environment') {
      environmentRequested = true;
      const value = args[index + 1];
      if (value !== undefined && value !== '--' && !value.startsWith('-')) {
        environmentName = value;
        index += 2;
        continue;
      }
      index += 1;
      continue;
    }
    if (token.startsWith('--environment=')) {
      environmentRequested = true;
      const value = token.slice('--environment='.length);
      if (value.length > 0) environmentName = value;
      index += 1;
      continue;
    }
    break;
  }
  return {
    noConfig,
    environmentName,
    environmentRequested,
    executableAndArgs: args.slice(index),
  };
}

function optString(value: unknown): string | undefined {
  return typeof value === 'string' && value.length > 0 ? value : undefined;
}

function requireOptionString(value: unknown, label: string): string {
  const parsed = optString(value);
  if (parsed === undefined) throw new Error(`${label} is required.`);
  return parsed;
}

function requirePositional(value: unknown, label: string): string {
  const parsed = typeof value === 'string' ? value : undefined;
  if (parsed === undefined || parsed.length === 0)
    throw new Error(`A ${label} is required.`);
  return parsed;
}

function positionalId(value: unknown): string {
  return requirePositional(value, 'policy id');
}

function parseLimit(raw: string): number {
  if (!/^[1-9][0-9]{0,3}$/u.test(raw))
    throw invalidConfiguration('--limit expects a whole number between 1 and 999.');
  return Number(raw);
}

function parseConfirmationSpec(spec: string): boolean | readonly string[] {
  const normalized = spec.trim().toLowerCase();
  if (normalized.length === 0 || normalized === 'true') return true;
  if (normalized === 'false') return false;
  return spec
    .split(',')
    .map((token) => token.trim())
    .filter((token) => token.length > 0);
}

function singleLine(message: string): string {
  return safeTerminalText(message, 512);
}

function safeTerminalText(value: string, maxLength = 1024): string {
  const sanitized = value.replace(
    // C0/C1 terminal controls include ANSI CSI/OSC introducers and line breaks.
    // eslint-disable-next-line no-control-regex
    /[\u0000-\u001f\u007f-\u009f]/gu,
    ' ',
  );
  return sanitized.length > maxLength
    ? `${sanitized.slice(0, Math.max(0, maxLength - 3))}...`
    : sanitized;
}

function requireTtl(value: unknown): string {
  const parsed = optString(value);
  if (parsed === undefined) {
    throw invalidConfiguration('--ttl is required to issue a grant.');
  }
  return parsed;
}
