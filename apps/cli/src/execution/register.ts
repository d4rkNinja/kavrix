import type { Command } from 'commander';

import { executeAgentExec, executeAgentRun } from './agent-command.js';
import { executeAudit } from './audit-command.js';
import {
  executeGrantCreate,
  executeGrantList,
  executeGrantRevoke,
} from './policy-command.js';
import {
  extractMergedOptions,
  executionFlatOptions,
  addExecutionRoutingOptions,
} from './cli-options.js';
import {
  invalidConfiguration,
  isCodedCliError,
  toErrorEnvelope,
} from './exit-codes.js';
import {
  executePolicyCreate,
  executePolicyList,
  executePolicyRemove,
  executePolicyShow,
} from './policy-command.js';
import { executeRun } from './run-command.js';

function collectExecutionOption(
  value: string,
  previous: readonly string[],
): readonly string[] {
  return [...previous, value];
}

/** Registers the credential-execution command family on the root program. */
export function registerExecutionCommands(program: Command): void {
  registerRun(program);
  registerPolicy(program);
  registerGrant(program);
  registerAudit(program);
  registerAgent(program);
}

// ---- run -------------------------------------------------------------------

function registerRun(program: Command): void {
  const run = program
    .command('run')
    .description(
      'Execute a command with selected credentials injected into its environment only.',
    )
    .allowUnknownOption(true)
    .allowExcessArguments(true)
    .option(
      '--secret <mapping>',
      'Destination variable and credential name (ENV=NAME).',
      collectExecutionOption,
      [],
    )
    .option('--environment <name>', 'Apply one project-file environment mapping set.')
    .option('--config <path>', 'Non-secret project configuration file.')
    .option('--no-config', 'Ignore any project configuration file.')
    .option(
      '--policy <id>',
      'Require this stored or project policy for the child.',
      collectExecutionOption,
      [],
    )
    .option(
      '--grant <ref>',
      'Consume a temporary grant by id or credential name.',
      collectExecutionOption,
      [],
    )
    .option(
      '--json',
      'Capture child output (redacted) and emit a machine-readable envelope.',
    );
  addExecutionRoutingOptions(run);
  run.action(async (...args: unknown[]) => {
    const command = args.at(-1) as Command;
    const merged = extractMergedOptions(command);
    let outcome: { readonly exitCode: number | null } | undefined;
    await guard(merged['json'] === true, async () => {
      const executed = await executeRun({
        ...executionFlatOptions(merged),
        secretMappings: asStrings(merged['secret']),
        ...(optString(merged['environment']) === undefined
          ? {}
          : { environmentName: optString(merged['environment']) }),
        ...(optString(merged['config']) === undefined
          ? {}
          : { config: optString(merged['config']) }),
        noConfig: merged['noConfig'] === true,
        policyIds: asStrings(merged['policy']),
        grantRefs: asStrings(merged['grant']),
        json: merged['json'] === true,
        executableAndArgs: [...command.args],
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
  });
}

// ---- policy ----------------------------------------------------------------

function registerPolicy(program: Command): void {
  const policy = program
    .command('policy')
    .description('Manage stored credential permission policies.');

  const create = policy
    .command('create <id>')
    .description('Create or replace one stored permission policy.')
    .option('--secret <name>', 'Credential this policy protects.')
    .option(
      '--command <name>',
      'Allowed executable; repeatable.',
      collectExecutionOption,
      [],
    )
    .option(
      '--hash <pin>',
      'Executable pin (COMMAND=SHA256HEX); repeatable.',
      collectExecutionOption,
      [],
    )
    .option(
      '--env <variable>',
      'Destination variable when used through grants or agents.',
    )
    .option('--reveal', 'Explicitly allow plaintext reveal of this credential.')
    .option('--deny', 'Forbid every use of this credential.')
    .option('--ttl <duration>', 'Maximum execution window per use (e.g. 30m).')
    .option(
      '--workdir <path>',
      'Restrict use to invocations inside this directory subtree.',
    )
    .option(
      '--max-uses <count>',
      'Maximum uses when issued as a grant.',
      parsePositiveInt,
    )
    .option(
      '--require-confirmation [spec]',
      'Ask before use: flag alone always asks; comma list asks on first-argument match.',
    )
    .option('--json', 'Emit machine-readable output.');
  addExecutionRoutingOptions(create);
  create.action(async (...args: unknown[]) => {
    const command = args.at(-1) as Command;
    const merged = extractMergedOptions(command);
    const id = positionalId(command.args[0]);
    // A bare `--require-confirmation` flag arrives as `true`; a value arrives
    // as its string form. Both normalize into the schema's union shape.
    const rawConfirmation: unknown = merged['requireConfirmation'];
    const confirmation =
      rawConfirmation === undefined
        ? undefined
        : typeof rawConfirmation === 'boolean'
          ? rawConfirmation
          : typeof rawConfirmation === 'string'
            ? parseConfirmationSpec(rawConfirmation)
            : undefined;
    await guard(merged['json'] === true, () =>
      executePolicyCreate({
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
        ...(typeof merged['maxUses'] === 'number'
          ? { maxUses: merged['maxUses'] }
          : {}),
        ...(confirmation === undefined ? {} : { requireConfirmation: confirmation }),
      }),
    );
  });

  const list = policy.command('list').description('List stored policies.');
  addExecutionRoutingOptions(list);
  list.option('--json', 'Emit machine-readable output.');
  list.action(async (...args: unknown[]) =>
    guardOrRender(list, args, async () =>
      executePolicyList(
        executionFlatOptions(extractMergedOptions(args.at(-1) as Command)),
      ),
    ),
  );

  const show = policy.command('show <id>').description('Show one stored policy.');
  addExecutionRoutingOptions(show);
  show.option('--json', 'Emit machine-readable output.');
  show.action(async (...args: unknown[]) => {
    const command = args.at(-1) as Command;
    const merged = extractMergedOptions(command);
    await guardOrRender(show, args, async () =>
      executePolicyShow({
        ...executionFlatOptions(merged),
        policyId: requirePositional(command.args[0], 'policy id'),
      }),
    );
  });

  const remove = policy.command('remove <id>').description('Remove one stored policy.');
  addExecutionRoutingOptions(remove);
  remove.option('--json', 'Emit machine-readable output.');
  remove.action(async (...args: unknown[]) => {
    const command = args.at(-1) as Command;
    const merged = extractMergedOptions(command);
    await guardOrRender(remove, args, async () =>
      executePolicyRemove({
        ...executionFlatOptions(merged),
        policyId: requirePositional(command.args[0], 'policy id'),
      }),
    );
  });
}

// ---- grant -----------------------------------------------------------------

function registerGrant(program: Command): void {
  const grant = program
    .command('grant [secretRef]')
    .description('Issue, list, or revoke temporary consumable authorizations.')
    // The documented bare form `kavrix grant <secret>` accepts creation flags
    // directly so it behaves exactly like `grant create`.
    .option('--json', 'Emit machine-readable output.')
    .option(
      '--command <name>',
      'Allowed executable; repeatable.',
      collectExecutionOption,
      [],
    )
    .option(
      '--hash <pin>',
      'Executable pin (COMMAND=SHA256HEX); repeatable.',
      collectExecutionOption,
      [],
    )
    .option('--env <variable>', 'Destination variable injected on use.')
    .option('--ttl <duration>', 'Grant validity window (e.g. 15m).')
    .option('--max-uses <count>', 'Maximum uses before exhaustion.', parsePositiveInt);
  addExecutionRoutingOptions(grant);

  // Creation flags live ONLY on the parent so the bare `grant <secret>` form
  // and `grant create` share one option surface; duplicating them on the child
  // makes commander swallow values before the subcommand sees them.
  const create = grant
    .command('create <secret>')
    .description('Issue one temporary authorization for a credential.');
  create.action(async (...args: unknown[]) => {
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
        ...(typeof merged['maxUses'] === 'number'
          ? { maxUses: merged['maxUses'] }
          : {}),
      }),
    );
  });

  const list = grant.command('list').description('List grants and their live status.');
  list.action(async (...args: unknown[]) => {
    const command = args.at(-1) as Command;
    await guardOrRender(list, args, async () =>
      executeGrantList(executionFlatOptions(extractMergedOptions(command))),
    );
  });

  const revoke = grant.command('revoke <grantId>').description('Revoke one grant.');
  revoke.action(async (...args: unknown[]) => {
    const command = args.at(-1) as Command;
    const merged = extractMergedOptions(command);
    await guard(merged['json'] === true, () =>
      executeGrantRevoke({
        ...executionFlatOptions(merged),
        grantId: requirePositional(command.args[0], 'grant id'),
      }),
    );
  });

  // Bare `kavrix grant <secret>` behaves like `grant create` per the product spec.
  grant.action(async (...args: unknown[]) => {
    const command = args.at(-1) as Command;
    const operands = [...command.args].filter((value) => typeof value === 'string');
    const first = operands[0];
    if (first === undefined || first.length === 0) {
      process.stderr.write(
        'Specify a secret, or use `kavrix grant create|list|revoke`.\n',
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
        ...(typeof merged['maxUses'] === 'number'
          ? { maxUses: merged['maxUses'] }
          : {}),
      }),
    );
  });
}

// ---- audit -----------------------------------------------------------------

function registerAudit(program: Command): void {
  const audit = program
    .command('audit')
    .description('Show recent security-relevant audit events (no secret material).');
  addExecutionRoutingOptions(audit);
  audit
    .option('--limit <count>', 'Maximum events to show.', '100')
    .option('--json', 'Emit machine-readable output.');
  audit.action(async (...args: unknown[]) => {
    const command = args.at(-1) as Command;
    const merged = extractMergedOptions(command);
    const limitRaw = optString(merged['limit']);
    await guardOrRender(audit, args, async () =>
      executeAudit({
        ...executionFlatOptions(merged),
        ...(limitRaw === undefined ? {} : { limit: parseLimit(limitRaw) }),
      }),
    );
  });
}

// ---- agent -----------------------------------------------------------------

function registerAgent(program: Command): void {
  const agent = program
    .command('agent')
    .description('Run AI coding agents behind the local credential firewall.');

  const agentRun = agent
    .command('run')
    .description('Start an agent process that must request credentials through Kavrix.')
    .allowUnknownOption(true)
    .allowExcessArguments(true)
    .requiredOption('--agent <name>', 'Agent entry in the project configuration file.')
    .option('--config <path>', 'Non-secret project configuration file.')
    .option('--json', 'Emit a machine-readable envelope after the agent exits.');
  addExecutionRoutingOptions(agentRun);
  agentRun.action(async (...args: unknown[]) => {
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
        json: merged['json'] === true,
        executableAndArgs: [...command.args],
      });
      summary = ran as { readonly exitCode: number };
      return ran;
    });
    if (summary !== undefined && summary.exitCode !== 0) {
      process.exitCode = summary.exitCode;
    }
  });

  const agentExec = agent
    .command('exec')
    .description(
      'Request one authorized operation from the running Kavrix agent broker.',
    )
    .allowUnknownOption(true)
    .allowExcessArguments(true)
    .argument('<permission>', 'Permission key from the agent configuration.');
  agentExec.action(async (...args: unknown[]) => {
    const command = args.at(-1) as Command;
    const permission = requirePositional(command.args[0], 'permission');
    await guard(false, () =>
      executeAgentExec({
        permission,
        executableAndArgs: command.args.slice(1),
      }),
    );
  });
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
    if (jsonRequested && error instanceof Error && isCodedCliError(error)) {
      emitJson(toErrorEnvelope(error.errorCode, singleLine(error.message)));
    }
    throw error;
  }
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
  process.stdout.write(`${JSON.stringify(value)}\n`);
}

export function renderHuman(value: unknown): void {
  if (isRunOutcome(value) || isAgentRunSummary(value)) {
    // The child owns the terminal; supervisors stay silent on success.
    return;
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
  for (const key of ['policies', 'grants', 'events']) {
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
    named('expires', record['expiresAt']),
  ].filter((part) => part.length > 0);
  return parts.join('  ');
}

export function text(value: unknown): string {
  if (typeof value === 'string') return value;
  if (typeof value === 'number') return String(value);
  if (typeof value === 'boolean') return String(value);
  return '';
}

export function named(name: string, value: unknown): string {
  const rendered = text(value);
  return rendered.length === 0 ? '' : `${name}=${rendered}`;
}

function asStrings(value: unknown): readonly string[] {
  return Array.isArray(value) ? value.map((entry) => String(entry)) : [];
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

function parsePositiveInt(raw: string): number {
  if (!/^[1-9][0-9]{0,6}$/u.test(raw))
    throw invalidConfiguration('--max-uses expects a positive whole number.');
  return Number(raw);
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
  // Strip terminal control sequences before emitting machine-readable JSON.
  const sanitized = message.replace(
    // eslint-disable-next-line no-control-regex
    /[\u0000-\u0008\u000b\u000c\u000e-\u001f\u007f]/gu,
    ' ',
  );
  return sanitized.length > 512 ? `${sanitized.slice(0, 509)}...` : sanitized;
}

function requireTtl(value: unknown): string {
  const parsed = optString(value);
  if (parsed === undefined) {
    throw invalidConfiguration('--ttl is required to issue a grant.');
  }
  return parsed;
}
