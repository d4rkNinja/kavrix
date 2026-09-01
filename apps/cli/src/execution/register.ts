import type { Command } from 'commander';

import { executeAgentExec, executeAgentRun } from './agent-command.js';
import { executeAudit } from './audit-command.js';
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
  executePolicyRemove,
  executePolicyShow,
  executePolicySuggest,
} from './policy-command.js';
import {
  addExecutionRoutingOptions,
  executionFlatOptions,
  extractMergedOptions,
} from './cli-options.js';
import {
  CLI_EXIT_CODES,
  CodedCliError,
  invalidConfiguration,
  isCodedCliError,
  toErrorEnvelope,
} from './exit-codes.js';
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

  const create = addPolicyDefinitionOptions(
    policy
      .command('create <id>')
      .description('Create or replace one stored permission policy.'),
  ).option('--json', 'Emit machine-readable output.');
  addExecutionRoutingOptions(create);
  create.action(async (...args: unknown[]) => {
    const command = args.at(-1) as Command;
    const merged = extractMergedOptions(command);
    await guard(merged['json'] === true, () =>
      executePolicyCreate(
        policyDefinitionOptions(merged, positionalId(command.args[0])),
      ),
    );
  });

  const check = policy
    .command('check <id>')
    .description('Simulate one invocation without reading the credential.')
    .usage('[options] <id> -- <executable> [args...]')
    .allowUnknownOption(true)
    .allowExcessArguments(true)
    .option('--json', 'Emit machine-readable output.');
  addExecutionRoutingOptions(check);
  requireExecutablePassThrough(check);
  check.action(async (...args: unknown[]) => {
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
  });

  const explain = policy
    .command('explain <id>')
    .description('Explain the ordered rules for one simulated invocation.')
    .usage('[options] <id> -- <executable> [args...]')
    .allowUnknownOption(true)
    .allowExcessArguments(true)
    .option('--json', 'Emit machine-readable output.');
  addExecutionRoutingOptions(explain);
  requireExecutablePassThrough(explain);
  explain.action(async (...args: unknown[]) => {
    const command = args.at(-1) as Command;
    const merged = extractMergedOptions(command);
    await guard(merged['json'] === true, () =>
      executePolicyExplain({
        ...executionFlatOptions(merged),
        policyId: positionalId(command.args[0]),
        executableAndArgs: command.args.slice(1),
      }),
    );
  });

  const lint = policy
    .command('lint')
    .description('Find ineffective, broad, shadowed, or expired authorization rules.')
    .option('--json', 'Emit machine-readable output.');
  addExecutionRoutingOptions(lint);
  lint.action(async (...args: unknown[]) => {
    const command = args.at(-1) as Command;
    const merged = extractMergedOptions(command);
    let errors = 0;
    await guard(merged['json'] === true, async () => {
      const result = await executePolicyLint(executionFlatOptions(merged));
      errors = result.errors;
      return result;
    });
    if (errors > 0) process.exitCode = CLI_EXIT_CODES.invalidConfiguration;
  });

  const diff = addPolicyDefinitionOptions(
    policy
      .command('diff <id>')
      .description('Preview the semantic change before replacing a policy.'),
  ).option('--json', 'Emit machine-readable output.');
  addExecutionRoutingOptions(diff);
  diff.action(async (...args: unknown[]) => {
    const command = args.at(-1) as Command;
    const merged = extractMergedOptions(command);
    await guard(merged['json'] === true, () =>
      executePolicyDiff(policyDefinitionOptions(merged, positionalId(command.args[0]))),
    );
  });

  const suggest = policy
    .command('suggest')
    .description('Suggest review-only least-privilege policy tightenings.')
    .option('--limit <count>', 'Maximum retained audit events to inspect.', '100')
    .option('--json', 'Emit machine-readable output.');
  addExecutionRoutingOptions(suggest);
  suggest.action(async (...args: unknown[]) => {
    const command = args.at(-1) as Command;
    const merged = extractMergedOptions(command);
    const limit = optString(merged['limit']);
    await guard(merged['json'] === true, () =>
      executePolicySuggest({
        ...executionFlatOptions(merged),
        ...(limit === undefined ? {} : { limit: parseLimit(limit) }),
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

function addPolicyDefinitionOptions(command: Command): Command {
  return command
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

function registerGrant(program: Command): void {
  const grant = program
    .command('grant [secretRef]')
    .description('Issue, inspect, list, or revoke temporary consumable authorizations.')
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
  create.addHelpText('after', () => inheritedGrantCreationHelp(grant));
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

  const show = grant.command('show <grantId>').description('Inspect one grant.');
  show.action(async (...args: unknown[]) => {
    const command = args.at(-1) as Command;
    const merged = extractMergedOptions(command);
    await guard(merged['json'] === true, () =>
      executeGrantShow({
        ...executionFlatOptions(merged),
        grantId: requirePositional(command.args[0], 'grant id'),
      }),
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
        ...(typeof merged['maxUses'] === 'number'
          ? { maxUses: merged['maxUses'] }
          : {}),
      }),
    );
  });
}

function requireExecutablePassThrough(command: Command): void {
  command.hook('preAction', (_hookCommand, actionCommand) => {
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
  });
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

function inheritedGrantCreationHelp(grant: Command): string {
  const options = grant.options.filter((option) => option.long !== undefined);
  const width = Math.max(...options.map((option) => option.flags.length));
  return [
    '',
    'Effective creation options inherited from `kavrix grant`:',
    'Place these options before or after `create <secret>`.',
    '',
    ...options.map(
      (option) => `  ${option.flags.padEnd(width)}  ${option.description}`,
    ),
  ].join('\n');
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
