import type { Command } from 'commander';

import { addExecutionRoutingOptions } from './cli-options.js';
import { invalidConfiguration } from './exit-codes.js';

/**
 * Light registration module: it only builds commander shapes synchronously on
 * every invocation. Heavy implementations (execute* handlers, guards, output
 * plumbing, and `reportJsonFailure`) live in `./commands.js`, which every
 * action callback and the executable pass-through hook import on demand.
 */

function collectExecutionOption(
  value: string,
  previous: readonly string[],
): readonly string[] {
  return [...previous, value];
}

/**
 * Commander applies custom option parsers synchronously while parsing argv,
 * before any action can await the implementation barrel, so this parse-time
 * `--max-uses` validation cannot move behind a dynamic import. It keeps
 * `invalidConfiguration` (and the schema package behind it) as the one
 * deliberate static weight in this registration module.
 */
function parsePositiveInt(raw: string): number {
  if (!/^[1-9][0-9]{0,6}$/u.test(raw))
    throw invalidConfiguration('--max-uses expects a positive whole number.');
  return Number(raw);
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
      'Execute a command with selected credentials injected into its environment only. The child may follow `--` or appear as remaining arguments (example: kavrix run --secret MYSECRET=name -- printenv MYSECRET). `--` is recommended when the child has its own flags.',
    )
    .usage('[options] -- <executable> [args...]')
    .allowUnknownOption(true)
    .allowExcessArguments(true)
    .option(
      '--secret <mapping>',
      'Destination variable and credential name (MYSECRET=NAME).',
      collectExecutionOption,
      [],
    )
    .option('--environment <name>', 'Apply one project-file environment mapping set.')
    .option('--config <path>', 'Non-secret project configuration file.')
    .option(
      '--no-config',
      'Skip project configuration: ignore cwd kavrix.yaml / --config; use only CLI --secret flags and profiles.',
    )
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
    const impl = await import('./commands.js');
    await impl.executeRunAction(args);
  });
}

// ---- policy ----------------------------------------------------------------

function registerPolicy(program: Command): void {
  const policy = program
    .command('policy')
    .description('Manage stored credential permission policies.');

  const snapshot = policy
    .command('snapshot')
    .description(
      'Read policies, grants, and audit from one authenticated state snapshot.',
    )
    .option('--json', 'Emit machine-readable output.');
  addExecutionRoutingOptions(snapshot);
  snapshot.action(async (...args: unknown[]) => {
    const impl = await import('./commands.js');
    await impl.executePolicySnapshotAction(args);
  });

  const create = addPolicyDefinitionOptions(
    policy
      .command('create <id>')
      .description('Create or replace one stored permission policy.'),
  ).option('--json', 'Emit machine-readable output.');
  addExecutionRoutingOptions(create);
  create.action(async (...args: unknown[]) => {
    const impl = await import('./commands.js');
    await impl.executePolicyCreateAction(args);
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
    const impl = await import('./commands.js');
    await impl.executePolicyCheckAction(args);
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
    const impl = await import('./commands.js');
    await impl.executePolicyExplainAction(args);
  });

  const lint = policy
    .command('lint')
    .description('Find ineffective, broad, shadowed, or expired authorization rules.')
    .option('--json', 'Emit machine-readable output.');
  addExecutionRoutingOptions(lint);
  lint.action(async (...args: unknown[]) => {
    const impl = await import('./commands.js');
    await impl.executePolicyLintAction(args);
  });

  const diff = addPolicyDefinitionOptions(
    policy
      .command('diff <id>')
      .description('Preview the semantic change before replacing a policy.'),
  ).option('--json', 'Emit machine-readable output.');
  addExecutionRoutingOptions(diff);
  diff.action(async (...args: unknown[]) => {
    const impl = await import('./commands.js');
    await impl.executePolicyDiffAction(args);
  });

  const suggest = policy
    .command('suggest')
    .description('Suggest review-only least-privilege policy tightenings.')
    .option('--limit <count>', 'Maximum retained audit events to inspect.', '100')
    .option('--json', 'Emit machine-readable output.');
  addExecutionRoutingOptions(suggest);
  suggest.action(async (...args: unknown[]) => {
    const impl = await import('./commands.js');
    await impl.executePolicySuggestAction(args);
  });

  const list = policy.command('list').description('List stored policies.');
  addExecutionRoutingOptions(list);
  list.option('--json', 'Emit machine-readable output.');
  list.action(async (...args: unknown[]) => {
    const impl = await import('./commands.js');
    await impl.executePolicyListAction(args);
  });

  const show = policy.command('show <id>').description('Show one stored policy.');
  addExecutionRoutingOptions(show);
  show.option('--json', 'Emit machine-readable output.');
  show.action(async (...args: unknown[]) => {
    const impl = await import('./commands.js');
    await impl.executePolicyShowAction(args);
  });

  const remove = policy.command('remove <id>').description('Remove one stored policy.');
  addExecutionRoutingOptions(remove);
  remove.option('--json', 'Emit machine-readable output.');
  remove.action(async (...args: unknown[]) => {
    const impl = await import('./commands.js');
    await impl.executePolicyRemoveAction(args);
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
    const impl = await import('./commands.js');
    await impl.executeGrantCreateAction(args);
  });

  const list = grant.command('list').description('List grants and their live status.');
  list.action(async (...args: unknown[]) => {
    const impl = await import('./commands.js');
    await impl.executeGrantListAction(args);
  });

  const show = grant.command('show <grantId>').description('Inspect one grant.');
  show.action(async (...args: unknown[]) => {
    const impl = await import('./commands.js');
    await impl.executeGrantShowAction(args);
  });

  const revoke = grant.command('revoke <grantId>').description('Revoke one grant.');
  revoke.action(async (...args: unknown[]) => {
    const impl = await import('./commands.js');
    await impl.executeGrantRevokeAction(args);
  });

  // Bare `kavrix grant <secret>` behaves like `grant create` per the product spec.
  grant.action(async (...args: unknown[]) => {
    const impl = await import('./commands.js');
    await impl.executeGrantAction(args);
  });
}

function requireExecutablePassThrough(command: Command): void {
  // Commander awaits pre-action hooks, so the heavy guard body (coded usage
  // errors, raw-argument recovery) loads on demand and still fails the
  // action dispatch with the same error.
  command.hook('preAction', async (_hookCommand, actionCommand) => {
    const impl = await import('./commands.js');
    impl.assertExecutablePassThrough(actionCommand);
  });
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
    const impl = await import('./commands.js');
    await impl.executeAuditAction(args);
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
    .option(
      '--dry-run',
      'Validate project agent config and datastore binding without starting an agent.',
    )
    .option('--json', 'Emit a machine-readable envelope after the agent exits.');
  addExecutionRoutingOptions(agentRun);
  agentRun.action(async (...args: unknown[]) => {
    const impl = await import('./commands.js');
    await impl.executeAgentRunAction(args);
  });

  const agentExec = agent
    .command('exec')
    .description(
      'Request one authorized operation from the running Kavrix agent broker.',
    )
    .allowUnknownOption(true)
    .allowExcessArguments(true)
    .argument('<permission>', 'Permission key from the agent configuration.')
    .option(
      '--dry-run',
      'Validate the permission against project agent config without contacting a broker (fails closed on unknown permissions).',
    )
    .option('--config <path>', 'Non-secret project configuration file.')
    .option('--json', 'Emit a machine-readable envelope.');
  agentExec.action(async (...args: unknown[]) => {
    const impl = await import('./commands.js');
    await impl.executeAgentExecAction(args);
  });
}
