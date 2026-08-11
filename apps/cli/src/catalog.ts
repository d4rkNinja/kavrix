import type { Writable } from 'node:stream';

import { Command } from 'commander';
import { z } from 'zod';

import type { CliStatus, CliUseCasePorts } from './contracts.js';
import { CliUnavailableError, CliUsageError, type CliFeature } from './errors.js';
import type {
  CliInitializationDependencies,
  CliInitializationStartOptions,
} from './initialization.js';
import { executePortableKeyFileCreation } from './key-file-create.js';
import {
  executePassphraseGeneration,
  executePasswordGeneration,
  executeTotpGeneration,
} from './public-security-tools.js';
import {
  SECRET_INPUT_OPTIONS,
  type AcquiredSecret,
  type SecretInputPort,
} from './secret-input.js';
import { safeJson } from './terminal.js';
import { CLI_VERSION } from './version.js';
import type { SecretBackendPolicy } from './production/secret-backend.js';
import type { ProductionStatusRequest } from './production/status.js';

const querySchema = z.string().trim().min(1).max(512);
const schemaVersionOptionSchema = z
  .string()
  .regex(/^[1-9][0-9]*$/u)
  .transform(Number)
  .pipe(z.number().int().positive());
const fieldIndexOptionSchema = z
  .string()
  .regex(/^[1-9][0-9]*$/u)
  .transform(Number)
  .pipe(z.number().int().positive().max(10_000));
const shellSchema = z.enum(['bash', 'zsh', 'fish', 'powershell']);

export type CliCommandContext = Readonly<{
  ports?: CliUseCasePorts;
  secrets?: SecretInputPort;
  initialization?: CliInitializationDependencies;
  productionStatus?: ProductionStatusCallback;
  environment?: Readonly<Record<string, string | undefined>>;
  stdout: Writable;
  stdoutIsTty: boolean;
}>;

export type ProductionStatusCallback = (
  request: ProductionStatusRequest,
) => Promise<CliStatus>;

type CliArgumentDescriptor = Readonly<{
  syntax: string;
  description: string;
}>;

type CliOptionDescriptor = Readonly<{
  flags: string;
  description: string;
  defaultValue?: string | boolean;
}>;

export type CliCommandDescriptor = Readonly<{
  name: string;
  description: string;
  arguments?: readonly CliArgumentDescriptor[];
  options?: readonly CliOptionDescriptor[];
  children?: readonly CliCommandDescriptor[];
  execute?: (
    context: CliCommandContext,
    arguments_: readonly string[],
    options: Readonly<Record<string, unknown>>,
  ) => Promise<void>;
}>;

const jsonOption = Object.freeze({
  flags: '--json',
  description: 'Emit stable redacted JSON.',
});
const secretBackendOption = Object.freeze({
  flags: '--secret-backend <native|sealed-file>',
  description: 'Protected local storage backend.',
  defaultValue: 'native',
});
const backendPassphraseStdinOption = Object.freeze({
  flags: '--backend-passphrase-stdin',
  description: 'Read the sealed-file backend passphrase from standard input.',
});
const vaultOption = Object.freeze({
  flags: '--vault <vault-id>',
  description: 'Target an opaque vault ID.',
});
const serverOption = Object.freeze({
  flags: '--server <url>',
  description: 'Sync server base URL; defaults to CREDS_SERVER_URL when set.',
});
const versionCommand: CliCommandDescriptor = Object.freeze({
  name: 'version',
  description: 'Print the Kavrix CLI version without loading vault data.',
  execute: async (context) => {
    context.stdout.write(`${CLI_VERSION}\n`);
    await Promise.resolve();
  },
});
const secretStdoutOption = Object.freeze({
  flags: '--stdout',
  description: 'Explicitly allow secret output when standard output is redirected.',
});
const generationCommand: CliCommandDescriptor = Object.freeze({
  name: 'generate',
  description: 'Generate cryptographically random credentials locally.',
  children: [
    {
      name: 'password',
      description: 'Generate one password from bounded character-class policy.',
      options: [
        {
          flags: '--length <number>',
          description: 'Password length from 8 through 1024.',
          defaultValue: '24',
        },
        {
          flags: '--lowercase-min <number>',
          description: 'Minimum lowercase characters; zero disables the class.',
          defaultValue: '1',
        },
        {
          flags: '--uppercase-min <number>',
          description: 'Minimum uppercase characters; zero disables the class.',
          defaultValue: '1',
        },
        {
          flags: '--digits-min <number>',
          description: 'Minimum decimal digits; zero disables the class.',
          defaultValue: '1',
        },
        {
          flags: '--symbols-min <number>',
          description: 'Minimum symbols; zero disables the class.',
          defaultValue: '1',
        },
        {
          flags: '--exclude <characters>',
          description: 'Exclude unique visible ASCII characters from generation.',
        },
        secretStdoutOption,
      ],
      execute: async (context, _arguments, options) => {
        await executePasswordGeneration(context, options);
      },
    },
    {
      name: 'passphrase',
      description: 'Generate one passphrase from the reviewed local word list.',
      options: [
        {
          flags: '--words <number>',
          description: 'Word count from 6 through 24.',
          defaultValue: '8',
        },
        {
          flags: '--separator <character>',
          description: 'One supported visible separator.',
          defaultValue: '-',
        },
        {
          flags: '--capitalize',
          description: 'Capitalize exactly one randomly selected word.',
        },
        {
          flags: '--digit',
          description: 'Append one independently selected decimal digit.',
        },
        {
          flags: '--exclude-word <word...>',
          description: 'Exclude canonical word-list entries.',
        },
        secretStdoutOption,
      ],
      execute: async (context, _arguments, options) => {
        await executePassphraseGeneration(context, options);
      },
    },
  ],
});
const totpCommand: CliCommandDescriptor = Object.freeze({
  name: 'totp',
  description: 'Generate one TOTP code from a locally supplied seed.',
  options: [
    {
      flags: SECRET_INPUT_OPTIONS.totpSeed.flag,
      description: SECRET_INPUT_OPTIONS.totpSeed.description,
    },
    {
      flags: '--algorithm <algorithm>',
      description: 'TOTP digest: sha1, sha256, or sha512.',
      defaultValue: 'sha1',
    },
    {
      flags: '--digits <number>',
      description: 'TOTP width: 6, 7, or 8 digits.',
      defaultValue: '6',
    },
    {
      flags: '--period <seconds>',
      description: 'TOTP period from 5 through 3600 seconds.',
      defaultValue: '30',
    },
    {
      flags: '--time <unix-seconds>',
      description: 'Generate at an explicit bounded Unix timestamp.',
    },
    secretStdoutOption,
  ],
  execute: async (context, _arguments, options) => {
    await executeTotpGeneration(context, secretInput(context, 'totp'), options);
  },
});
const keyCommand: CliCommandDescriptor = Object.freeze({
  name: 'key',
  description: 'Create portable key files using protected local storage.',
  children: [
    {
      name: 'create',
      description: 'Create one unbound version-one portable key file.',
      options: [
        {
          flags: '--file <path>',
          description: 'New key-file path; existing files are never replaced.',
        },
        {
          flags: '--protect-with-passphrase',
          description: 'Encrypt the key file with a confirmed passphrase.',
        },
        {
          flags: '--passphrase-stdin',
          description: 'Read passphrase and confirmation as two exact stdin frames.',
        },
      ],
      execute: async (context, _arguments, options) => {
        await executePortableKeyFileCreation(
          secretInput(context, 'key create'),
          options,
        );
        context.stdout.write('Portable key file created.\n');
      },
    },
  ],
});
const initializationCommand: CliCommandDescriptor = Object.freeze({
  name: 'init',
  description: 'Initialize a vault through injected protected lifecycle adapters.',
  options: [
    serverOption,
    {
      flags: '--existing-portable',
      description: 'Import an existing portable key through a masked prompt.',
    },
    {
      flags: '--key-file <path>',
      description: 'Import through the injected protected portable-key file reader.',
    },
    {
      flags: '--key-stdin',
      description:
        'Read imported portable, then confirmations as three staged exact stdin frames.',
    },
    {
      flags: '--confirmation-stdin',
      description: 'Read portable and recovery confirmation as two exact stdin frames.',
    },
  ],
  children: [
    {
      name: 'resume',
      description: 'Resume a crash-safe initialization journal operation.',
      arguments: [
        {
          syntax: '<operation-id>',
          description: 'Opaque initialization operation identifier.',
        },
      ],
      options: [serverOption],
      execute: async (context, arguments_, options) => {
        const { parseLifecycleOperationId, renderInitializationReceipt } =
          await import('./initialization.js');
        const operationId = parseLifecycleOperationId(
          requiredArgument(arguments_[0], 'operation ID'),
        );
        const coordinator = initialization(context).coordinator;
        const serverUrl = optionString(options, 'server');
        const receipt =
          serverUrl === undefined
            ? await coordinator.resume(operationId)
            : await coordinator.resume(operationId, serverUrl);
        context.stdout.write(renderInitializationReceipt(receipt));
      },
    },
    {
      name: 'cancel',
      description: 'Cancel a safely cancellable prepared initialization operation.',
      arguments: [
        {
          syntax: '<operation-id>',
          description: 'Opaque initialization operation identifier.',
        },
      ],
      options: [serverOption],
      execute: async (context, arguments_, options) => {
        const { parseLifecycleOperationId } = await import('./initialization.js');
        const operationId = parseLifecycleOperationId(
          requiredArgument(arguments_[0], 'operation ID'),
        );
        const coordinator = initialization(context).coordinator;
        const serverUrl = optionString(options, 'server');
        if (serverUrl === undefined) {
          await coordinator.cancel(operationId);
        } else {
          await coordinator.cancel(operationId, serverUrl);
        }
        context.stdout.write('Initialization cancelled.\n');
      },
    },
  ],
  execute: async (context, _arguments, options) => {
    const { renderInitializationReceipt, startVaultInitialization } =
      await import('./initialization.js');
    const serverUrl = optionString(options, 'server');
    const dependencies = initialization(context);
    const secrets = secretInput(context, 'init');
    const startOptions = parseInitializationStartOptions(options);
    const receipt =
      serverUrl === undefined
        ? await startVaultInitialization(dependencies, secrets, startOptions)
        : await startVaultInitialization(
            dependencies,
            secrets,
            startOptions,
            serverUrl,
          );
    context.stdout.write(renderInitializationReceipt(receipt));
  },
});
const statusCommand: CliCommandDescriptor = Object.freeze({
  name: 'status',
  description: 'Show local vault and sync status without secret data.',
  options: [jsonOption, secretBackendOption, backendPassphraseStdinOption],
  execute: async (context, _arguments, options) => {
    const backendPolicy = parseStatusBackendPolicy(options);
    let rawStatus: CliStatus;
    if (context.ports !== undefined) {
      rawStatus = await context.ports.status();
    } else {
      if (context.productionStatus === undefined || context.environment === undefined) {
        throw new CliUnavailableError('status');
      }
      rawStatus = await context.productionStatus({
        backendPolicy,
        environment: context.environment,
        secrets: secretInput(context, 'status'),
      });
    }
    const [{ parseStatus }, { renderStatus }] = await Promise.all([
      import('./contracts.js'),
      import('./render.js'),
    ]);
    const status = parseStatus(rawStatus);
    context.stdout.write(renderStatus(status, optionBoolean(options, 'json')));
  },
});

export const CLI_COMMAND_CATALOG: readonly CliCommandDescriptor[] = Object.freeze([
  versionCommand,
  generationCommand,
  totpCommand,
  keyCommand,
  initializationCommand,
  statusCommand,
  {
    name: 'lock',
    description: 'Lock the active vault and clear use-case-managed secret state.',
    execute: async (context) => {
      await useCases(context, 'lock').lock();
      context.stdout.write('Vault locked.\n');
    },
  },
  {
    name: 'show',
    description: 'Show a schema-driven item with secret fields redacted.',
    arguments: [
      { syntax: '<group>', description: 'Group ID, unique name, or alias.' },
      {
        syntax: '<credential>',
        description: 'Credential ID, unique name, or alias within the group.',
      },
    ],
    options: [jsonOption],
    execute: async (context, arguments_, options) => {
      const [{ parseShowResult }, { renderShow }] = await Promise.all([
        import('./contracts.js'),
        import('./render.js'),
      ]);
      const groupQuery = parseInput(querySchema, arguments_[0], 'group query');
      const credentialQuery = parseInput(
        querySchema,
        arguments_[1],
        'credential query',
      );
      const result = parseShowResult(
        await useCases(context, 'show').show(groupQuery, credentialQuery),
      );
      context.stdout.write(renderShow(result, optionBoolean(options, 'json')));
    },
  },
  {
    name: 'copy',
    description: 'Copy one authorized credential field to the guarded clipboard.',
    arguments: [
      { syntax: '<group>', description: 'Group ID, unique name, or alias.' },
      {
        syntax: '<credential>',
        description: 'Credential ID, unique name, or alias within the group.',
      },
      {
        syntax: '<field>',
        description: 'Field ID, stable key, exact label, or unique prefix.',
      },
    ],
    options: [
      {
        flags: '--index <number>',
        description: 'Select a one-based element from a repeatable field.',
      },
    ],
    execute: async (context, arguments_, options) => {
      const [{ parseCopyReceipt }, { renderCopyReceipt }] = await Promise.all([
        import('./contracts.js'),
        import('./render.js'),
      ]);
      const groupQuery = parseInput(querySchema, arguments_[0], 'group query');
      const credentialQuery = parseInput(
        querySchema,
        arguments_[1],
        'credential query',
      );
      const fieldQuery = parseInput(querySchema, arguments_[2], 'field query');
      const rawIndex = options['index'];
      const index =
        rawIndex === undefined
          ? undefined
          : parseInput(fieldIndexOptionSchema, rawIndex, 'field index');
      const receipt = parseCopyReceipt(
        await useCases(context, 'copy').copy(
          groupQuery,
          credentialQuery,
          fieldQuery,
          index === undefined ? {} : { index },
        ),
      );
      context.stdout.write(renderCopyReceipt(receipt));
    },
  },
  {
    name: 'device',
    description: 'Manage this device and zero-knowledge enrollment.',
    children: [
      {
        name: 'invite',
        description: 'List, revoke, or redeem device invites.',
        children: [
          {
            name: 'list',
            description: 'List public invite metadata.',
            options: [vaultOption, jsonOption],
            execute: async (context, _arguments, options) => {
              const [{ parseInviteList, parseVaultId }, { renderInvites }] =
                await Promise.all([import('./contracts.js'), import('./render.js')]);
              const vaultId = parseInputString(options, 'vault', parseVaultId);
              const invites = parseInviteList(
                await useCases(context, 'device invite list').listInvites(vaultId),
              );
              context.stdout.write(
                renderInvites(invites, optionBoolean(options, 'json')),
              );
            },
          },
          {
            name: 'revoke',
            description: 'Revoke an unused invite by opaque ID.',
            arguments: [
              { syntax: '<invite-id>', description: 'Opaque invite identifier.' },
            ],
            options: [vaultOption],
            execute: async (context, arguments_, options) => {
              const { parseInviteId, parseVaultId } = await import('./contracts.js');
              const vaultId = parseInputString(options, 'vault', parseVaultId);
              const inviteId = parseInputValue(
                requiredArgument(arguments_[0], 'invite ID'),
                'invite ID',
                parseInviteId,
              );
              await useCases(context, 'device invite revoke').revokeInvite(
                vaultId,
                inviteId,
              );
              context.stdout.write('Invite revoked.\n');
            },
          },
          {
            name: 'join',
            description: 'Redeem an invite without placing its token in argv.',
            options: [
              serverOption,
              {
                flags: '--vault <vault-id>',
                description: 'Join this opaque vault ID, as named by the invite.',
              },
              {
                flags: '--schema-version <version>',
                description: 'Use the supported positive device schema version.',
                defaultValue: '1',
              },
              {
                flags: SECRET_INPUT_OPTIONS.invite.flag,
                description: SECRET_INPUT_OPTIONS.invite.description,
              },
              jsonOption,
            ],
            execute: async (context, _arguments, options) => {
              const { parseJoinResult, shapeInviteJoinRequest } =
                await import('./contracts.js');
              const serverUrl = optionString(options, 'server');
              const vaultId = requiredOption(options, 'vault', 'vault ID');
              const schemaVersion = parseInput(
                schemaVersionOptionSchema,
                requiredOption(options, 'schemaVersion', 'schema version'),
                'schema version',
              );
              // Redemption needs the invite token and the portable key that
              // unlocks the redeemed vault. Over stdin they arrive as one
              // framed batch; interactively they are two masked prompts.
              const fromStdin = optionBoolean(options, 'inviteStdin');
              const frames = await secretInput(context, 'device invite join').readBatch(
                {
                  kinds: ['invite', 'portable-key'],
                  fromStdin,
                  requireEnd: fromStdin,
                },
              );
              const inviteToken = requiredSecretFrame(frames, 0);
              const portableKey = requiredSecretFrame(frames, 1);
              const request = parseInputValue(
                [inviteToken, vaultId, schemaVersion] as const,
                'invite enrollment request',
                ([token, vault, version]) =>
                  shapeInviteJoinRequest(token, vault, version),
              );
              const inviteUseCases = useCases(context, 'device invite join');
              const result = parseJoinResult(
                serverUrl === undefined
                  ? await inviteUseCases.joinInvite(request, portableKey)
                  : await inviteUseCases.joinInvite(request, portableKey, serverUrl),
              );
              const safe = { vaultId: result.vaultId, deviceId: result.deviceId };
              context.stdout.write(
                optionBoolean(options, 'json')
                  ? safeJson(safe)
                  : `Device joined vault ${result.vaultId}.\n`,
              );
            },
          },
        ],
      },
    ],
  },
  completionCommand(() => CLI_COMMAND_CATALOG),
]);

/**
 * Explicit public surface for the packed executable. These are the only command
 * families with production composition today; the internal catalog above keeps
 * the remaining dependency-injected commands available to integration tests.
 */
export const PUBLIC_CLI_COMMAND_CATALOG: readonly CliCommandDescriptor[] =
  Object.freeze([
    versionCommand,
    generationCommand,
    totpCommand,
    keyCommand,
    statusCommand,
    completionCommand(() => PUBLIC_CLI_COMMAND_CATALOG),
  ]);

function completionCommand(
  catalog: () => readonly CliCommandDescriptor[],
): CliCommandDescriptor {
  return Object.freeze({
    name: 'completion',
    description: 'Print static shell completion without reading vault data.',
    arguments: [
      {
        syntax: '<shell>',
        description: 'One of bash, zsh, fish, or powershell.',
      },
    ],
    execute: async (context, arguments_) => {
      const shell = parseInput(shellSchema, arguments_[0], 'shell');
      // Resolved on invocation: the published catalog cannot reference itself
      // while it is still being constructed.
      context.stdout.write(renderCompletion(shell, catalog()));
      await Promise.resolve();
    },
  });
}

export function registerCommandCatalog(
  program: Command,
  descriptors: readonly CliCommandDescriptor[],
  context: CliCommandContext,
): void {
  for (const descriptor of descriptors) {
    const command = program
      .command(descriptor.name)
      .description(descriptor.description);
    command.allowExcessArguments(false);
    for (const argument of descriptor.arguments ?? []) {
      command.argument(argument.syntax, argument.description);
    }
    for (const option of descriptor.options ?? []) {
      command.option(option.flags, option.description, option.defaultValue);
    }
    if (descriptor.children !== undefined) {
      registerCommandCatalog(command, descriptor.children, context);
    }
    if (descriptor.execute !== undefined) {
      const argumentCount = descriptor.arguments?.length ?? 0;
      command.action(async (...actionArguments: unknown[]) => {
        const invokedCommand = actionArguments.at(-1);
        if (!(invokedCommand instanceof Command)) {
          throw new Error('Commander did not supply the invoked command context');
        }
        const positionals = actionArguments
          .slice(0, argumentCount)
          .map((value) => (typeof value === 'string' ? value : ''));
        await descriptor.execute?.(
          context,
          positionals,
          invokedCommand.optsWithGlobals(),
        );
      });
    } else {
      command.action(() => {
        command.outputHelp();
      });
    }
  }
}

function requiredOption(
  options: Readonly<Record<string, unknown>>,
  key: string,
  label: string,
): string {
  const value = options[key];
  if (typeof value !== 'string' || value.length === 0) {
    throw new CliUsageError(`A ${label} is required.`);
  }
  return value;
}

function useCases(context: CliCommandContext, feature: CliFeature): CliUseCasePorts {
  if (context.ports === undefined) throw new CliUnavailableError(feature);
  return context.ports;
}

function requiredSecretFrame(
  frames: readonly AcquiredSecret[],
  index: number,
): AcquiredSecret {
  const frame = frames[index];
  if (frame === undefined)
    throw new CliUsageError('Secret input used invalid framing.');
  return frame;
}

function secretInput(context: CliCommandContext, feature: CliFeature): SecretInputPort {
  if (context.secrets === undefined) {
    throw new CliUnavailableError(feature);
  }
  return context.secrets;
}

function initialization(context: CliCommandContext): CliInitializationDependencies {
  if (context.initialization === undefined) throw new CliUnavailableError('init');
  return context.initialization;
}

function requiredArgument(value: string | undefined, label: string): string {
  if (value === undefined || value.length === 0) {
    throw new CliUsageError(`A ${label} is required.`);
  }
  return value;
}

function optionBoolean(
  options: Readonly<Record<string, unknown>>,
  key: string,
): boolean {
  return options[key] === true;
}

/** Reads an optional string option and rejects an explicitly empty value. */
function optionString(
  options: Readonly<Record<string, unknown>>,
  key: string,
): string | undefined {
  const value = options[key];
  if (value === undefined) return undefined;
  if (typeof value !== 'string' || value.length === 0) {
    throw new CliUsageError('The server URL is invalid.');
  }
  return value;
}

function parseStatusBackendPolicy(
  options: Readonly<Record<string, unknown>>,
): SecretBackendPolicy {
  const kind = options['secretBackend'];
  const stdinValue = options['backendPassphraseStdin'];
  if (
    (kind !== 'native' && kind !== 'sealed-file') ||
    (stdinValue !== undefined && typeof stdinValue !== 'boolean')
  ) {
    throw new CliUsageError('The protected secret backend policy is invalid.');
  }
  const passphraseFromStdin = stdinValue === true;
  if (kind === 'native') {
    if (passphraseFromStdin) {
      throw new CliUsageError(
        '--backend-passphrase-stdin requires --secret-backend sealed-file.',
      );
    }
    return { kind: 'native' };
  }
  return { kind: 'sealed-file', passphraseFromStdin };
}

function parseInitializationStartOptions(
  options: Readonly<Record<string, unknown>>,
): CliInitializationStartOptions {
  const masked = optionBoolean(options, 'existingPortable');
  const stdin = optionBoolean(options, 'keyStdin');
  const keyFile = options['keyFile'];
  const confirmationFromStdin = optionBoolean(options, 'confirmationStdin');
  const sourceCount = Number(masked) + Number(stdin) + Number(keyFile !== undefined);
  if (sourceCount > 1) {
    throw new CliUsageError('Choose exactly one existing portable-key source.');
  }
  if (stdin) {
    if (confirmationFromStdin) {
      throw new CliUsageError('--key-stdin already includes both confirmation frames.');
    }
    return { source: 'stdin-protocol', confirmationFromStdin: true };
  }
  if (masked) {
    if (confirmationFromStdin) {
      throw new CliUsageError('Masked portable import requires masked confirmation.');
    }
    return { source: 'masked-portable', confirmationFromStdin: false };
  }
  if (keyFile !== undefined) {
    if (typeof keyFile !== 'string') {
      throw new CliUsageError('The portable key file path is invalid.');
    }
    return { source: 'key-file', path: keyFile, confirmationFromStdin };
  }
  return { source: 'generated', confirmationFromStdin };
}

function parseInputString<TResult>(
  options: Readonly<Record<string, unknown>>,
  key: string,
  parser: (value: string) => TResult,
): TResult {
  return parseInputValue(requiredOption(options, key, key), key, parser);
}

function parseInputValue<TInput, TResult>(
  value: TInput,
  label: string,
  parser: (input: TInput) => TResult,
): TResult {
  try {
    return parser(value);
  } catch {
    throw new CliUsageError(`The ${label} is invalid.`);
  }
}

function parseInput<TOutput>(
  schema: z.ZodType<TOutput>,
  value: unknown,
  label: string,
): TOutput {
  const parsed = schema.safeParse(value);
  if (!parsed.success) throw new CliUsageError(`The ${label} is invalid.`);
  return parsed.data;
}

function renderCompletion(
  shell: z.infer<typeof shellSchema>,
  descriptors: readonly CliCommandDescriptor[],
): string {
  const topLevel = descriptors.map(({ name }) => name).join(' ');
  switch (shell) {
    case 'bash':
      return `_creds_complete() { COMPREPLY=( $(compgen -W '${topLevel}' -- "\${COMP_WORDS[COMP_CWORD]}") ); }\ncomplete -F _creds_complete creds\n`;
    case 'zsh':
      return `#compdef creds\n_arguments '1:command:(${topLevel})'\n`;
    case 'fish':
      return `complete -c creds -f -n '__fish_use_subcommand' -a '${topLevel}'\n`;
    case 'powershell':
      return `Register-ArgumentCompleter -Native -CommandName creds -ScriptBlock { param($wordToComplete) '${topLevel}'.Split(' ') | Where-Object { $_ -like "$wordToComplete*" } }\n`;
  }
}
