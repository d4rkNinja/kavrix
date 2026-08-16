import type { Readable, Writable } from 'node:stream';

import { Command } from 'commander';
import {
  controlListPageQuerySchema,
  deviceIdSchema,
  inviteIssueRequestSchema,
  keySlotIdSchema,
  type GroupPayload,
  type GroupTemplate,
  type InviteIssueRequest,
  type ItemPayload,
  type KeySlotId,
  type TemplateMigrationPlan,
  transferCollisionStrategySchema,
  vaultIdSchema,
} from '@kavrix/schemas';
import { z } from 'zod';
import type { VaultRootKey } from '@kavrix/crypto';
import type { SqliteSyncLocalStore } from '@kavrix/local-store';
import type { LifecycleOperationId } from '@kavrix/client/cli-contracts';

import {
  cliKeySlotListSchema,
  cliKeySlotResultSchema,
  cliPortableKeyRotationResultSchema,
  parseRecoverRequest,
  type CliAttachmentDeleteResult,
  type CliAttachmentDownloadResult,
  type CliAttachmentSummary,
  type CliAttachmentUploadResult,
  type CliAuditEventDetail,
  type CliAuditEventPage,
  type CliHistoryDetail,
  type CliHistoryDiff,
  type CliHistoryRestoreResult,
  type CliHistorySummary,
  type CliRecoverResult,
  type CliRecoveryCodeListResult,
  type CliRecoveryCodeRevealResult,
  type CliRecoveryCodeUseResult,
  type CliStatus,
  type CliTemplateMigrationApplyResult,
  type CliTemplateMigrationStatusResult,
  type CliTemplateSummary,
  type CliUseCasePorts,
} from './contracts.js';
import {
  CliRunFailedError,
  CliUnavailableError,
  CliUsageError,
  type CliFeature,
} from './errors.js';
import type {
  CliInitializationDependencies,
  CliInitializationStartOptions,
} from './initialization.js';
import type {
  CliFieldMutationResult,
  CliFieldReadResult,
} from './mutation-contracts.js';
import { executePortableKeyFileCreation } from './key-file-create.js';
import {
  executePassphraseGeneration,
  executePasswordGeneration,
  executeTotpGeneration,
} from './public-security-tools.js';
import {
  SECRET_INPUT_OPTIONS,
  acquiredSecretSchema,
  type AcquiredSecret,
  type SecretInputPort,
} from './secret-input.js';
import { safeJson, sanitizeTerminalText } from './terminal.js';
import { CLI_VERSION } from './version.js';
import type { SecretBackendPolicy } from './production/secret-backend.js';
import type { ProductionStatusRequest } from './production/status.js';
import type { ProductionUnlockedContext } from './production/unlock.js';
import type {
  KeySlotOperation,
  NewSlotCredential,
  SlotReauthentication,
} from './production/slot-lifecycle.js';
import type { PortableKeyRotationOperation } from './production/portable-key-rotation.js';

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
const revisionOptionSchema = z
  .string()
  .regex(/^(?:0|[1-9][0-9]*)$/u)
  .transform(Number)
  .pipe(z.number().int().nonnegative().max(Number.MAX_SAFE_INTEGER));
/**
 * One-based record revision an optimistic write must match.
 *
 * Revision zero never identifies a stored record, so a caller that passes it
 * has miscomputed the expectation and must be rejected rather than guessed at.
 */
const expectedRevisionOptionSchema = z
  .string()
  .regex(/^[1-9][0-9]*$/u)
  .transform(Number)
  .pipe(z.number().int().positive().max(Number.MAX_SAFE_INTEGER));
const conflictStrategySchema = z.enum(['keep-local', 'accept-remote']);
const shellSchema = z.enum(['bash', 'zsh', 'fish', 'powershell']);
const inviteExpiryOptionSchema = z
  .string()
  .regex(/^(?:[6-9][0-9]|[1-9][0-9]{2,4}|[1-7][0-9]{4}|8[0-5][0-9]{3}|86400)$/u)
  .transform(Number)
  .pipe(z.number().int().min(60).max(86_400));
const DEFAULT_INVITE_SCOPES = ['sync:read', 'sync:write'] as const;

export type CliCommandContext = Readonly<{
  ports?: CliUseCasePorts;
  secrets?: SecretInputPort;
  initialization?: CliInitializationDependencies;
  productionStatus?: ProductionStatusCallback;
  environment?: Readonly<Record<string, string | undefined>>;
  stdin: Readable;
  stderr: Writable;
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
  /** Collect every occurrence instead of keeping only the last one. */
  repeatable?: boolean;
}>;

export type CliCommandDescriptor = Readonly<{
  name: string;
  description: string;
  arguments?: readonly CliArgumentDescriptor[];
  options?: readonly CliOptionDescriptor[];
  /**
   * Relay every argument from the first operand onward to this command's own
   * handler. Required by commands that hand arguments to another program, where
   * a flag claimed by this CLI would silently never reach that program.
   */
  passThrough?: boolean;
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
const keyFilePassphraseStdinOption = Object.freeze({
  flags: '--key-file-passphrase-stdin',
  description:
    'Read a protected portable-key file passphrase from the leading stdin frame.',
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
    {
      name: 'slot',
      description: 'List and manage authenticated vault unlock slots.',
      children: [
        {
          name: 'list',
          description: 'List redacted public unlock-slot metadata.',
          options: [jsonOption, secretBackendOption, backendPassphraseStdinOption],
          execute: async (context, _arguments, options) => {
            const raw =
              context.ports?.listKeySlots === undefined
                ? await executeProductionKeySlotOperation(context, options, {
                    kind: 'list',
                  })
                : await context.ports.listKeySlots();
            const { renderKeySlots } = await import('./render.js');
            context.stdout.write(
              renderKeySlots(
                cliKeySlotListSchema.parse(raw),
                optionBoolean(options, 'json'),
              ),
            );
          },
        },
        {
          name: 'create',
          description:
            'Create a portable, passphrase, recovery, or device unlock slot.',
          arguments: [
            {
              syntax: '<portable-key|passphrase|recovery-key|device-key>',
              description: 'Credential type for the new slot.',
            },
          ],
          options: slotLifecycleOptions(true),
          execute: async (context, arguments_, options) => {
            const slotType = parseInput(
              z.enum(['portable-key', 'passphrase', 'recovery-key', 'device-key']),
              requiredArgument(arguments_[0], 'slot type'),
              'slot type',
            );
            const operation = await acquireCreateSlotOperation(
              context,
              options,
              slotType,
            );
            const raw =
              context.ports?.createKeySlot === undefined
                ? await executeProductionKeySlotOperation(context, options, operation)
                : await context.ports.createKeySlot(operation);
            const { renderKeySlotResult } = await import('./render.js');
            context.stdout.write(
              renderKeySlotResult(
                cliKeySlotResultSchema.parse(raw),
                optionBoolean(options, 'json'),
              ),
            );
          },
        },
        {
          name: 'disable',
          description:
            'Remove a local device-slot secret without changing the server record.',
          arguments: [
            { syntax: '<slot-id>', description: 'Opaque unlock-slot identifier.' },
          ],
          options: slotLifecycleOptions(false),
          execute: async (context, arguments_, options) => {
            const slotId = parseInputValue(
              requiredArgument(arguments_[0], 'slot ID'),
              'slot ID',
              (value) => keySlotIdSchema.parse(value),
            );
            const operation = await acquireLifecycleSlotOperation(context, options, {
              kind: 'disable',
              slotId,
            });
            const raw =
              context.ports?.disableKeySlot === undefined
                ? await executeProductionKeySlotOperation(context, options, operation)
                : await context.ports.disableKeySlot(slotId);
            const { renderKeySlotResult } = await import('./render.js');
            context.stdout.write(
              renderKeySlotResult(
                cliKeySlotResultSchema.parse(raw),
                optionBoolean(options, 'json'),
              ),
            );
          },
        },
        {
          name: 'revoke',
          description: 'Revoke a server unlock slot after last-slot protection checks.',
          arguments: [
            { syntax: '<slot-id>', description: 'Opaque unlock-slot identifier.' },
          ],
          options: slotLifecycleOptions(false),
          execute: async (context, arguments_, options) => {
            const slotId = parseInputValue(
              requiredArgument(arguments_[0], 'slot ID'),
              'slot ID',
              (value) => keySlotIdSchema.parse(value),
            );
            const operation = await acquireLifecycleSlotOperation(context, options, {
              kind: 'revoke',
              slotId,
            });
            const raw =
              context.ports?.revokeKeySlot === undefined
                ? await executeProductionKeySlotOperation(context, options, operation)
                : await context.ports.revokeKeySlot(slotId, operation);
            const { renderKeySlotResult } = await import('./render.js');
            context.stdout.write(
              renderKeySlotResult(
                cliKeySlotResultSchema.parse(raw),
                optionBoolean(options, 'json'),
              ),
            );
          },
        },
      ],
    },
    {
      name: 'rotate',
      description: 'Rotate one portable-key wrapping credential with crash resume.',
      options: portableKeyRotationOptions(),
      execute: async (context, _arguments, options) => {
        const operation = await acquirePortableKeyRotationStart(context, options);
        const raw = await executeProductionPortableKeyRotationOperation(
          context,
          options,
          operation,
        );
        const { renderPortableKeyRotation } = await import('./render.js');
        context.stdout.write(
          renderPortableKeyRotation(
            cliPortableKeyRotationResultSchema.parse(raw),
            optionBoolean(options, 'json'),
          ),
        );
      },
      children: [
        {
          name: 'resume',
          description: 'Resume an interrupted portable-key rotation.',
          arguments: [
            {
              syntax: '<operation-id>',
              description: 'Opaque rotation operation identifier.',
            },
          ],
          options: portableKeyRotationResumeOptions(),
          execute: async (context, arguments_, options) => {
            rejectRotationStdinCollision(options);
            const operation: PortableKeyRotationOperation = {
              kind: 'resume',
              operationId: await parseRotationOperationId(arguments_[0]),
              replacementFile: {
                path: requiredOption(
                  options,
                  'replacementFile',
                  'replacement key file',
                ),
                passphraseFromStdin: optionBoolean(
                  options,
                  'replacementFilePassphraseStdin',
                ),
              },
              reauthentication: await acquireReauthentication(context, options),
            };
            const raw = await executeProductionPortableKeyRotationOperation(
              context,
              options,
              operation,
            );
            const { renderPortableKeyRotation } = await import('./render.js');
            context.stdout.write(
              renderPortableKeyRotation(
                cliPortableKeyRotationResultSchema.parse(raw),
                optionBoolean(options, 'json'),
              ),
            );
          },
        },
        {
          name: 'list',
          description: 'List redacted portable-key rotation journal entries.',
          options: [jsonOption, secretBackendOption, backendPassphraseStdinOption],
          execute: async (context, _arguments, options) => {
            const raw = await executeProductionPortableKeyRotationOperation(
              context,
              options,
              { kind: 'list' },
            );
            const { renderPortableKeyRotation } = await import('./render.js');
            context.stdout.write(
              renderPortableKeyRotation(
                cliPortableKeyRotationResultSchema.parse(raw),
                optionBoolean(options, 'json'),
              ),
            );
          },
        },
      ],
    },
  ],
});
const initializationCommand: CliCommandDescriptor = Object.freeze({
  name: 'init',
  description: 'Initialize a vault through injected protected lifecycle adapters.',
  options: [
    serverOption,
    secretBackendOption,
    backendPassphraseStdinOption,
    {
      flags: '--existing-portable',
      description: 'Import an existing portable key through a masked prompt.',
    },
    {
      flags: '--key-file <path>',
      description: 'Import through the injected protected portable-key file reader.',
    },
    keyFilePassphraseStdinOption,
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
      options: [serverOption, secretBackendOption, backendPassphraseStdinOption],
      execute: async (context, arguments_, options) => {
        const { parseLifecycleOperationId, renderInitializationReceipt } =
          await import('./initialization.js');
        const operationId = parseLifecycleOperationId(
          requiredArgument(arguments_[0], 'operation ID'),
        );
        const serverUrl = optionString(options, 'server');
        const receipt = await withInitialization(context, options, (deps) =>
          serverUrl === undefined
            ? deps.coordinator.resume(operationId)
            : deps.coordinator.resume(operationId, serverUrl),
        );
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
      options: [serverOption, secretBackendOption, backendPassphraseStdinOption],
      execute: async (context, arguments_, options) => {
        const { parseLifecycleOperationId } = await import('./initialization.js');
        const operationId = parseLifecycleOperationId(
          requiredArgument(arguments_[0], 'operation ID'),
        );
        const serverUrl = optionString(options, 'server');
        await withInitialization(context, options, (deps) =>
          serverUrl === undefined
            ? deps.coordinator.cancel(operationId)
            : deps.coordinator.cancel(operationId, serverUrl),
        );
        context.stdout.write('Initialization cancelled.\n');
      },
    },
  ],
  execute: async (context, _arguments, options) => {
    const { renderInitializationReceipt, startVaultInitialization } =
      await import('./initialization.js');
    const serverUrl = optionString(options, 'server');
    const secrets = secretInput(context, 'init');
    const startOptions = parseInitializationStartOptions(options);
    const receipt = await withInitialization(context, options, (deps) =>
      serverUrl === undefined
        ? startVaultInitialization(deps, secrets, startOptions)
        : startVaultInitialization(deps, secrets, startOptions, serverUrl),
    );
    if (context.initialization === undefined && context.environment !== undefined) {
      const { executeProductionSync } = await import('./production/sync.js');
      await executeProductionSync({
        environment: context.environment,
        secrets,
        backendPolicy: parseStatusBackendPolicy(options),
      });
    }
    context.stdout.write(renderInitializationReceipt(receipt));
  },
});
const connectCommand: CliCommandDescriptor = Object.freeze({
  name: 'connect',
  description: 'Connect an empty local data home to an existing enrolled vault.',
  options: [
    serverOption,
    vaultOption,
    {
      flags: '--device <device-id>',
      description: 'Existing enrolled device ID for the opaque vault.',
    },
    jsonOption,
    secretBackendOption,
    backendPassphraseStdinOption,
  ],
  execute: async (context, _arguments, options) => {
    const configuredServer =
      optionString(options, 'server') ??
      (context.environment ?? process.env)['CREDS_SERVER_URL'];
    if (configuredServer === undefined || configuredServer.length === 0) {
      throw new CliUsageError('A server URL is required.');
    }
    const { parseConnectRequest, parseConnectResult } = await import('./contracts.js');
    const request = parseConnectRequest({
      serverUrl: configuredServer,
      vaultId: parseInputString(options, 'vault', (value) =>
        vaultIdSchema.parse(value),
      ),
      deviceId: parseInputString(options, 'device', (value) =>
        deviceIdSchema.parse(value),
      ),
    });
    let rawResult: unknown;
    if (context.ports?.connect !== undefined) {
      rawResult = await context.ports.connect(request);
    } else {
      const { executeProductionConnect } = await import('./production/connect.js');
      rawResult = await executeProductionConnect({
        environment: context.environment ?? process.env,
        secrets: secretInput(context, 'connect'),
        backendPolicy: parseStatusBackendPolicy(options),
        request,
      });
    }
    const { renderConnect } = await import('./render.js');
    context.stdout.write(
      renderConnect(parseConnectResult(rawResult), optionBoolean(options, 'json')),
    );
  },
});
const recoverCommand: CliCommandDescriptor = Object.freeze({
  name: 'recover',
  description: 'Recover an empty local data home with an invite and portable key.',
  options: [
    serverOption,
    vaultOption,
    {
      flags: '--key-file <path>',
      description:
        'Read a guarded unprotected or passphrase-protected portable key file.',
    },
    {
      flags: '--portable-key-stdin',
      description: 'Read the portable key from an explicit stdin frame.',
    },
    keyFilePassphraseStdinOption,
    {
      flags: '--invite-stdin',
      description: 'Read the invite token from an explicit stdin frame.',
    },
    jsonOption,
    secretBackendOption,
    backendPassphraseStdinOption,
  ],
  children: [
    {
      name: 'resume',
      description: 'Resume a durable recovery operation.',
      arguments: [
        {
          syntax: '<operation-id>',
          description: 'Opaque recovery operation identifier.',
        },
      ],
      options: [
        serverOption,
        vaultOption,
        {
          flags: '--key-file <path>',
          description:
            'Read a guarded portable key file when slot setup is incomplete.',
        },
        {
          flags: '--portable-key-stdin',
          description: 'Read the portable key from an explicit stdin frame.',
        },
        keyFilePassphraseStdinOption,
        jsonOption,
        secretBackendOption,
        backendPassphraseStdinOption,
      ],
      execute: async (context, arguments_, options) => {
        const { parseRecoverResult } = await import('./contracts.js');
        const request = parseRecoverRequestFromOptions(
          options,
          context.environment ?? process.env,
        );
        const operationId = await parseRecoveryOperationId(arguments_[0]);
        const source = parseRecoverySourceOptions(options, true);
        if (source.inviteFromStdin) {
          throw new CliUsageError(
            '--invite-stdin is valid only when starting recovery.',
          );
        }
        if (context.environment === undefined) {
          throw new CliUnavailableError('recover');
        }
        const { executeProductionRecovery } = await import('./production/recovery.js');
        const raw = await executeProductionRecovery({
          environment: context.environment,
          secrets: secretInput(context, 'recover'),
          backendPolicy: parseStatusBackendPolicy(options),
          request,
          operationId,
          ...(source.keyFilePath === undefined
            ? {}
            : { keyFilePath: source.keyFilePath }),
          portableKeyFromStdin: source.portableKeyFromStdin,
          keyFilePassphraseFromStdin: source.keyFilePassphraseFromStdin,
        });
        const { renderRecover } = await import('./render.js');
        context.stdout.write(
          renderRecover(parseRecoverResult(raw), optionBoolean(options, 'json')),
        );
      },
    },
    {
      name: 'cancel',
      description: 'Cancel a prepared recovery operation before network use.',
      arguments: [
        {
          syntax: '<operation-id>',
          description: 'Opaque recovery operation identifier.',
        },
      ],
      options: [
        serverOption,
        vaultOption,
        secretBackendOption,
        backendPassphraseStdinOption,
      ],
      execute: async (context, arguments_, options) => {
        if (context.environment === undefined) {
          throw new CliUnavailableError('recover');
        }
        const { executeProductionRecoveryCancel } =
          await import('./production/recovery.js');
        const operationId = await parseRecoveryOperationId(arguments_[0]);
        await executeProductionRecoveryCancel({
          environment: context.environment,
          secrets: secretInput(context, 'recover'),
          backendPolicy: parseStatusBackendPolicy(options),
          request: parseRecoverRequestFromOptions(
            options,
            context.environment ?? process.env,
          ),
          operationId,
        });
        context.stdout.write('Recovery cancelled.\n');
      },
    },
  ],
  execute: async (context, _arguments, options) => {
    const result = await executeRecoveryStart(context, options, 'recover');
    const { renderRecover } = await import('./render.js');
    context.stdout.write(renderRecover(result, optionBoolean(options, 'json')));
  },
});

const deviceJoinCommand: CliCommandDescriptor = Object.freeze({
  name: 'join',
  description: 'Join an existing vault with an invite and portable key.',
  options: recoverCommand.options ?? [],
  children: (recoverCommand.children ?? []).map((child) => ({
    ...child,
    description:
      child.name === 'resume'
        ? 'Resume a durable device-join operation.'
        : 'Cancel a prepared device-join operation before network use.',
  })),
  execute: async (context, _arguments, options) => {
    const result = await executeRecoveryStart(context, options, 'device join');
    const { renderDeviceJoin } = await import('./render.js');
    context.stdout.write(renderDeviceJoin(result, optionBoolean(options, 'json')));
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

const unlockCommand: CliCommandDescriptor = Object.freeze({
  name: 'unlock',
  description: 'Verify vault unlock material without leaving an unlocked daemon.',
  options: [
    secretBackendOption,
    backendPassphraseStdinOption,
    {
      flags: '--check',
      description: 'Verify unlock material and immediately relock.',
    },
  ],
  execute: async (context, _arguments, options) => {
    const check = optionBoolean(options, 'check');
    if (!check) {
      throw new CliUsageError('The --check flag is required for unlock verification.');
    }
    if (context.ports !== undefined) {
      await context.ports.status();
    } else {
      if (context.environment === undefined) {
        throw new CliUnavailableError('unlock');
      }
      const backendPolicy = parseStatusBackendPolicy(options);
      const { runProductionUnlocked } = await import('./production/unlock.js');
      await runProductionUnlocked(
        {
          environment: context.environment,
          secrets: secretInput(context, 'unlock'),
          backendPolicy,
          unlockMethod: { kind: 'remembered-device' },
        },
        async () => Promise.resolve(),
      );
    }
    context.stdout.write('Vault unlock verified and relocked.\n');
  },
});

const lockCommand: CliCommandDescriptor = Object.freeze({
  name: 'lock',
  description: 'Lock the active vault and clear use-case-managed secret state.',
  options: [secretBackendOption, backendPassphraseStdinOption],
  execute: async (context, _arguments, options) => {
    if (context.ports !== undefined) {
      await context.ports.lock();
    } else {
      if (context.environment === undefined) {
        throw new CliUnavailableError('lock');
      }
      const backendPolicy = parseStatusBackendPolicy(options);
      const { runProductionLock } = await import('./production/unlock.js');
      await runProductionLock({
        environment: context.environment,
        secrets: secretInput(context, 'lock'),
        backendPolicy,
      });
    }
    context.stdout.write('Vault locked.\n');
  },
});

async function unwrapVaultRootKeyFromContext(
  unlocked: ProductionUnlockedContext,
): Promise<VaultRootKey> {
  const { unwrapRememberedDeviceRootKey } = await import('./production/unlock.js');
  return unwrapRememberedDeviceRootKey(unlocked);
}

/**
 * Opens the unlocked production store, derives the vault root key, runs the
 * bounded operation, and always zeroizes the derived root key on exit. The
 * operation must not retain the root key or store beyond its promise.
 *
 * Zeroization is registered on the session as well as run in the local `finally`,
 * so the key is wiped even when the invocation ends on a deadline or a signal
 * while the operation is still pending. Wiping twice is harmless; not wiping once
 * is not.
 */
async function withUnlockedVault<Output>(
  context: CliCommandContext,
  feature: CliFeature,
  options: Readonly<Record<string, unknown>>,
  operation: (
    unlocked: ProductionUnlockedContext,
    store: SqliteSyncLocalStore,
    rootKey: VaultRootKey,
  ) => Promise<Output>,
): Promise<Output> {
  if (context.environment === undefined) {
    throw new CliUnavailableError(feature);
  }
  const backendPolicy = parseStatusBackendPolicy(options);
  const { runProductionUnlocked } = await import('./production/unlock.js');
  const { zeroize } = await import('@kavrix/crypto');
  return runProductionUnlocked(
    {
      environment: context.environment,
      secrets: secretInput(context, feature),
      backendPolicy,
    },
    async (unlocked) => {
      const store = await unlocked.environment.openSyncStore(unlocked.profile);
      const rootKey = await unwrapVaultRootKeyFromContext(unlocked);
      unlocked.session.register('vault root key', () => {
        zeroize(rootKey);
      });
      // A proven device-key unwrap is the credential proof that opens the
      // reauthentication window; it closes again the moment the key is gone.
      unlocked.session.authorize();
      try {
        return await operation(unlocked, store, rootKey);
      } finally {
        zeroize(rootKey);
        unlocked.session.revokeAuthorization();
      }
    },
  );
}

const templateCommand: CliCommandDescriptor = Object.freeze({
  name: 'template',
  description: 'Manage reusable schema templates.',
  options: [secretBackendOption, backendPassphraseStdinOption],
  children: [
    {
      name: 'list',
      description: 'List available built-in and group templates.',
      options: [jsonOption, secretBackendOption, backendPassphraseStdinOption],
      execute: async (context, _arguments, options) => {
        let templates: readonly CliTemplateSummary[];
        if (context.ports?.listTemplates !== undefined) {
          templates = await context.ports.listTemplates();
        } else {
          const { executeProductionListTemplates } =
            await import('./production/mutations.js');
          templates = await withUnlockedVault(
            context,
            'template list',
            options,
            async (unlocked, store, rootKey) =>
              executeProductionListTemplates({
                source: store,
                vaultId: unlocked.profile.vaultId,
                rootKey,
              }),
          );
        }
        const { renderTemplateList } = await import('./render.js');
        context.stdout.write(
          renderTemplateList(templates, optionBoolean(options, 'json')),
        );
      },
    },
    {
      name: 'inspect',
      description: 'Inspect a template schema definition.',
      arguments: [
        {
          syntax: '<query>',
          description: 'Template key, name, ID, or group name.',
        },
      ],
      options: [jsonOption, secretBackendOption, backendPassphraseStdinOption],
      execute: async (context, arguments_, options) => {
        const query = requiredArgument(arguments_[0], 'template query');
        let template: GroupTemplate;
        if (context.ports?.inspectTemplate !== undefined) {
          template = await context.ports.inspectTemplate(query);
        } else {
          const { executeProductionInspectTemplate } =
            await import('./production/mutations.js');
          template = await withUnlockedVault(
            context,
            'template inspect',
            options,
            async (unlocked, store, rootKey) =>
              executeProductionInspectTemplate(
                {
                  source: store,
                  vaultId: unlocked.profile.vaultId,
                  rootKey,
                },
                query,
              ),
          );
        }
        const { renderTemplateInspect } = await import('./render.js');
        context.stdout.write(
          renderTemplateInspect(template, optionBoolean(options, 'json')),
        );
      },
    },
    {
      name: 'show',
      description: 'Alias for template inspect.',
      arguments: [
        {
          syntax: '<query>',
          description: 'Template key, name, ID, or group name.',
        },
      ],
      options: [jsonOption, secretBackendOption, backendPassphraseStdinOption],
      execute: async (context, arguments_, options) => {
        const query = requiredArgument(arguments_[0], 'template query');
        let template: GroupTemplate;
        if (context.ports?.inspectTemplate !== undefined) {
          template = await context.ports.inspectTemplate(query);
        } else {
          const { executeProductionInspectTemplate } =
            await import('./production/mutations.js');
          template = await withUnlockedVault(
            context,
            'template inspect',
            options,
            async (unlocked, store, rootKey) =>
              executeProductionInspectTemplate(
                {
                  source: store,
                  vaultId: unlocked.profile.vaultId,
                  rootKey,
                },
                query,
              ),
          );
        }
        const { renderTemplateInspect } = await import('./render.js');
        context.stdout.write(
          renderTemplateInspect(template, optionBoolean(options, 'json')),
        );
      },
    },
    {
      name: 'create',
      description: 'Create a reusable template container.',
      arguments: [{ syntax: '<name>', description: 'Template / group name.' }],
      options: [
        { flags: '--description <text>', description: 'Optional description.' },
        {
          flags: '--from <template>',
          description: 'Built-in template key or existing group template.',
        },
        secretBackendOption,
        backendPassphraseStdinOption,
      ],
      execute: async (context, arguments_, options) => {
        const name = requiredArgument(arguments_[0], 'template name');
        const description = optionString(options, 'description');
        const fromTemplate = optionString(options, 'from');
        const { cliCreateTemplateRequestSchema } =
          await import('./mutation-contracts.js');
        const request = cliCreateTemplateRequestSchema.parse({
          name,
          ...(description ? { description } : {}),
          ...(fromTemplate ? { fromTemplate } : {}),
        });

        if (context.ports?.createTemplate !== undefined) {
          await context.ports.createTemplate(request);
        } else {
          const { executeProductionCreateTemplate } =
            await import('./production/mutations.js');
          await withUnlockedVault(
            context,
            'template create',
            options,
            async (unlocked, store, rootKey) => {
              await executeProductionCreateTemplate(
                {
                  source: store,
                  queue: store,
                  vaultId: unlocked.profile.vaultId,
                  rootKey,
                },
                request,
              );
            },
          );
        }
        context.stdout.write(`Template "${request.name}" created.\n`);
      },
    },
    {
      name: 'edit',
      description: 'Edit a template name or description.',
      arguments: [{ syntax: '<query>', description: 'Group name or ID.' }],
      options: [
        { flags: '--name <text>', description: 'Updated template name.' },
        { flags: '--description <text>', description: 'Updated description.' },
        secretBackendOption,
        backendPassphraseStdinOption,
      ],
      execute: async (context, arguments_, options) => {
        const groupQuery = requiredArgument(arguments_[0], 'group query');
        const name = optionString(options, 'name');
        const description = optionString(options, 'description');
        const { cliUpdateTemplateRequestSchema } =
          await import('./mutation-contracts.js');
        const request = cliUpdateTemplateRequestSchema.parse({
          groupQuery,
          ...(name ? { name } : {}),
          ...(description ? { description } : {}),
        });

        if (context.ports?.updateTemplate !== undefined) {
          await context.ports.updateTemplate(request);
        } else {
          const { executeProductionUpdateTemplate } =
            await import('./production/mutations.js');
          await withUnlockedVault(
            context,
            'template edit',
            options,
            async (unlocked, store, rootKey) => {
              await executeProductionUpdateTemplate(
                {
                  source: store,
                  queue: store,
                  vaultId: unlocked.profile.vaultId,
                  rootKey,
                },
                request,
              );
            },
          );
        }
        context.stdout.write(`Template for "${groupQuery}" updated.\n`);
      },
    },
    {
      name: 'archive',
      description: 'Archive a group template container.',
      arguments: [{ syntax: '<query>', description: 'Group name or ID.' }],
      options: [secretBackendOption, backendPassphraseStdinOption],
      execute: async (context, arguments_, options) => {
        const query = requiredArgument(arguments_[0], 'group query');
        const { cliArchiveEntityRequestSchema } =
          await import('./mutation-contracts.js');
        const request = cliArchiveEntityRequestSchema.parse({ groupQuery: query });

        if (context.ports?.archiveTemplate !== undefined) {
          await context.ports.archiveTemplate(request);
        } else if (context.ports?.archiveEntity !== undefined) {
          await context.ports.archiveEntity(request);
        } else {
          const { executeProductionArchiveEntity } =
            await import('./production/mutations.js');
          await withUnlockedVault(
            context,
            'template archive',
            options,
            async (unlocked, store, rootKey) =>
              executeProductionArchiveEntity(
                {
                  source: store,
                  queue: store,
                  vaultId: unlocked.profile.vaultId,
                  rootKey,
                },
                request,
              ),
          );
        }
        context.stdout.write(`Template for "${query}" archived.\n`);
      },
    },
    {
      name: 'restore',
      description: 'Restore an archived group template container.',
      arguments: [{ syntax: '<query>', description: 'Group name or ID.' }],
      options: [secretBackendOption, backendPassphraseStdinOption],
      execute: async (context, arguments_, options) => {
        const query = requiredArgument(arguments_[0], 'group query');
        const { cliRestoreEntityRequestSchema } =
          await import('./mutation-contracts.js');
        const request = cliRestoreEntityRequestSchema.parse({ groupQuery: query });

        if (context.ports?.restoreTemplate !== undefined) {
          await context.ports.restoreTemplate(request);
        } else if (context.ports?.restoreEntity !== undefined) {
          await context.ports.restoreEntity(request);
        } else {
          const { executeProductionRestoreEntity } =
            await import('./production/mutations.js');
          await withUnlockedVault(
            context,
            'template restore',
            options,
            async (unlocked, store, rootKey) =>
              executeProductionRestoreEntity(
                {
                  source: store,
                  queue: store,
                  vaultId: unlocked.profile.vaultId,
                  rootKey,
                },
                request,
              ),
          );
        }
        context.stdout.write(`Template for "${query}" restored.\n`);
      },
    },
    {
      name: 'delete',
      description: 'Permanently delete a group template container.',
      arguments: [{ syntax: '<query>', description: 'Group name or ID.' }],
      options: [
        { flags: '--force', description: 'Confirm permanent deletion.' },
        secretBackendOption,
        backendPassphraseStdinOption,
      ],
      execute: async (context, arguments_, options) => {
        const query = requiredArgument(arguments_[0], 'group query');
        const force = optionBoolean(options, 'force');
        if (!force) {
          throw new CliUsageError(
            'The --force flag is required for permanent deletion.',
          );
        }

        if (context.ports?.deleteTemplate !== undefined) {
          await context.ports.deleteTemplate(query);
        } else if (context.ports?.deleteGroup !== undefined) {
          await context.ports.deleteGroup(query);
        } else {
          const { executeProductionDeleteGroup } =
            await import('./production/mutations.js');
          await withUnlockedVault(
            context,
            'template delete',
            options,
            async (unlocked, store, rootKey) =>
              executeProductionDeleteGroup(
                {
                  source: store,
                  queue: store,
                  vaultId: unlocked.profile.vaultId,
                  rootKey,
                },
                query,
              ),
          );
        }
        context.stdout.write(`Template for "${query}" deleted.\n`);
      },
    },
    {
      name: 'migrate',
      description: 'Plan, preview, and apply lossless template migrations.',
      options: [secretBackendOption, backendPassphraseStdinOption],
      children: [
        {
          name: 'plan',
          description: 'Preview a template migration plan and affected item counts.',
          arguments: [{ syntax: '<group>', description: 'Group name or ID.' }],
          options: [
            {
              flags: '--target <template>',
              description: 'Target template key, name, or group query.',
            },
            {
              flags: '--template-file <file>',
              description: 'Path to JSON template file.',
            },
            {
              flags: '--to-version <version>',
              description: 'Target template schema version.',
            },
            jsonOption,
            secretBackendOption,
            backendPassphraseStdinOption,
          ],
          execute: async (context, arguments_, options) => {
            const groupQuery = requiredArgument(arguments_[0], 'group query');
            const targetTemplateQuery = optionString(options, 'target');
            const templateFile = optionString(options, 'templateFile');
            const toVersionRaw = optionString(options, 'toVersion');
            const toVersion = toVersionRaw ? Number(toVersionRaw) : undefined;
            const { cliPlanTemplateMigrationRequestSchema } =
              await import('./mutation-contracts.js');
            const request = cliPlanTemplateMigrationRequestSchema.parse({
              groupQuery,
              ...(targetTemplateQuery ? { targetTemplateQuery } : {}),
              ...(templateFile ? { templateFile } : {}),
              ...(toVersion !== undefined ? { toVersion } : {}),
            });

            let plan: TemplateMigrationPlan;
            if (context.ports?.planTemplateMigration !== undefined) {
              plan = await context.ports.planTemplateMigration(request);
            } else {
              const { executeProductionPlanTemplateMigration } =
                await import('./production/mutations.js');
              plan = await withUnlockedVault(
                context,
                'template migrate plan',
                options,
                async (unlocked, store, rootKey) =>
                  executeProductionPlanTemplateMigration(
                    {
                      source: store,
                      vaultId: unlocked.profile.vaultId,
                      rootKey,
                    },
                    request,
                  ),
              );
            }
            const { renderTemplateMigrationPlan } = await import('./render.js');
            context.stdout.write(
              renderTemplateMigrationPlan(plan, optionBoolean(options, 'json')),
            );
          },
        },
        {
          name: 'apply',
          description: 'Apply a lossless template migration to a group.',
          arguments: [{ syntax: '<group>', description: 'Group name or ID.' }],
          options: [
            {
              flags: '--target <template>',
              description: 'Target template key, name, or group query.',
            },
            {
              flags: '--template-file <file>',
              description: 'Path to JSON template file.',
            },
            {
              flags: '--to-version <version>',
              description: 'Target template schema version.',
            },
            {
              flags: '--confirm-risky',
              description: 'Confirm migration steps that require confirmation.',
            },
            jsonOption,
            secretBackendOption,
            backendPassphraseStdinOption,
          ],
          execute: async (context, arguments_, options) => {
            const groupQuery = requiredArgument(arguments_[0], 'group query');
            const targetTemplateQuery = optionString(options, 'target');
            const templateFile = optionString(options, 'templateFile');
            const toVersionRaw = optionString(options, 'toVersion');
            const toVersion = toVersionRaw ? Number(toVersionRaw) : undefined;
            const confirmRisky = optionBoolean(options, 'confirmRisky');
            const { cliApplyTemplateMigrationRequestSchema } =
              await import('./mutation-contracts.js');
            const request = cliApplyTemplateMigrationRequestSchema.parse({
              groupQuery,
              ...(targetTemplateQuery ? { targetTemplateQuery } : {}),
              ...(templateFile ? { templateFile } : {}),
              ...(toVersion !== undefined ? { toVersion } : {}),
              ...(confirmRisky ? { confirmRisky } : {}),
            });

            let result: CliTemplateMigrationApplyResult;
            if (context.ports?.applyTemplateMigration !== undefined) {
              result = await context.ports.applyTemplateMigration(request);
            } else {
              const { executeProductionApplyTemplateMigration } =
                await import('./production/mutations.js');
              result = await withUnlockedVault(
                context,
                'template migrate apply',
                options,
                async (unlocked, store, rootKey) =>
                  executeProductionApplyTemplateMigration(
                    {
                      source: store,
                      queue: store,
                      vaultId: unlocked.profile.vaultId,
                      rootKey,
                    },
                    request,
                  ),
              );
            }
            const { renderTemplateMigrationApply } = await import('./render.js');
            context.stdout.write(
              renderTemplateMigrationApply(result, optionBoolean(options, 'json')),
            );
          },
        },
        {
          name: 'status',
          description: 'Show template migration status and active version for a group.',
          arguments: [{ syntax: '<group>', description: 'Group name or ID.' }],
          options: [jsonOption, secretBackendOption, backendPassphraseStdinOption],
          execute: async (context, arguments_, options) => {
            const groupQuery = requiredArgument(arguments_[0], 'group query');
            let status: CliTemplateMigrationStatusResult;
            if (context.ports?.getTemplateMigrationStatus !== undefined) {
              status = await context.ports.getTemplateMigrationStatus(groupQuery);
            } else {
              const { executeProductionGetTemplateMigrationStatus } =
                await import('./production/mutations.js');
              status = await withUnlockedVault(
                context,
                'template migrate status',
                options,
                async (unlocked, store, rootKey) =>
                  executeProductionGetTemplateMigrationStatus(
                    {
                      source: store,
                      vaultId: unlocked.profile.vaultId,
                      rootKey,
                    },
                    groupQuery,
                  ),
              );
            }
            const { renderTemplateMigrationStatus } = await import('./render.js');
            context.stdout.write(
              renderTemplateMigrationStatus(status, optionBoolean(options, 'json')),
            );
          },
        },
      ],
    },
  ],
});

const groupCommand: CliCommandDescriptor = Object.freeze({
  name: 'group',
  description: 'Manage group containers.',
  options: [secretBackendOption, backendPassphraseStdinOption],
  children: [
    {
      name: 'create',
      description: 'Create a new group container.',
      arguments: [{ syntax: '<name>', description: 'Group name.' }],
      options: [
        { flags: '--description <text>', description: 'Optional group description.' },
        {
          flags: '--template <query>',
          description:
            'Initialize group with a built-in template key or existing group template.',
        },
        secretBackendOption,
        backendPassphraseStdinOption,
      ],
      execute: async (context, arguments_, options) => {
        const name = requiredArgument(arguments_[0], 'group name');
        const description = optionString(options, 'description');
        const template = optionString(options, 'template');
        const { cliCreateGroupRequestSchema } = await import('./mutation-contracts.js');
        const request = cliCreateGroupRequestSchema.parse({
          name,
          ...(description ? { description } : {}),
          ...(template ? { template } : {}),
        });

        if (context.ports?.createGroup !== undefined) {
          await context.ports.createGroup(request);
        } else {
          const { executeProductionCreateGroup } =
            await import('./production/mutations.js');
          await withUnlockedVault(
            context,
            'group create',
            options,
            async (unlocked, store, rootKey) => {
              await executeProductionCreateGroup(
                {
                  source: store,
                  queue: store,
                  vaultId: unlocked.profile.vaultId,
                  rootKey,
                },
                request,
              );
            },
          );
        }
        context.stdout.write(`Group "${request.name}" created.\n`);
      },
    },
    {
      name: 'list',
      description: 'List active groups in the vault.',
      options: [jsonOption, secretBackendOption, backendPassphraseStdinOption],
      execute: async (context, _arguments, options) => {
        let groups: readonly GroupPayload[];
        if (context.ports?.listGroups !== undefined) {
          groups = await context.ports.listGroups();
        } else {
          const { VaultReadSession } = await import('@kavrix/client');
          groups = await withUnlockedVault(
            context,
            'group list',
            options,
            async (unlocked, store, rootKey) => {
              const readSession = new VaultReadSession(store, unlocked.profile.vaultId);
              try {
                await readSession.unlock(rootKey);
                return await readSession.listGroups();
              } finally {
                readSession.lock();
              }
            },
          );
        }
        const { renderGroupList } = await import('./render.js');
        context.stdout.write(renderGroupList(groups, optionBoolean(options, 'json')));
      },
    },
    {
      name: 'rename',
      description: 'Rename an active group.',
      arguments: [
        { syntax: '<query>', description: 'Group ID, name, or alias.' },
        { syntax: '<new-name>', description: 'New group name.' },
      ],
      options: [secretBackendOption, backendPassphraseStdinOption],
      execute: async (context, arguments_, options) => {
        const query = requiredArgument(arguments_[0], 'group query');
        const newName = requiredArgument(arguments_[1], 'new group name');

        if (context.ports?.renameGroup !== undefined) {
          await context.ports.renameGroup(query, newName);
        } else {
          const { VaultReadSession, VaultMutationService } =
            await import('@kavrix/client');
          const { createDefaultMutationDependencies } =
            await import('./production/mutations.js');
          await withUnlockedVault(
            context,
            'group rename',
            options,
            async (unlocked, store, rootKey) => {
              const readSession = new VaultReadSession(store, unlocked.profile.vaultId);
              let group: GroupPayload;
              try {
                await readSession.unlock(rootKey);
                group = await readSession.showGroup(query);
              } finally {
                readSession.lock();
              }
              const service = new VaultMutationService(
                store,
                store,
                unlocked.profile.vaultId,
                rootKey,
                createDefaultMutationDependencies(),
              );
              await service.updateGroup({
                ...group,
                name: newName,
              });
            },
          );
        }
        context.stdout.write(`Group renamed to "${newName}".\n`);
      },
    },
    {
      name: 'archive',
      description: 'Archive an active group.',
      arguments: [{ syntax: '<query>', description: 'Group ID, name, or alias.' }],
      options: [secretBackendOption, backendPassphraseStdinOption],
      execute: async (context, arguments_, options) => {
        const query = requiredArgument(arguments_[0], 'group query');
        const { cliArchiveEntityRequestSchema } =
          await import('./mutation-contracts.js');
        const request = cliArchiveEntityRequestSchema.parse({ groupQuery: query });

        if (context.ports?.archiveEntity !== undefined) {
          await context.ports.archiveEntity(request);
        } else {
          const { executeProductionArchiveEntity } =
            await import('./production/mutations.js');
          await withUnlockedVault(
            context,
            'group archive',
            options,
            async (unlocked, store, rootKey) => {
              await executeProductionArchiveEntity(
                {
                  source: store,
                  queue: store,
                  vaultId: unlocked.profile.vaultId,
                  rootKey,
                },
                request,
              );
            },
          );
        }
        context.stdout.write(`Group "${query}" archived.\n`);
      },
    },
    {
      name: 'restore',
      description: 'Restore an archived group.',
      arguments: [{ syntax: '<group-id>', description: 'Archived group ID.' }],
      options: [secretBackendOption, backendPassphraseStdinOption],
      execute: async (context, arguments_, options) => {
        const groupId = requiredArgument(arguments_[0], 'group ID');
        const { cliRestoreEntityRequestSchema } =
          await import('./mutation-contracts.js');
        const request = cliRestoreEntityRequestSchema.parse({ groupQuery: groupId });

        if (context.ports?.restoreEntity !== undefined) {
          await context.ports.restoreEntity(request);
        } else {
          const { executeProductionRestoreEntity } =
            await import('./production/mutations.js');
          await withUnlockedVault(
            context,
            'group restore',
            options,
            async (unlocked, store, rootKey) => {
              await executeProductionRestoreEntity(
                {
                  source: store,
                  queue: store,
                  vaultId: unlocked.profile.vaultId,
                  rootKey,
                },
                request,
              );
            },
          );
        }
        context.stdout.write(`Group "${groupId}" restored.\n`);
      },
    },
    {
      name: 'delete',
      description: 'Permanently delete a group.',
      arguments: [{ syntax: '<query>', description: 'Group ID, name, or alias.' }],
      options: [
        { flags: '--force', description: 'Confirm permanent deletion.' },
        secretBackendOption,
        backendPassphraseStdinOption,
      ],
      execute: async (context, arguments_, options) => {
        const query = requiredArgument(arguments_[0], 'group query');
        const force = optionBoolean(options, 'force');
        if (!force) {
          throw new CliUsageError(
            'The --force flag is required for permanent group deletion.',
          );
        }
        if (context.ports?.deleteGroup !== undefined) {
          await context.ports.deleteGroup(query);
        } else {
          const { VaultReadSession, VaultMutationService } =
            await import('@kavrix/client');
          const { createDefaultMutationDependencies } =
            await import('./production/mutations.js');
          const { recordRevisionSchema } = await import('@kavrix/schemas');
          await withUnlockedVault(
            context,
            'group delete',
            options,
            async (unlocked, store, rootKey) => {
              const readSession = new VaultReadSession(store, unlocked.profile.vaultId);
              let group: GroupPayload;
              try {
                await readSession.unlock(rootKey);
                group = await readSession.showGroup(query);
              } finally {
                readSession.lock();
              }
              const state = await store.getCurrentGroup(
                unlocked.profile.vaultId,
                group.id,
              );
              if (state?.state !== 'active') {
                throw new Error('Group not found or inactive');
              }
              const service = new VaultMutationService(
                store,
                store,
                unlocked.profile.vaultId,
                rootKey,
                createDefaultMutationDependencies(),
              );
              await service.deleteGroup(
                group.id,
                recordRevisionSchema.parse(state.record.recordRevision),
              );
            },
          );
        }
        context.stdout.write(`Group "${query}" deleted.\n`);
      },
    },
  ],
});

const credentialCommand: CliCommandDescriptor = Object.freeze({
  name: 'credential',
  description: 'Manage credential items inside groups.',
  options: [secretBackendOption, backendPassphraseStdinOption],
  children: [
    {
      name: 'create',
      description: 'Create a new credential item in a group.',
      arguments: [
        { syntax: '<group>', description: 'Group ID, unique name, or alias.' },
        { syntax: '<title>', description: 'Credential title.' },
      ],
      options: [secretBackendOption, backendPassphraseStdinOption],
      execute: async (context, arguments_, options) => {
        const groupQuery = requiredArgument(arguments_[0], 'group query');
        const title = requiredArgument(arguments_[1], 'credential title');
        const { cliCreateCredentialRequestSchema } =
          await import('./mutation-contracts.js');
        const request = cliCreateCredentialRequestSchema.parse({
          groupQuery,
          title,
        });

        let result: { credentialId: string };
        if (context.ports?.createCredential !== undefined) {
          result = await context.ports.createCredential(request);
        } else {
          const { executeProductionCreateCredential } =
            await import('./production/mutations.js');
          result = await withUnlockedVault(
            context,
            'credential create',
            options,
            async (unlocked, store, rootKey) =>
              executeProductionCreateCredential(
                {
                  source: store,
                  queue: store,
                  vaultId: unlocked.profile.vaultId,
                  rootKey,
                },
                request,
              ),
          );
        }
        context.stdout.write(
          `Credential "${request.title}" created (${result.credentialId}).\n`,
        );
      },
    },
    {
      name: 'list',
      description: 'List active credentials in a group.',
      arguments: [
        { syntax: '<group>', description: 'Group ID, unique name, or alias.' },
      ],
      options: [jsonOption, secretBackendOption, backendPassphraseStdinOption],
      execute: async (context, arguments_, options) => {
        const groupQuery = requiredArgument(arguments_[0], 'group query');
        let items: readonly ItemPayload[];
        if (context.ports?.listCredentials !== undefined) {
          items = await context.ports.listCredentials(groupQuery);
        } else {
          const { VaultReadSession } = await import('@kavrix/client');
          items = await withUnlockedVault(
            context,
            'credential list',
            options,
            async (unlocked, store, rootKey) => {
              const readSession = new VaultReadSession(store, unlocked.profile.vaultId);
              try {
                await readSession.unlock(rootKey);
                return await readSession.listItems(groupQuery);
              } finally {
                readSession.lock();
              }
            },
          );
        }
        const { renderCredentialList } = await import('./render.js');
        context.stdout.write(
          renderCredentialList(items, optionBoolean(options, 'json')),
        );
      },
    },
    {
      name: 'rename',
      description: 'Rename an active credential.',
      arguments: [
        { syntax: '<group>', description: 'Group ID, unique name, or alias.' },
        {
          syntax: '<credential>',
          description: 'Credential ID, unique name, or alias.',
        },
        { syntax: '<new-title>', description: 'New credential title.' },
      ],
      options: [secretBackendOption, backendPassphraseStdinOption],
      execute: async (context, arguments_, options) => {
        const groupQuery = requiredArgument(arguments_[0], 'group query');
        const credentialQuery = requiredArgument(arguments_[1], 'credential query');
        const newTitle = requiredArgument(arguments_[2], 'new credential title');

        if (context.ports?.renameCredential !== undefined) {
          await context.ports.renameCredential(groupQuery, credentialQuery, newTitle);
        } else {
          const { VaultReadSession, VaultMutationService } =
            await import('@kavrix/client');
          const { createDefaultMutationDependencies } =
            await import('./production/mutations.js');
          await withUnlockedVault(
            context,
            'credential rename',
            options,
            async (unlocked, store, rootKey) => {
              const readSession = new VaultReadSession(store, unlocked.profile.vaultId);
              let found: { group: GroupPayload; item: ItemPayload };
              try {
                await readSession.unlock(rootKey);
                found = await readSession.show(groupQuery, credentialQuery);
              } finally {
                readSession.lock();
              }
              const service = new VaultMutationService(
                store,
                store,
                unlocked.profile.vaultId,
                rootKey,
                createDefaultMutationDependencies(),
              );
              await service.updateItem(found.group.id, {
                ...found.item,
                title: newTitle,
              });
            },
          );
        }
        context.stdout.write(`Credential renamed to "${newTitle}".\n`);
      },
    },
    {
      name: 'archive',
      description: 'Archive an active credential.',
      arguments: [
        { syntax: '<group>', description: 'Group ID, unique name, or alias.' },
        {
          syntax: '<credential>',
          description: 'Credential ID, unique name, or alias.',
        },
      ],
      options: [secretBackendOption, backendPassphraseStdinOption],
      execute: async (context, arguments_, options) => {
        const groupQuery = requiredArgument(arguments_[0], 'group query');
        const credentialQuery = requiredArgument(arguments_[1], 'credential query');
        const { cliArchiveEntityRequestSchema } =
          await import('./mutation-contracts.js');
        const request = cliArchiveEntityRequestSchema.parse({
          groupQuery,
          credentialQuery,
        });

        if (context.ports?.archiveEntity !== undefined) {
          await context.ports.archiveEntity(request);
        } else {
          const { executeProductionArchiveEntity } =
            await import('./production/mutations.js');
          await withUnlockedVault(
            context,
            'credential archive',
            options,
            async (unlocked, store, rootKey) => {
              await executeProductionArchiveEntity(
                {
                  source: store,
                  queue: store,
                  vaultId: unlocked.profile.vaultId,
                  rootKey,
                },
                request,
              );
            },
          );
        }
        context.stdout.write(`Credential "${credentialQuery}" archived.\n`);
      },
    },
    {
      name: 'restore',
      description: 'Restore an archived credential.',
      arguments: [
        { syntax: '<group>', description: 'Group ID, unique name, or alias.' },
        { syntax: '<credential-id>', description: 'Archived credential ID.' },
      ],
      options: [secretBackendOption, backendPassphraseStdinOption],
      execute: async (context, arguments_, options) => {
        const groupQuery = requiredArgument(arguments_[0], 'group query');
        const credentialId = requiredArgument(arguments_[1], 'credential ID');
        const { cliRestoreEntityRequestSchema } =
          await import('./mutation-contracts.js');
        const request = cliRestoreEntityRequestSchema.parse({
          groupQuery,
          credentialQuery: credentialId,
        });

        if (context.ports?.restoreEntity !== undefined) {
          await context.ports.restoreEntity(request);
        } else {
          const { executeProductionRestoreEntity } =
            await import('./production/mutations.js');
          await withUnlockedVault(
            context,
            'credential restore',
            options,
            async (unlocked, store, rootKey) => {
              await executeProductionRestoreEntity(
                {
                  source: store,
                  queue: store,
                  vaultId: unlocked.profile.vaultId,
                  rootKey,
                },
                request,
              );
            },
          );
        }
        context.stdout.write(`Credential "${credentialId}" restored.\n`);
      },
    },
    {
      name: 'delete',
      description: 'Permanently delete a credential.',
      arguments: [
        { syntax: '<group>', description: 'Group ID, unique name, or alias.' },
        {
          syntax: '<credential>',
          description: 'Credential ID, unique name, or alias.',
        },
      ],
      options: [
        { flags: '--force', description: 'Confirm permanent deletion.' },
        secretBackendOption,
        backendPassphraseStdinOption,
      ],
      execute: async (context, arguments_, options) => {
        const groupQuery = requiredArgument(arguments_[0], 'group query');
        const credentialQuery = requiredArgument(arguments_[1], 'credential query');
        const force = optionBoolean(options, 'force');
        if (!force) {
          throw new CliUsageError(
            'The --force flag is required for permanent credential deletion.',
          );
        }
        if (context.ports?.deleteCredential !== undefined) {
          await context.ports.deleteCredential(groupQuery, credentialQuery);
        } else {
          const { VaultReadSession, VaultMutationService } =
            await import('@kavrix/client');
          const { createDefaultMutationDependencies } =
            await import('./production/mutations.js');
          const { recordRevisionSchema } = await import('@kavrix/schemas');
          await withUnlockedVault(
            context,
            'credential delete',
            options,
            async (unlocked, store, rootKey) => {
              const readSession = new VaultReadSession(store, unlocked.profile.vaultId);
              let found: { group: GroupPayload; item: ItemPayload };
              try {
                await readSession.unlock(rootKey);
                found = await readSession.show(groupQuery, credentialQuery);
              } finally {
                readSession.lock();
              }
              const state = await store.getCurrentItem(
                unlocked.profile.vaultId,
                found.item.id,
              );
              if (state?.state !== 'active') {
                throw new Error('Credential item is not active or found');
              }
              const service = new VaultMutationService(
                store,
                store,
                unlocked.profile.vaultId,
                rootKey,
                createDefaultMutationDependencies(),
              );
              await service.deleteItem(
                found.group.id,
                found.item.id,
                recordRevisionSchema.parse(state.record.recordRevision),
              );
            },
          );
        }
        context.stdout.write(`Credential "${credentialQuery}" deleted.\n`);
      },
    },
  ],
});

function zeroizeBytes(buffer: Uint8Array): void {
  buffer.fill(0);
}

/** Options every field write shares, so `field set` and `set` stay identical. */
const fieldWriteOptions: readonly CliOptionDescriptor[] = Object.freeze([
  {
    flags: '--if-revision <number>',
    description: 'Only write when the credential is still at this revision.',
  },
  { flags: '--json', description: 'Format the receipt as structured JSON.' },
]);

/**
 * Acquire a field value without ever touching argv.
 *
 * Standard input is the scriptable path; a terminal falls back to a masked
 * prompt, which itself fails closed when no terminal is attached.
 */
async function readFieldValue(
  context: CliCommandContext,
  feature: CliFeature,
  options: Readonly<Record<string, unknown>>,
): Promise<Uint8Array> {
  const fromStdin = optionBoolean(options, 'valueStdin');
  const acquired = await secretInput(context, feature).read({
    kind: 'field-value',
    fromStdin,
  });
  return Buffer.from(acquired, 'utf8');
}

function expectedRevision(
  options: Readonly<Record<string, unknown>>,
): number | undefined {
  const raw = options['ifRevision'];
  return raw === undefined
    ? undefined
    : parseInput(expectedRevisionOptionSchema, raw, 'expected revision');
}

/**
 * Reads the `--code` selector and validates its shape as a usage error.
 *
 * Validating here as well as in the request schema keeps a malformed identifier a
 * usage failure raised before any vault is unlocked, rather than a vault-level
 * failure that implies the vault was consulted.
 */
async function recoveryCodeSelector(
  options: Readonly<Record<string, unknown>>,
): Promise<string> {
  const raw = requiredOption(options, 'code', 'recovery code');
  const { recoveryCodeSelectorSchema } = await import('./mutation-contracts.js');
  return parseInput(recoveryCodeSelectorSchema, raw, 'recovery code');
}

/** Shared body of `field set` and the top-level `set`. */
async function executeFieldSet(
  feature: Extract<CliFeature, 'field set' | 'set'>,
  context: CliCommandContext,
  arguments_: readonly (string | undefined)[],
  options: Readonly<Record<string, unknown>>,
): Promise<void> {
  const groupQuery = requiredArgument(arguments_[0], 'group query');
  const credentialQuery = requiredArgument(arguments_[1], 'credential query');
  const fieldQuery = requiredArgument(arguments_[2], 'field query');
  const create = optionBoolean(options, 'create');
  const asJson = optionBoolean(options, 'json');
  const ifRevision = expectedRevision(options);
  const secretBytes = await readFieldValue(context, feature, options);

  try {
    const { cliSetFieldRequestSchema } = await import('./mutation-contracts.js');
    const request = cliSetFieldRequestSchema.parse({
      groupQuery,
      credentialQuery,
      fieldKey: fieldQuery,
      value: secretBytes,
      ...(create ? { create: true } : {}),
      ...(ifRevision === undefined ? {} : { ifRevision }),
    });

    let result: CliFieldMutationResult;
    if (context.ports?.setField !== undefined) {
      result = await context.ports.setField(request);
    } else {
      const { executeProductionSetField } = await import('./production/mutations.js');
      let produced: CliFieldMutationResult | undefined;
      await withUnlockedVault(
        context,
        feature,
        options,
        async (unlocked, store, rootKey) => {
          produced = await executeProductionSetField(
            {
              source: store,
              queue: store,
              vaultId: unlocked.profile.vaultId,
              rootKey,
            },
            request,
          );
        },
      );
      if (produced === undefined) {
        throw new Error('The field write did not produce a receipt.');
      }
      result = produced;
    }
    const { renderFieldMutation } = await import('./render.js');
    context.stdout.write(renderFieldMutation('set', result, asJson));
  } finally {
    zeroizeBytes(secretBytes);
  }
}

/** Shared body of `field update` and the top-level `update`. */
async function executeFieldUpdate(
  feature: Extract<CliFeature, 'field update' | 'update'>,
  context: CliCommandContext,
  arguments_: readonly (string | undefined)[],
  options: Readonly<Record<string, unknown>>,
): Promise<void> {
  const groupQuery = requiredArgument(arguments_[0], 'group query');
  const credentialQuery = requiredArgument(arguments_[1], 'credential query');
  const fieldQuery = requiredArgument(arguments_[2], 'field query');
  const label = optionString(options, 'label');
  const typeStr = optionString(options, 'type');
  const sensitiveFlag = options['sensitive'];
  const sensitive = typeof sensitiveFlag === 'boolean' ? sensitiveFlag : undefined;
  const asJson = optionBoolean(options, 'json');
  const ifRevision = expectedRevision(options);

  // The request contract also rejects an empty change set, but a bare Zod
  // failure reports nothing actionable, so name the missing flags here.
  if (label === undefined && typeStr === undefined && sensitive === undefined) {
    throw new CliUsageError(
      'Provide at least one of --label, --type, --sensitive, or --no-sensitive.',
    );
  }

  const { cliUpdateFieldRequestSchema } = await import('./mutation-contracts.js');
  const request = cliUpdateFieldRequestSchema.parse({
    groupQuery,
    credentialQuery,
    fieldKey: fieldQuery,
    ...(label ? { label } : {}),
    ...(typeStr ? { fieldType: typeStr } : {}),
    ...(sensitive === undefined ? {} : { sensitive }),
    ...(ifRevision === undefined ? {} : { ifRevision }),
  });

  let result: CliFieldMutationResult;
  if (context.ports?.updateField !== undefined) {
    result = await context.ports.updateField(request);
  } else {
    const { executeProductionUpdateField } = await import('./production/mutations.js');
    let produced: CliFieldMutationResult | undefined;
    await withUnlockedVault(
      context,
      feature,
      options,
      async (unlocked, store, rootKey) => {
        produced = await executeProductionUpdateField(
          {
            source: store,
            queue: store,
            vaultId: unlocked.profile.vaultId,
            rootKey,
          },
          request,
        );
      },
    );
    if (produced === undefined) {
      throw new Error('The field update did not produce a receipt.');
    }
    result = produced;
  }
  const { renderFieldMutation } = await import('./render.js');
  context.stdout.write(renderFieldMutation('updated', result, asJson));
}

const fieldCommand: CliCommandDescriptor = Object.freeze({
  name: 'field',
  description: 'Manage dynamic credential fields.',
  options: [secretBackendOption, backendPassphraseStdinOption],
  children: [
    {
      name: 'add',
      description: 'Add a new dynamic field to a credential.',
      arguments: [
        { syntax: '<group>', description: 'Group ID, unique name, or alias.' },
        {
          syntax: '<credential>',
          description: 'Credential ID, unique name, or alias.',
        },
        { syntax: '<field-key>', description: 'Stable field key.' },
      ],
      options: [
        { flags: '--type <type>', description: 'Canonical field type.' },
        { flags: '--label <text>', description: 'Field display label.' },
        { flags: '--sensitive', description: 'Mark field as sensitive.' },
        {
          flags: SECRET_INPUT_OPTIONS.fieldValue.flag,
          description: SECRET_INPUT_OPTIONS.fieldValue.description,
        },
        secretBackendOption,
        backendPassphraseStdinOption,
      ],
      execute: async (context, arguments_, options) => {
        const groupQuery = requiredArgument(arguments_[0], 'group query');
        const credentialQuery = requiredArgument(arguments_[1], 'credential query');
        const fieldKey = requiredArgument(arguments_[2], 'field key');
        const typeStr = optionString(options, 'type');
        const label = optionString(options, 'label');
        const sensitive = optionBoolean(options, 'sensitive');
        const fromStdin = optionBoolean(options, 'valueStdin');

        // A field value may be secret, and process arguments are readable by
        // every local process, so an initial value only arrives out of band.
        let secretBytes: Uint8Array | undefined;
        if (fromStdin) {
          const acquired = await secretInput(context, 'field add').read({
            kind: 'field-value',
            fromStdin: true,
          });
          secretBytes = Buffer.from(acquired, 'utf8');
        }

        const { cliAddFieldRequestSchema } = await import('./mutation-contracts.js');
        const request = cliAddFieldRequestSchema.parse({
          groupQuery,
          credentialQuery,
          fieldKey,
          ...(typeStr ? { fieldType: typeStr } : {}),
          ...(label ? { label } : {}),
          ...(sensitive ? { sensitive: true } : {}),
          ...(secretBytes ? { value: secretBytes } : {}),
        });

        try {
          if (context.ports?.addField !== undefined) {
            await context.ports.addField(request);
          } else {
            const { executeProductionAddField } =
              await import('./production/mutations.js');
            await withUnlockedVault(
              context,
              'field add',
              options,
              async (unlocked, store, rootKey) =>
                executeProductionAddField(
                  {
                    source: store,
                    queue: store,
                    vaultId: unlocked.profile.vaultId,
                    rootKey,
                  },
                  request,
                ),
            );
          }
          context.stdout.write(
            `Field "${request.fieldKey}" added to credential "${credentialQuery}".\n`,
          );
        } finally {
          if (secretBytes !== undefined) zeroizeBytes(secretBytes);
        }
      },
    },
    {
      name: 'set',
      description: 'Set the value of a credential field.',
      arguments: [
        { syntax: '<group>', description: 'Group ID, unique name, or alias.' },
        {
          syntax: '<credential>',
          description: 'Credential ID, unique name, or alias.',
        },
        {
          syntax: '<field>',
          description: 'Field ID, stable key, exact label, or unique prefix.',
        },
      ],
      options: [
        {
          flags: SECRET_INPUT_OPTIONS.fieldValue.flag,
          description: SECRET_INPUT_OPTIONS.fieldValue.description,
        },
        {
          flags: '--create',
          description: 'Create the field when no existing field matches.',
        },
        ...fieldWriteOptions,
        secretBackendOption,
        backendPassphraseStdinOption,
      ],
      execute: async (context, arguments_, options) => {
        await executeFieldSet('field set', context, arguments_, options);
      },
    },
    {
      name: 'update',
      description: 'Update the definition of a dynamic field.',
      arguments: [
        { syntax: '<group>', description: 'Group ID, unique name, or alias.' },
        {
          syntax: '<credential>',
          description: 'Credential ID, unique name, or alias.',
        },
        {
          syntax: '<field>',
          description: 'Field ID, stable key, exact label, or unique prefix.',
        },
      ],
      options: [
        { flags: '--label <text>', description: 'Updated field display label.' },
        { flags: '--type <type>', description: 'Updated canonical field type.' },
        { flags: '--sensitive', description: 'Mark field as sensitive.' },
        { flags: '--no-sensitive', description: 'Mark field as non-sensitive.' },
        ...fieldWriteOptions,
        secretBackendOption,
        backendPassphraseStdinOption,
      ],
      execute: async (context, arguments_, options) => {
        await executeFieldUpdate('field update', context, arguments_, options);
      },
    },
    {
      name: 'archive',
      description: 'Archive a field value.',
      arguments: [
        { syntax: '<group>', description: 'Group ID, unique name, or alias.' },
        {
          syntax: '<credential>',
          description: 'Credential ID, unique name, or alias.',
        },
        { syntax: '<field-key>', description: 'Stable field key.' },
      ],
      options: [secretBackendOption, backendPassphraseStdinOption],
      execute: async (context, arguments_, options) => {
        const groupQuery = requiredArgument(arguments_[0], 'group query');
        const credentialQuery = requiredArgument(arguments_[1], 'credential query');
        const fieldKey = requiredArgument(arguments_[2], 'field key');
        const { cliArchiveFieldRequestSchema } =
          await import('./mutation-contracts.js');
        const request = cliArchiveFieldRequestSchema.parse({
          groupQuery,
          credentialQuery,
          fieldKey,
        });

        if (context.ports?.archiveField !== undefined) {
          await context.ports.archiveField(request);
        } else {
          const { executeProductionArchiveField } =
            await import('./production/mutations.js');
          await withUnlockedVault(
            context,
            'field archive',
            options,
            async (unlocked, store, rootKey) =>
              executeProductionArchiveField(
                {
                  source: store,
                  queue: store,
                  vaultId: unlocked.profile.vaultId,
                  rootKey,
                },
                request,
              ),
          );
        }
        context.stdout.write(
          `Field "${request.fieldKey}" archived for credential "${credentialQuery}".\n`,
        );
      },
    },
    {
      name: 'restore',
      description: 'Restore an archived field value.',
      arguments: [
        { syntax: '<group>', description: 'Group ID, unique name, or alias.' },
        {
          syntax: '<credential>',
          description: 'Credential ID, unique name, or alias.',
        },
        { syntax: '<field-key>', description: 'Stable field key.' },
      ],
      options: [secretBackendOption, backendPassphraseStdinOption],
      execute: async (context, arguments_, options) => {
        const groupQuery = requiredArgument(arguments_[0], 'group query');
        const credentialQuery = requiredArgument(arguments_[1], 'credential query');
        const fieldKey = requiredArgument(arguments_[2], 'field key');
        const { cliRestoreFieldRequestSchema } =
          await import('./mutation-contracts.js');
        const request = cliRestoreFieldRequestSchema.parse({
          groupQuery,
          credentialQuery,
          fieldKey,
        });

        if (context.ports?.restoreField !== undefined) {
          await context.ports.restoreField(request);
        } else {
          const { executeProductionRestoreField } =
            await import('./production/mutations.js');
          await withUnlockedVault(
            context,
            'field restore',
            options,
            async (unlocked, store, rootKey) =>
              executeProductionRestoreField(
                {
                  source: store,
                  queue: store,
                  vaultId: unlocked.profile.vaultId,
                  rootKey,
                },
                request,
              ),
          );
        }
        context.stdout.write(
          `Field "${request.fieldKey}" restored for credential "${credentialQuery}".\n`,
        );
      },
    },
    {
      name: 'remove',
      description: 'Permanently remove a dynamic item field.',
      arguments: [
        { syntax: '<group>', description: 'Group ID, unique name, or alias.' },
        {
          syntax: '<credential>',
          description: 'Credential ID, unique name, or alias.',
        },
        { syntax: '<field-key>', description: 'Stable field key.' },
      ],
      options: [
        { flags: '--force', description: 'Confirm permanent field removal.' },
        secretBackendOption,
        backendPassphraseStdinOption,
      ],
      execute: async (context, arguments_, options) => {
        const groupQuery = requiredArgument(arguments_[0], 'group query');
        const credentialQuery = requiredArgument(arguments_[1], 'credential query');
        const fieldKey = requiredArgument(arguments_[2], 'field key');
        const force = optionBoolean(options, 'force');
        if (!force) {
          throw new CliUsageError(
            'The --force flag is required for permanent field removal.',
          );
        }
        const { cliRemoveFieldRequestSchema } = await import('./mutation-contracts.js');
        const request = cliRemoveFieldRequestSchema.parse({
          groupQuery,
          credentialQuery,
          fieldKey,
        });

        if (context.ports?.removeField !== undefined) {
          await context.ports.removeField(request);
        } else {
          const { executeProductionRemoveField } =
            await import('./production/mutations.js');
          await withUnlockedVault(
            context,
            'field remove',
            options,
            async (unlocked, store, rootKey) =>
              executeProductionRemoveField(
                {
                  source: store,
                  queue: store,
                  vaultId: unlocked.profile.vaultId,
                  rootKey,
                },
                request,
              ),
          );
        }
        context.stdout.write(
          `Field "${request.fieldKey}" removed from credential "${credentialQuery}".\n`,
        );
      },
    },
  ],
});

const noteCommand: CliCommandDescriptor = Object.freeze({
  name: 'note',
  description: 'Manage encrypted group and credential notes.',
  options: [secretBackendOption, backendPassphraseStdinOption],
  children: [
    {
      name: 'add',
      description: 'Add an encrypted note to a group or credential.',
      arguments: [
        { syntax: '<group>', description: 'Group ID, unique name, or alias.' },
        {
          syntax: '[credential]',
          description: 'Optional credential ID, unique name, or alias.',
        },
      ],
      options: [
        { flags: '--title <text>', description: 'Note title.' },
        { flags: '--content <text>', description: 'Initial text content.' },
        {
          flags: SECRET_INPUT_OPTIONS.noteContent.flag,
          description: SECRET_INPUT_OPTIONS.noteContent.description,
        },
        { flags: '--sensitive', description: 'Mark note as sensitive.' },
        { flags: '--no-sensitive', description: 'Mark note as non-sensitive.' },
        { flags: '--pinned', description: 'Pin note to top.' },
        secretBackendOption,
        backendPassphraseStdinOption,
      ],
      execute: async (context, arguments_, options) => {
        const groupQuery = requiredArgument(arguments_[0], 'group query');
        const secondArg = arguments_[1];
        const titleOption = optionString(options, 'title');

        let credentialQuery: string | undefined;
        let title: string;

        if (titleOption !== undefined) {
          credentialQuery = secondArg;
          title = titleOption;
        } else if (secondArg !== undefined) {
          title = secondArg;
        } else {
          throw new CliUsageError(
            'Provide a note title via positional argument or --title.',
          );
        }

        const textContent = optionString(options, 'content');
        const fromStdin = optionBoolean(options, 'contentStdin');

        let secretBytes: Uint8Array | undefined;
        if (fromStdin) {
          const acquired = await secretInput(context, 'note add').read({
            kind: 'note-content',
            fromStdin: true,
          });
          secretBytes = Buffer.from(acquired, 'utf8');
        } else if (textContent !== undefined) {
          secretBytes = Buffer.from(textContent, 'utf8');
        }

        const sensitiveFlag = options['sensitive'];
        const sensitive =
          typeof sensitiveFlag === 'boolean' ? sensitiveFlag : undefined;
        const pinnedFlag = options['pinned'];
        const pinned = typeof pinnedFlag === 'boolean' ? pinnedFlag : undefined;

        const contentString = secretBytes
          ? Buffer.from(secretBytes).toString('utf8')
          : undefined;

        const { cliAddNoteRequestSchema } = await import('./mutation-contracts.js');
        const request = cliAddNoteRequestSchema.parse({
          groupQuery,
          ...(credentialQuery ? { credentialQuery } : {}),
          title,
          ...(contentString !== undefined ? { content: contentString } : {}),
          ...(sensitive !== undefined ? { isSensitive: sensitive } : {}),
          ...(pinned !== undefined ? { isPinned: pinned } : {}),
        });

        try {
          if (context.ports?.addNote !== undefined) {
            await context.ports.addNote(request);
          } else {
            const { executeProductionAddNote } =
              await import('./production/mutations.js');
            await withUnlockedVault(
              context,
              'note add',
              options,
              async (unlocked, store, rootKey) =>
                executeProductionAddNote(
                  {
                    source: store,
                    queue: store,
                    vaultId: unlocked.profile.vaultId,
                    rootKey,
                  },
                  request,
                ),
            );
          }
          const targetStr = credentialQuery
            ? `credential "${credentialQuery}"`
            : `group "${groupQuery}"`;
          context.stdout.write(`Note "${title}" added to ${targetStr}.\n`);
        } finally {
          if (secretBytes !== undefined) zeroizeBytes(secretBytes);
        }
      },
    },
    {
      name: 'update',
      description: 'Update an encrypted note.',
      arguments: [
        { syntax: '<group>', description: 'Group ID, unique name, or alias.' },
        { syntax: '<credential-or-note>', description: 'Credential ID or note query.' },
        { syntax: '[note]', description: 'Note ID, title, or unique prefix.' },
      ],
      options: [
        { flags: '--title <text>', description: 'Updated note title.' },
        { flags: '--content <text>', description: 'Updated text content.' },
        {
          flags: SECRET_INPUT_OPTIONS.noteContent.flag,
          description: SECRET_INPUT_OPTIONS.noteContent.description,
        },
        { flags: '--sensitive', description: 'Mark note as sensitive.' },
        { flags: '--no-sensitive', description: 'Mark note as non-sensitive.' },
        { flags: '--pinned', description: 'Pin note to top.' },
        { flags: '--no-pinned', description: 'Unpin note.' },
        secretBackendOption,
        backendPassphraseStdinOption,
      ],
      execute: async (context, arguments_, options) => {
        const groupQuery = requiredArgument(arguments_[0], 'group query');
        const secondArg = requiredArgument(arguments_[1], 'credential or note query');
        const thirdArg = arguments_[2];

        let credentialQuery: string | undefined;
        let noteQuery: string;

        if (thirdArg !== undefined) {
          credentialQuery = secondArg;
          noteQuery = thirdArg;
        } else {
          noteQuery = secondArg;
        }

        const title = optionString(options, 'title');
        const textContent = optionString(options, 'content');
        const fromStdin = optionBoolean(options, 'contentStdin');

        let secretBytes: Uint8Array | undefined;
        if (fromStdin) {
          const acquired = await secretInput(context, 'note update').read({
            kind: 'note-content',
            fromStdin: true,
          });
          secretBytes = Buffer.from(acquired, 'utf8');
        } else if (textContent !== undefined) {
          secretBytes = Buffer.from(textContent, 'utf8');
        }

        const sensitiveFlag = options['sensitive'];
        const sensitive =
          typeof sensitiveFlag === 'boolean' ? sensitiveFlag : undefined;
        const pinnedFlag = options['pinned'];
        const pinned = typeof pinnedFlag === 'boolean' ? pinnedFlag : undefined;

        const contentString = secretBytes
          ? Buffer.from(secretBytes).toString('utf8')
          : undefined;

        const { cliUpdateNoteRequestSchema } = await import('./mutation-contracts.js');
        const request = cliUpdateNoteRequestSchema.parse({
          groupQuery,
          ...(credentialQuery ? { credentialQuery } : {}),
          noteQuery,
          ...(title ? { title } : {}),
          ...(contentString !== undefined ? { content: contentString } : {}),
          ...(sensitive !== undefined ? { isSensitive: sensitive } : {}),
          ...(pinned !== undefined ? { isPinned: pinned } : {}),
        });

        try {
          if (context.ports?.updateNote !== undefined) {
            await context.ports.updateNote(request);
          } else {
            const { executeProductionUpdateNote } =
              await import('./production/mutations.js');
            await withUnlockedVault(
              context,
              'note update',
              options,
              async (unlocked, store, rootKey) =>
                executeProductionUpdateNote(
                  {
                    source: store,
                    queue: store,
                    vaultId: unlocked.profile.vaultId,
                    rootKey,
                  },
                  request,
                ),
            );
          }
          context.stdout.write(`Note "${noteQuery}" updated.\n`);
        } finally {
          if (secretBytes !== undefined) zeroizeBytes(secretBytes);
        }
      },
    },
    {
      name: 'archive',
      description: 'Archive a note.',
      arguments: [
        { syntax: '<group>', description: 'Group ID, unique name, or alias.' },
        { syntax: '<credential-or-note>', description: 'Credential ID or note query.' },
        { syntax: '[note]', description: 'Note ID, title, or unique prefix.' },
      ],
      options: [secretBackendOption, backendPassphraseStdinOption],
      execute: async (context, arguments_, options) => {
        const groupQuery = requiredArgument(arguments_[0], 'group query');
        const secondArg = requiredArgument(arguments_[1], 'credential or note query');
        const thirdArg = arguments_[2];

        const credentialQuery = thirdArg !== undefined ? secondArg : undefined;
        const noteQuery = thirdArg ?? secondArg;

        const { cliArchiveNoteRequestSchema } = await import('./mutation-contracts.js');
        const request = cliArchiveNoteRequestSchema.parse({
          groupQuery,
          ...(credentialQuery ? { credentialQuery } : {}),
          noteQuery,
        });

        if (context.ports?.archiveNote !== undefined) {
          await context.ports.archiveNote(request);
        } else {
          const { executeProductionArchiveNote } =
            await import('./production/mutations.js');
          await withUnlockedVault(
            context,
            'note archive',
            options,
            async (unlocked, store, rootKey) =>
              executeProductionArchiveNote(
                {
                  source: store,
                  queue: store,
                  vaultId: unlocked.profile.vaultId,
                  rootKey,
                },
                request,
              ),
          );
        }
        context.stdout.write(`Note "${noteQuery}" archived.\n`);
      },
    },
    {
      name: 'restore',
      description: 'Restore an archived note.',
      arguments: [
        { syntax: '<group>', description: 'Group ID, unique name, or alias.' },
        { syntax: '<credential-or-note>', description: 'Credential ID or note query.' },
        { syntax: '[note]', description: 'Note ID, title, or unique prefix.' },
      ],
      options: [secretBackendOption, backendPassphraseStdinOption],
      execute: async (context, arguments_, options) => {
        const groupQuery = requiredArgument(arguments_[0], 'group query');
        const secondArg = requiredArgument(arguments_[1], 'credential or note query');
        const thirdArg = arguments_[2];

        const credentialQuery = thirdArg !== undefined ? secondArg : undefined;
        const noteQuery = thirdArg ?? secondArg;

        const { cliRestoreNoteRequestSchema } = await import('./mutation-contracts.js');
        const request = cliRestoreNoteRequestSchema.parse({
          groupQuery,
          ...(credentialQuery ? { credentialQuery } : {}),
          noteQuery,
        });

        if (context.ports?.restoreNote !== undefined) {
          await context.ports.restoreNote(request);
        } else {
          const { executeProductionRestoreNote } =
            await import('./production/mutations.js');
          await withUnlockedVault(
            context,
            'note restore',
            options,
            async (unlocked, store, rootKey) =>
              executeProductionRestoreNote(
                {
                  source: store,
                  queue: store,
                  vaultId: unlocked.profile.vaultId,
                  rootKey,
                },
                request,
              ),
          );
        }
        context.stdout.write(`Note "${noteQuery}" restored.\n`);
      },
    },
    {
      name: 'remove',
      description: 'Permanently remove a note.',
      arguments: [
        { syntax: '<group>', description: 'Group ID, unique name, or alias.' },
        { syntax: '<credential-or-note>', description: 'Credential ID or note query.' },
        { syntax: '[note]', description: 'Note ID, title, or unique prefix.' },
      ],
      options: [
        { flags: '--force', description: 'Confirm permanent note removal.' },
        secretBackendOption,
        backendPassphraseStdinOption,
      ],
      execute: async (context, arguments_, options) => {
        const groupQuery = requiredArgument(arguments_[0], 'group query');
        const secondArg = requiredArgument(arguments_[1], 'credential or note query');
        const thirdArg = arguments_[2];

        const credentialQuery = thirdArg !== undefined ? secondArg : undefined;
        const noteQuery = thirdArg ?? secondArg;

        const force = optionBoolean(options, 'force');
        if (!force) {
          throw new CliUsageError(
            'The --force flag is required for permanent note removal.',
          );
        }

        const { cliRemoveNoteRequestSchema } = await import('./mutation-contracts.js');
        const request = cliRemoveNoteRequestSchema.parse({
          groupQuery,
          ...(credentialQuery ? { credentialQuery } : {}),
          noteQuery,
        });

        if (context.ports?.removeNote !== undefined) {
          await context.ports.removeNote(request);
        } else {
          const { executeProductionRemoveNote } =
            await import('./production/mutations.js');
          await withUnlockedVault(
            context,
            'note remove',
            options,
            async (unlocked, store, rootKey) =>
              executeProductionRemoveNote(
                {
                  source: store,
                  queue: store,
                  vaultId: unlocked.profile.vaultId,
                  rootKey,
                },
                request,
              ),
          );
        }
        context.stdout.write(`Note "${noteQuery}" removed.\n`);
      },
    },
  ],
});

const attachmentCommand: CliCommandDescriptor = Object.freeze({
  name: 'attachment',
  description: 'Manage encrypted attachments for credential items.',
  options: [secretBackendOption, backendPassphraseStdinOption],
  children: [
    {
      name: 'list',
      description: 'List encrypted attachments for a credential item.',
      arguments: [
        { syntax: '<group>', description: 'Group ID, unique name, or alias.' },
        {
          syntax: '<credential>',
          description: 'Credential ID, unique name, or alias within the group.',
        },
      ],
      options: [jsonOption, secretBackendOption, backendPassphraseStdinOption],
      execute: async (context, arguments_, options) => {
        const groupQuery = requiredArgument(arguments_[0], 'group query');
        const credentialQuery = requiredArgument(arguments_[1], 'credential query');
        const json = optionBoolean(options, 'json');

        let summaries: readonly CliAttachmentSummary[];
        if (context.ports?.listAttachments !== undefined) {
          summaries = await context.ports.listAttachments(groupQuery, credentialQuery);
        } else {
          const { executeProductionListAttachments } =
            await import('./production/mutations.js');
          summaries = await withUnlockedVault(
            context,
            'attachment list',
            options,
            async (unlocked, store, rootKey) =>
              executeProductionListAttachments(
                {
                  source: store,
                  vaultId: unlocked.profile.vaultId,
                  rootKey,
                },
                groupQuery,
                credentialQuery,
              ),
          );
        }
        const { renderAttachmentList } = await import('./render.js');
        context.stdout.write(renderAttachmentList(summaries, json));
      },
    },
    {
      name: 'upload',
      description:
        'Upload a local file as an encrypted attachment to a credential item.',
      arguments: [
        { syntax: '<group>', description: 'Group ID, unique name, or alias.' },
        {
          syntax: '<credential>',
          description: 'Credential ID, unique name, or alias within the group.',
        },
        { syntax: '<file-path>', description: 'Path to the local file to upload.' },
      ],
      options: [jsonOption, secretBackendOption, backendPassphraseStdinOption],
      execute: async (context, arguments_, options) => {
        const groupQuery = requiredArgument(arguments_[0], 'group query');
        const credentialQuery = requiredArgument(arguments_[1], 'credential query');
        const filePath = requiredArgument(arguments_[2], 'file path');
        const json = optionBoolean(options, 'json');

        const { cliUploadAttachmentRequestSchema } =
          await import('./mutation-contracts.js');
        const request = cliUploadAttachmentRequestSchema.parse({
          groupQuery,
          credentialQuery,
          filePath,
        });

        let result: CliAttachmentUploadResult;
        if (context.ports?.uploadAttachment !== undefined) {
          result = await context.ports.uploadAttachment(request);
        } else {
          const { executeProductionUploadAttachment } =
            await import('./production/mutations.js');
          result = await withUnlockedVault(
            context,
            'attachment upload',
            options,
            async (unlocked, store, rootKey) =>
              executeProductionUploadAttachment(
                {
                  source: store,
                  queue: store,
                  vaultId: unlocked.profile.vaultId,
                  rootKey,
                },
                request,
              ),
          );
        }
        const { renderAttachmentUpload } = await import('./render.js');
        context.stdout.write(renderAttachmentUpload(result, json));
      },
    },
    {
      name: 'download',
      description: 'Download and decrypt an attachment to a local file.',
      arguments: [
        { syntax: '<group>', description: 'Group ID, unique name, or alias.' },
        {
          syntax: '<credential>',
          description: 'Credential ID, unique name, or alias within the group.',
        },
        { syntax: '<attachment-id>', description: 'Attachment ID.' },
        { syntax: '<destination-path>', description: 'Local destination file path.' },
      ],
      options: [
        { flags: '--force', description: 'Confirm overwrite of existing file.' },
        jsonOption,
        secretBackendOption,
        backendPassphraseStdinOption,
      ],
      execute: async (context, arguments_, options) => {
        const groupQuery = requiredArgument(arguments_[0], 'group query');
        const credentialQuery = requiredArgument(arguments_[1], 'credential query');
        const attachmentId = requiredArgument(arguments_[2], 'attachment ID');
        const destinationPath = requiredArgument(arguments_[3], 'destination path');
        const force = optionBoolean(options, 'force');
        const json = optionBoolean(options, 'json');

        const { cliDownloadAttachmentRequestSchema } =
          await import('./mutation-contracts.js');
        const request = cliDownloadAttachmentRequestSchema.parse({
          groupQuery,
          credentialQuery,
          attachmentId,
          destinationPath,
          ...(force ? { force } : {}),
        });

        let result: CliAttachmentDownloadResult;
        if (context.ports?.downloadAttachment !== undefined) {
          result = await context.ports.downloadAttachment(request);
        } else {
          const { executeProductionDownloadAttachment } =
            await import('./production/mutations.js');
          result = await withUnlockedVault(
            context,
            'attachment download',
            options,
            async (unlocked, store, rootKey) =>
              executeProductionDownloadAttachment(
                {
                  source: store,
                  vaultId: unlocked.profile.vaultId,
                  rootKey,
                },
                request,
              ),
          );
        }
        const { renderAttachmentDownload } = await import('./render.js');
        context.stdout.write(renderAttachmentDownload(result, json));
      },
    },
    {
      name: 'delete',
      description: 'Delete an encrypted attachment with explicit --force.',
      arguments: [
        { syntax: '<group>', description: 'Group ID, unique name, or alias.' },
        {
          syntax: '<credential>',
          description: 'Credential ID, unique name, or alias within the group.',
        },
        { syntax: '<attachment-id>', description: 'Attachment ID.' },
      ],
      options: [
        { flags: '--force', description: 'Confirm permanent deletion.' },
        jsonOption,
        secretBackendOption,
        backendPassphraseStdinOption,
      ],
      execute: async (context, arguments_, options) => {
        const groupQuery = requiredArgument(arguments_[0], 'group query');
        const credentialQuery = requiredArgument(arguments_[1], 'credential query');
        const attachmentId = requiredArgument(arguments_[2], 'attachment ID');
        const force = optionBoolean(options, 'force');
        const json = optionBoolean(options, 'json');

        const { cliDeleteAttachmentRequestSchema } =
          await import('./mutation-contracts.js');
        const request = cliDeleteAttachmentRequestSchema.parse({
          groupQuery,
          credentialQuery,
          attachmentId,
          ...(force ? { force } : {}),
        });

        let result: CliAttachmentDeleteResult;
        if (context.ports?.deleteAttachment !== undefined) {
          result = await context.ports.deleteAttachment(request);
        } else {
          const { executeProductionDeleteAttachment } =
            await import('./production/mutations.js');
          result = await withUnlockedVault(
            context,
            'attachment delete',
            options,
            async (unlocked, store, rootKey) =>
              executeProductionDeleteAttachment(
                {
                  source: store,
                  queue: store,
                  vaultId: unlocked.profile.vaultId,
                  rootKey,
                },
                request,
              ),
          );
        }
        const { renderAttachmentDelete } = await import('./render.js');
        context.stdout.write(renderAttachmentDelete(result, json));
      },
    },
  ],
});

const historyCommand: CliCommandDescriptor = Object.freeze({
  name: 'history',
  description: 'Manage encrypted item history revisions and projections.',
  options: [secretBackendOption, backendPassphraseStdinOption],
  children: [
    {
      name: 'list',
      description: 'List historical revisions for a credential item.',
      arguments: [
        { syntax: '<group>', description: 'Group ID, unique name, or alias.' },
        {
          syntax: '<credential>',
          description: 'Credential ID, unique name, or alias within the group.',
        },
      ],
      options: [jsonOption, secretBackendOption, backendPassphraseStdinOption],
      execute: async (context, arguments_, options) => {
        const groupQuery = requiredArgument(arguments_[0], 'group query');
        const credentialQuery = requiredArgument(arguments_[1], 'credential query');
        const json = optionBoolean(options, 'json');

        let summaries: readonly CliHistorySummary[];
        if (context.ports?.listHistory !== undefined) {
          summaries = await context.ports.listHistory(groupQuery, credentialQuery);
        } else {
          const { executeProductionListHistory } =
            await import('./production/mutations.js');
          summaries = await withUnlockedVault(
            context,
            'history list',
            options,
            async (unlocked, store, rootKey) =>
              executeProductionListHistory(
                {
                  source: store,
                  vaultId: unlocked.profile.vaultId,
                  rootKey,
                },
                groupQuery,
                credentialQuery,
              ),
          );
        }
        const { renderHistoryList } = await import('./render.js');
        context.stdout.write(renderHistoryList(summaries, json));
      },
    },
    {
      name: 'show',
      description: 'Inspect a historical revision projection with masked values.',
      arguments: [
        { syntax: '<group>', description: 'Group ID, unique name, or alias.' },
        {
          syntax: '<credential>',
          description: 'Credential ID, unique name, or alias within the group.',
        },
        { syntax: '<revision>', description: 'Revision number to inspect.' },
      ],
      options: [jsonOption, secretBackendOption, backendPassphraseStdinOption],
      execute: async (context, arguments_, options) => {
        const groupQuery = requiredArgument(arguments_[0], 'group query');
        const credentialQuery = requiredArgument(arguments_[1], 'credential query');
        const revisionStr = requiredArgument(arguments_[2], 'revision');
        const revision = revisionOptionSchema.parse(revisionStr);
        const json = optionBoolean(options, 'json');

        const { cliShowHistoryRequestSchema } = await import('./mutation-contracts.js');
        const request = cliShowHistoryRequestSchema.parse({
          groupQuery,
          credentialQuery,
          revision,
        });

        let detail: CliHistoryDetail;
        if (context.ports?.showHistory !== undefined) {
          detail = await context.ports.showHistory(request);
        } else {
          const { executeProductionShowHistory } =
            await import('./production/mutations.js');
          detail = await withUnlockedVault(
            context,
            'history show',
            options,
            async (unlocked, store, rootKey) =>
              executeProductionShowHistory(
                {
                  source: store,
                  vaultId: unlocked.profile.vaultId,
                  rootKey,
                },
                request,
              ),
          );
        }
        const { renderHistoryDetail } = await import('./render.js');
        context.stdout.write(renderHistoryDetail(detail, json));
      },
    },
    {
      name: 'diff',
      description: 'Compare changed fields between credential revisions.',
      arguments: [
        { syntax: '<group>', description: 'Group ID, unique name, or alias.' },
        {
          syntax: '<credential>',
          description: 'Credential ID, unique name, or alias within the group.',
        },
        { syntax: '<revision>', description: 'Base revision number.' },
        {
          syntax: '[compare-revision]',
          description: 'Target revision number (defaults to current active revision).',
        },
      ],
      options: [jsonOption, secretBackendOption, backendPassphraseStdinOption],
      execute: async (context, arguments_, options) => {
        const groupQuery = requiredArgument(arguments_[0], 'group query');
        const credentialQuery = requiredArgument(arguments_[1], 'credential query');
        const revisionStr = requiredArgument(arguments_[2], 'revision');
        const revision = revisionOptionSchema.parse(revisionStr);
        const compareRevisionStr = arguments_[3];
        const compareRevision =
          compareRevisionStr !== undefined
            ? revisionOptionSchema.parse(compareRevisionStr)
            : undefined;
        const json = optionBoolean(options, 'json');

        const { cliDiffHistoryRequestSchema } = await import('./mutation-contracts.js');
        const request = cliDiffHistoryRequestSchema.parse({
          groupQuery,
          credentialQuery,
          revision,
          ...(compareRevision !== undefined ? { compareRevision } : {}),
        });

        let diff: CliHistoryDiff;
        if (context.ports?.diffHistory !== undefined) {
          diff = await context.ports.diffHistory(request);
        } else {
          const { executeProductionDiffHistory } =
            await import('./production/mutations.js');
          diff = await withUnlockedVault(
            context,
            'history diff',
            options,
            async (unlocked, store, rootKey) =>
              executeProductionDiffHistory(
                {
                  source: store,
                  vaultId: unlocked.profile.vaultId,
                  rootKey,
                },
                request,
              ),
          );
        }
        const { renderHistoryDiff } = await import('./render.js');
        context.stdout.write(renderHistoryDiff(diff, json));
      },
    },
    {
      name: 'restore',
      description:
        'Restore an exact prior revision as a new mutation with explicit --force.',
      arguments: [
        { syntax: '<group>', description: 'Group ID, unique name, or alias.' },
        {
          syntax: '<credential>',
          description: 'Credential ID, unique name, or alias within the group.',
        },
        { syntax: '<revision>', description: 'Revision number to restore.' },
      ],
      options: [
        {
          flags: '--force',
          description: 'Confirm restoration of historical revision.',
        },
        jsonOption,
        secretBackendOption,
        backendPassphraseStdinOption,
      ],
      execute: async (context, arguments_, options) => {
        const groupQuery = requiredArgument(arguments_[0], 'group query');
        const credentialQuery = requiredArgument(arguments_[1], 'credential query');
        const revisionStr = requiredArgument(arguments_[2], 'revision');
        const revision = revisionOptionSchema.parse(revisionStr);
        const force = optionBoolean(options, 'force');
        const json = optionBoolean(options, 'json');

        const { cliRestoreHistoryRequestSchema } =
          await import('./mutation-contracts.js');
        const request = cliRestoreHistoryRequestSchema.parse({
          groupQuery,
          credentialQuery,
          revision,
          ...(force ? { force } : {}),
        });

        let result: CliHistoryRestoreResult;
        if (context.ports?.restoreHistory !== undefined) {
          result = await context.ports.restoreHistory(request);
        } else {
          const { executeProductionRestoreHistory } =
            await import('./production/mutations.js');
          result = await withUnlockedVault(
            context,
            'history restore',
            options,
            async (unlocked, store, rootKey) =>
              executeProductionRestoreHistory(
                {
                  source: store,
                  queue: store,
                  vaultId: unlocked.profile.vaultId,
                  rootKey,
                },
                request,
              ),
          );
        }
        const { renderHistoryRestore } = await import('./render.js');
        context.stdout.write(renderHistoryRestore(result, json));
      },
    },
  ],
});

/**
 * Options every recovery-code command shares.
 *
 * `--code` is the only selector: recovery codes are addressed by their stable
 * element identifier, never by position, so a list that shifts underneath a
 * script can never cause the wrong code to be consumed.
 */
const recoveryCodeOption: CliOptionDescriptor = Object.freeze({
  flags: '--code <id>',
  description: 'Stable recovery code identifier, or an unambiguous prefix of one.',
});

const recoveryCommand: CliCommandDescriptor = Object.freeze({
  name: 'recovery',
  description: 'List and consume encrypted recovery codes without index ambiguity.',
  options: [secretBackendOption, backendPassphraseStdinOption],
  children: [
    {
      name: 'list',
      description:
        'List recovery codes by identifier and lifecycle with values masked.',
      arguments: [
        { syntax: '<group>', description: 'Group ID, unique name, or alias.' },
        {
          syntax: '<credential>',
          description: 'Credential ID, unique name, or alias within the group.',
        },
        {
          syntax: '<field>',
          description: 'Recovery-code field ID, stable key, exact label, or prefix.',
        },
      ],
      options: [jsonOption, secretBackendOption, backendPassphraseStdinOption],
      execute: async (context, arguments_, options) => {
        const groupQuery = requiredArgument(arguments_[0], 'group query');
        const credentialQuery = requiredArgument(arguments_[1], 'credential query');
        const fieldQuery = requiredArgument(arguments_[2], 'field query');
        const json = optionBoolean(options, 'json');

        const { cliListRecoveryCodesRequestSchema } =
          await import('./mutation-contracts.js');
        const request = cliListRecoveryCodesRequestSchema.parse({
          groupQuery,
          credentialQuery,
          fieldQuery,
        });

        let result: CliRecoveryCodeListResult;
        if (context.ports?.listRecoveryCodes !== undefined) {
          result = await context.ports.listRecoveryCodes(request);
        } else {
          const { executeProductionListRecoveryCodes } =
            await import('./production/mutations.js');
          result = await withUnlockedVault(
            context,
            'recovery list',
            options,
            async (unlocked, store, rootKey) =>
              executeProductionListRecoveryCodes(
                {
                  source: store,
                  vaultId: unlocked.profile.vaultId,
                  rootKey,
                },
                request,
              ),
          );
        }
        const { renderRecoveryCodeList } = await import('./render.js');
        context.stdout.write(renderRecoveryCodeList(result, json));
      },
    },
    {
      name: 'use',
      description: 'Mark one recovery code used without revealing its value.',
      arguments: [
        { syntax: '<group>', description: 'Group ID, unique name, or alias.' },
        {
          syntax: '<credential>',
          description: 'Credential ID, unique name, or alias within the group.',
        },
        {
          syntax: '<field>',
          description: 'Recovery-code field ID, stable key, exact label, or prefix.',
        },
      ],
      options: [
        recoveryCodeOption,
        {
          flags: '--if-revision <number>',
          description: 'Only write when the credential is still at this revision.',
        },
        jsonOption,
        secretBackendOption,
        backendPassphraseStdinOption,
      ],
      execute: async (context, arguments_, options) => {
        const groupQuery = requiredArgument(arguments_[0], 'group query');
        const credentialQuery = requiredArgument(arguments_[1], 'credential query');
        const fieldQuery = requiredArgument(arguments_[2], 'field query');
        const code = await recoveryCodeSelector(options);
        const ifRevision = expectedRevision(options);
        const json = optionBoolean(options, 'json');

        const { cliUseRecoveryCodeRequestSchema } =
          await import('./mutation-contracts.js');
        const request = cliUseRecoveryCodeRequestSchema.parse({
          groupQuery,
          credentialQuery,
          fieldQuery,
          code,
          ...(ifRevision === undefined ? {} : { ifRevision }),
        });

        let result: CliRecoveryCodeUseResult;
        if (context.ports?.useRecoveryCode !== undefined) {
          result = await context.ports.useRecoveryCode(request);
        } else {
          const { executeProductionUseRecoveryCode } =
            await import('./production/mutations.js');
          result = await withUnlockedVault(
            context,
            'recovery use',
            options,
            async (unlocked, store, rootKey) =>
              executeProductionUseRecoveryCode(
                {
                  source: store,
                  queue: store,
                  vaultId: unlocked.profile.vaultId,
                  rootKey,
                },
                request,
              ),
          );
        }
        const { renderRecoveryCodeUse } = await import('./render.js');
        context.stdout.write(renderRecoveryCodeUse(result, json));
      },
    },
    {
      name: 'reveal',
      description: 'Reveal one authorized recovery code, optionally consuming it.',
      arguments: [
        { syntax: '<group>', description: 'Group ID, unique name, or alias.' },
        {
          syntax: '<credential>',
          description: 'Credential ID, unique name, or alias within the group.',
        },
        {
          syntax: '<field>',
          description: 'Recovery-code field ID, stable key, exact label, or prefix.',
        },
      ],
      options: [
        recoveryCodeOption,
        {
          flags: '--use',
          description: 'Mark the code used before it is printed.',
        },
        {
          flags: '--if-revision <number>',
          description: 'Only write when the credential is still at this revision.',
        },
        {
          flags: '--stdout',
          description:
            'Explicitly allow writing revealed secret to non-interactive stdout stream.',
        },
        secretBackendOption,
        backendPassphraseStdinOption,
      ],
      execute: async (context, arguments_, options) => {
        const groupQuery = requiredArgument(arguments_[0], 'group query');
        const credentialQuery = requiredArgument(arguments_[1], 'credential query');
        const fieldQuery = requiredArgument(arguments_[2], 'field query');
        const code = await recoveryCodeSelector(options);
        const use = optionBoolean(options, 'use');
        const ifRevision = expectedRevision(options);

        const allowStdout = optionBoolean(options, 'stdout');
        if (!allowStdout && (context.stdout as { isTTY?: boolean }).isTTY !== true) {
          throw new CliUsageError(
            'Redirection is denied by default for revealed secrets. Use --stdout to explicitly allow streaming.',
          );
        }

        const { cliRevealRecoveryCodeRequestSchema } =
          await import('./mutation-contracts.js');
        const request = cliRevealRecoveryCodeRequestSchema.parse({
          groupQuery,
          credentialQuery,
          fieldQuery,
          code,
          ...(use ? { use: true } : {}),
          ...(ifRevision === undefined ? {} : { ifRevision }),
        });

        let result: CliRecoveryCodeRevealResult;
        if (context.ports?.revealRecoveryCode !== undefined) {
          result = await context.ports.revealRecoveryCode(request);
        } else {
          const { executeProductionRevealRecoveryCode } =
            await import('./production/mutations.js');
          result = await withUnlockedVault(
            context,
            'recovery reveal',
            options,
            async (unlocked, store, rootKey) =>
              executeProductionRevealRecoveryCode(
                {
                  source: store,
                  queue: store,
                  vaultId: unlocked.profile.vaultId,
                  rootKey,
                },
                request,
              ),
          );
        }

        if (result.receipt !== null) {
          const { renderRecoveryCodeUse } = await import('./render.js');
          context.stderr.write(renderRecoveryCodeUse(result.receipt, false));
        }
        context.stdout.write(`${sanitizeTerminalText(result.value)}\n`);
      },
    },
    {
      name: 'copy',
      description: 'Copy one available recovery code to the guarded clipboard.',
      arguments: [
        { syntax: '<group>', description: 'Group ID, unique name, or alias.' },
        {
          syntax: '<credential>',
          description: 'Credential ID, unique name, or alias within the group.',
        },
        {
          syntax: '<field>',
          description: 'Recovery-code field ID, stable key, exact label, or prefix.',
        },
      ],
      options: [recoveryCodeOption, secretBackendOption, backendPassphraseStdinOption],
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
        const elementId = await recoveryCodeSelector(options);

        const copyOpts = { elementId };
        let rawReceipt: unknown;

        if (context.ports?.copy !== undefined) {
          rawReceipt = await context.ports.copy(
            groupQuery,
            credentialQuery,
            fieldQuery,
            copyOpts,
          );
        } else {
          const { executeProductionCopy } = await import('./production/copy.js');
          await withUnlockedVault(
            context,
            'recovery copy',
            options,
            async (unlocked, store, rootKey) => {
              rawReceipt = await executeProductionCopy(
                {
                  source: store,
                  vaultId: unlocked.profile.vaultId,
                  rootKey,
                  clipboard: unlocked.environment.clipboard,
                  signal: unlocked.session.signal,
                },
                groupQuery,
                credentialQuery,
                fieldQuery,
                copyOpts,
              );
            },
          );
        }

        const receipt = parseCopyReceipt(rawReceipt);
        context.stdout.write(renderCopyReceipt(receipt));
      },
    },
  ],
});

const auditCommand: CliCommandDescriptor = Object.freeze({
  name: 'audit',
  description: 'Inspect locally derived, authorized audit events.',
  options: [secretBackendOption, backendPassphraseStdinOption],
  children: [
    {
      name: 'list',
      description: 'List authorized audit events newest first with bounded pagination.',
      options: [
        {
          flags: '--class <device|slot|mutation|backup|recovery>',
          description: 'Restrict the feed to one coarse audit event class.',
        },
        {
          flags: '--limit <1..200>',
          description: 'Maximum number of audit events to return.',
        },
        {
          flags: '--cursor <event-id>',
          description: 'Continue after a previously returned audit event identifier.',
        },
        jsonOption,
        secretBackendOption,
        backendPassphraseStdinOption,
      ],
      execute: async (context, _arguments, options) => {
        const json = optionBoolean(options, 'json');
        const { cliListAuditEventsQuerySchema } =
          await import('./mutation-contracts.js');
        const request = parseInput(
          cliListAuditEventsQuerySchema,
          {
            ...(options['class'] === undefined ? {} : { class: options['class'] }),
            ...(options['limit'] === undefined ? {} : { limit: options['limit'] }),
            ...(options['cursor'] === undefined ? {} : { cursor: options['cursor'] }),
          },
          'audit list request',
        );

        let page: CliAuditEventPage;
        if (context.ports?.listAuditEvents !== undefined) {
          page = await context.ports.listAuditEvents(request);
        } else {
          const { executeProductionListAuditEvents } =
            await import('./production/audit.js');
          page = await withUnlockedVault(
            context,
            'audit list',
            options,
            async (unlocked, store) =>
              executeProductionListAuditEvents(
                { source: store, vaultId: unlocked.profile.vaultId },
                request,
              ),
          );
        }
        const { renderAuditEventList } = await import('./render.js');
        context.stdout.write(renderAuditEventList(page, json));
      },
    },
    {
      name: 'show',
      description: 'Inspect one authorized audit event by its opaque identifier.',
      arguments: [
        {
          syntax: '<event-id>',
          description: 'Audit event identifier from audit list.',
        },
      ],
      options: [jsonOption, secretBackendOption, backendPassphraseStdinOption],
      execute: async (context, arguments_, options) => {
        const eventIdArgument = requiredArgument(
          arguments_[0],
          'audit event identifier',
        );
        const json = optionBoolean(options, 'json');

        const { cliShowAuditEventRequestSchema } =
          await import('./mutation-contracts.js');
        const request = parseInput(
          cliShowAuditEventRequestSchema,
          { eventId: eventIdArgument },
          'audit event identifier',
        );

        let detail: CliAuditEventDetail;
        if (context.ports?.showAuditEvent !== undefined) {
          detail = await context.ports.showAuditEvent(request);
        } else {
          const { executeProductionShowAuditEvent } =
            await import('./production/audit.js');
          detail = await withUnlockedVault(
            context,
            'audit show',
            options,
            async (unlocked, store) =>
              executeProductionShowAuditEvent(
                { source: store, vaultId: unlocked.profile.vaultId },
                request,
              ),
          );
        }
        const { renderAuditEventDetail } = await import('./render.js');
        context.stdout.write(renderAuditEventDetail(detail, json));
      },
    },
  ],
});

const showCommand: CliCommandDescriptor = Object.freeze({
  name: 'show',
  description: 'Show a schema-driven item with secret fields redacted.',
  arguments: [
    { syntax: '<group>', description: 'Group ID, unique name, or alias.' },
    {
      syntax: '<credential>',
      description: 'Credential ID, unique name, or alias within the group.',
    },
  ],
  options: [jsonOption, secretBackendOption, backendPassphraseStdinOption],
  execute: async (context, arguments_, options) => {
    const [{ parseShowResult }, { renderShow }] = await Promise.all([
      import('./contracts.js'),
      import('./render.js'),
    ]);
    const groupQuery = parseInput(querySchema, arguments_[0], 'group query');
    const credentialQuery = parseInput(querySchema, arguments_[1], 'credential query');

    let rawResult: unknown;
    if (context.ports?.show !== undefined) {
      rawResult = await context.ports.show(groupQuery, credentialQuery);
    } else {
      const { executeProductionShow } = await import('./production/show.js');
      const { projectCredentialShow } = await import('@kavrix/client/cli-contracts');
      await withUnlockedVault(
        context,
        'show',
        options,
        async (unlocked, store, rootKey) => {
          rawResult = projectCredentialShow(
            await executeProductionShow(
              {
                source: store,
                vaultId: unlocked.profile.vaultId,
                rootKey,
              },
              groupQuery,
              credentialQuery,
            ),
          );
        },
      );
    }

    const result = parseShowResult(rawResult);
    context.stdout.write(renderShow(result, optionBoolean(options, 'json')));
  },
});

const copyCommand: CliCommandDescriptor = Object.freeze({
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
    secretBackendOption,
    backendPassphraseStdinOption,
  ],
  execute: async (context, arguments_, options) => {
    const [{ parseCopyReceipt }, { renderCopyReceipt }] = await Promise.all([
      import('./contracts.js'),
      import('./render.js'),
    ]);
    const groupQuery = parseInput(querySchema, arguments_[0], 'group query');
    const credentialQuery = parseInput(querySchema, arguments_[1], 'credential query');
    const fieldQuery = parseInput(querySchema, arguments_[2], 'field query');
    const rawIndex = options['index'];
    const index =
      rawIndex === undefined
        ? undefined
        : parseInput(fieldIndexOptionSchema, rawIndex, 'field index');

    const copyOpts = index === undefined ? {} : { index };
    let rawReceipt: unknown;

    if (context.ports?.copy !== undefined) {
      rawReceipt = await context.ports.copy(
        groupQuery,
        credentialQuery,
        fieldQuery,
        copyOpts,
      );
    } else {
      const { executeProductionCopy } = await import('./production/copy.js');
      await withUnlockedVault(
        context,
        'copy',
        options,
        async (unlocked, store, rootKey) => {
          rawReceipt = await executeProductionCopy(
            {
              source: store,
              vaultId: unlocked.profile.vaultId,
              rootKey,
              clipboard: unlocked.environment.clipboard,
              signal: unlocked.session.signal,
            },
            groupQuery,
            credentialQuery,
            fieldQuery,
            copyOpts,
          );
        },
      );
    }

    const receipt = parseCopyReceipt(rawReceipt);
    context.stdout.write(renderCopyReceipt(receipt));
  },
});

const revealCommand: CliCommandDescriptor = Object.freeze({
  name: 'reveal',
  description: 'Reveal an authorized credential field value.',
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
    {
      flags: '--stdout',
      description:
        'Explicitly allow writing revealed secret to non-interactive stdout stream.',
    },
    secretBackendOption,
    backendPassphraseStdinOption,
  ],
  execute: async (context, arguments_, options) => {
    const groupQuery = parseInput(querySchema, arguments_[0], 'group query');
    const credentialQuery = parseInput(querySchema, arguments_[1], 'credential query');
    const fieldQuery = parseInput(querySchema, arguments_[2], 'field query');
    const rawIndex = options['index'];
    const index =
      rawIndex === undefined
        ? undefined
        : parseInput(fieldIndexOptionSchema, rawIndex, 'field index');

    const allowStdout = optionBoolean(options, 'stdout');
    if (!allowStdout && (context.stdout as { isTTY?: boolean }).isTTY !== true) {
      throw new CliUsageError(
        'Redirection is denied by default for revealed secrets. Use --stdout to explicitly allow streaming.',
      );
    }

    const revealOpts = index === undefined ? {} : { index };
    let revealedValue: string;

    if (context.ports?.reveal !== undefined) {
      const res = await context.ports.reveal(
        groupQuery,
        credentialQuery,
        fieldQuery,
        revealOpts,
      );
      revealedValue = res.value;
    } else {
      const { executeProductionReveal } = await import('./production/reveal.js');
      let resultVal: string | undefined;
      await withUnlockedVault(
        context,
        'reveal',
        options,
        async (unlocked, store, rootKey) => {
          const res = await executeProductionReveal(
            {
              source: store,
              vaultId: unlocked.profile.vaultId,
              rootKey,
            },
            groupQuery,
            credentialQuery,
            fieldQuery,
            revealOpts,
          );
          resultVal = res.value;
        },
      );
      if (resultVal === undefined) {
        throw new Error('Failed to reveal value');
      }
      revealedValue = resultVal;
    }

    context.stdout.write(`${sanitizeTerminalText(revealedValue)}\n`);
  },
});

const getCommand: CliCommandDescriptor = Object.freeze({
  name: 'get',
  description: 'Get one credential field value.',
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
    {
      flags: '--reveal',
      description: 'Explicitly allow outputting sensitive/secret field value.',
    },
    {
      flags: '--json',
      description: 'Format response as structured JSON.',
    },
    secretBackendOption,
    backendPassphraseStdinOption,
  ],
  execute: async (context, arguments_, options) => {
    const groupQuery = parseInput(querySchema, arguments_[0], 'group query');
    const credentialQuery = parseInput(querySchema, arguments_[1], 'credential query');
    const fieldQuery = parseInput(querySchema, arguments_[2], 'field query');
    const rawIndex = options['index'];
    const index =
      rawIndex === undefined
        ? undefined
        : parseInput(fieldIndexOptionSchema, rawIndex, 'field index');

    const reveal = optionBoolean(options, 'reveal');
    const asJson = optionBoolean(options, 'json');

    const getOpts = {
      ...(index === undefined ? {} : { index }),
      ...(reveal ? { reveal: true } : {}),
    };

    let result: CliFieldReadResult;

    if (context.ports?.get !== undefined) {
      result = await context.ports.get(
        groupQuery,
        credentialQuery,
        fieldQuery,
        getOpts,
      );
    } else {
      const { executeProductionGet } = await import('./production/get.js');
      let resultVal: CliFieldReadResult | undefined;
      await withUnlockedVault(
        context,
        'get',
        options,
        async (unlocked, store, rootKey) => {
          resultVal = await executeProductionGet(
            {
              source: store,
              vaultId: unlocked.profile.vaultId,
              rootKey,
            },
            groupQuery,
            credentialQuery,
            fieldQuery,
            getOpts,
          );
        },
      );
      if (resultVal === undefined) {
        throw new Error('Failed to get field value');
      }
      result = resultVal;
    }

    const { renderFieldRead } = await import('./render.js');
    context.stdout.write(renderFieldRead(result, asJson));
  },
});

/**
 * Scriptable sibling of `field set`, so a script can pair `get` with a write
 * without descending into the `field` family. Both share one handler because a
 * second copy of the write path could drift away from these guarantees.
 */
const setCommand: CliCommandDescriptor = Object.freeze({
  name: 'set',
  description: 'Set one credential field value.',
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
      flags: SECRET_INPUT_OPTIONS.fieldValue.flag,
      description: SECRET_INPUT_OPTIONS.fieldValue.description,
    },
    {
      flags: '--create',
      description: 'Create the field when no existing field matches.',
    },
    ...fieldWriteOptions,
    secretBackendOption,
    backendPassphraseStdinOption,
  ],
  execute: async (context, arguments_, options) => {
    await executeFieldSet('set', context, arguments_, options);
  },
});

/** Scriptable sibling of `field update`, sharing that command's handler. */
const updateCommand: CliCommandDescriptor = Object.freeze({
  name: 'update',
  description: 'Update one credential field definition.',
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
    { flags: '--label <text>', description: 'Updated field display label.' },
    { flags: '--type <type>', description: 'Updated canonical field type.' },
    { flags: '--sensitive', description: 'Mark field as sensitive.' },
    { flags: '--no-sensitive', description: 'Mark field as non-sensitive.' },
    ...fieldWriteOptions,
    secretBackendOption,
    backendPassphraseStdinOption,
  ],
  execute: async (context, arguments_, options) => {
    await executeFieldUpdate('update', context, arguments_, options);
  },
});

const runCommand: CliCommandDescriptor = Object.freeze({
  name: 'run',
  description: 'Run a command with credential fields released into its environment.',
  arguments: [
    {
      syntax: '<executable>',
      description: 'Program to run. Resolved by the operating system without a shell.',
    },
    {
      syntax: '[args...]',
      description:
        'Arguments relayed verbatim to the program. Every flag after <executable> belongs to the program, so the options of this command must be given first.',
    },
  ],
  passThrough: true,
  options: [
    {
      flags: '--env <NAME=group/credential/field>',
      description:
        'Release one field into NAME. Repeatable. Append #index for a repeatable field.',
      repeatable: true,
    },
    {
      flags: '--inherit <names>',
      description:
        'Comma-separated allow-list of parent variables the child may inherit.',
    },
    {
      flags: '--cwd <path>',
      description:
        'Working directory for the child. Defaults to the current directory.',
    },
    {
      flags: '--timeout <milliseconds>',
      description: 'Terminate the child after this many milliseconds.',
    },
    {
      flags: '--max-output <bytes>',
      description: 'Capture limit per stream. Output beyond the limit is truncated.',
    },
    {
      flags: '--dry-run',
      description:
        'Validate and print the plan without unlocking the vault or starting the command.',
    },
    jsonOption,
    secretBackendOption,
    backendPassphraseStdinOption,
  ],
  execute: async (context, arguments_, options) => {
    const { cliRunQuerySchema } = await import('./mutation-contracts.js');
    const rawEnvironment = options['env'];
    // Passthrough relays every operand untouched, so a separator written out of
    // habit would otherwise reach the program as a real argument. Only one
    // leading separator is consumed; a later `--` is the program's own argument.
    const relayed = arguments_.slice(1);
    const childArguments = relayed[0] === '--' ? relayed.slice(1) : relayed;
    const request = parseInput(
      cliRunQuerySchema,
      {
        executable: arguments_[0] ?? '',
        arguments: childArguments,
        // The repeatable collector always leaves an array behind, so an omitted
        // flag arrives as an empty list rather than as undefined.
        env: Array.isArray(rawEnvironment) ? rawEnvironment : [],
        inherit: options['inherit'],
        cwd: options['cwd'],
        timeout: options['timeout'],
        maxOutput: options['maxOutput'],
        dryRun: optionBoolean(options, 'dryRun'),
      },
      'run request',
    );

    const nodePath = await import('node:path');
    const { RUNNER_LIMITS } = await import('@kavrix/runner');
    // The executor requires an absolute working directory, so the relative form
    // is resolved here and reported in both the plan and the injected request.
    const cwd = nodePath.resolve(request.cwd ?? process.cwd());
    const maxOutputBytes = request.maxOutputBytes ?? RUNNER_LIMITS.defaultCaptureBytes;
    const json = optionBoolean(options, 'json');

    if (request.dryRun === true) {
      // Built from the parsed request alone. No vault is opened and no field is
      // read, so a dry run cannot decrypt anything. It therefore confirms the
      // shape of the invocation, not that every address resolves.
      const { renderRunPlan } = await import('./render.js');
      context.stdout.write(
        renderRunPlan(
          {
            executable: request.executable,
            argumentCount: request.arguments.length,
            environmentNames: request.environment.map((mapping) => mapping.name),
            inherited: request.inherit,
            cwd,
            timeoutMs: request.timeoutMs ?? null,
            maxOutputBytes,
          },
          json,
        ),
      );
      return;
    }

    const invocation = { ...request, cwd, maxOutputBytes };
    const result =
      context.ports?.run !== undefined
        ? await context.ports.run(invocation)
        : await withUnlockedVault(
            context,
            'run',
            options,
            async (unlocked, store, rootKey) => {
              const { executeProductionRun } = await import('./production/run.js');
              return executeProductionRun(
                {
                  source: store,
                  vaultId: unlocked.profile.vaultId,
                  rootKey,
                  cwd,
                  signal: unlocked.session.signal,
                },
                invocation,
              );
            },
          );

    const { renderRunResult } = await import('./render.js');
    context.stdout.write(renderRunResult(result, json));
    if (result.termination !== 'exit' || result.exitCode !== 0) {
      // The child's own exit code, signal, and termination reason are already
      // rendered above. Failing here keeps the CLI from presenting a failed
      // child as a successful command.
      throw new CliRunFailedError(result.termination, result.exitCode);
    }
  },
});

const syncConflictsCommand: CliCommandDescriptor = Object.freeze({
  name: 'conflicts',
  description: 'List and resolve explicit synchronization conflicts.',
  children: [
    {
      name: 'list',
      description: 'List redacted unresolved conflict metadata.',
      options: [jsonOption],
      execute: async (context, _arguments, options) => {
        let raw: unknown;
        if (context.ports?.listConflicts !== undefined) {
          raw = await context.ports.listConflicts();
        } else {
          const { executeProductionConflictList } =
            await import('./production/conflicts.js');
          raw = await executeProductionConflictList({
            environment: context.environment ?? process.env,
            secrets: secretInput(context, 'sync conflicts list'),
            backendPolicy: parseStatusBackendPolicy(options),
          });
        }
        const { parseConflicts } = await import('./contracts.js');
        const { renderConflicts } = await import('./render.js');
        context.stdout.write(
          renderConflicts(parseConflicts(raw), optionBoolean(options, 'json')),
        );
      },
    },
    {
      name: 'resolve',
      description: 'Resolve one conflict at an exact displayed revision.',
      arguments: [
        { syntax: '<conflict-id>', description: 'Opaque mutation conflict ID.' },
      ],
      options: [
        {
          flags: '--strategy <keep-local|accept-remote>',
          description: 'Keep the encrypted local mutation or accept the remote record.',
        },
        {
          flags: '--revision <number>',
          description: 'Exact current revision shown by conflict list.',
        },
        jsonOption,
      ],
      execute: async (context, arguments_, options) => {
        const conflictId = requiredArgument(arguments_[0], 'conflict ID');
        const strategy = parseInput(
          conflictStrategySchema,
          requiredOption(options, 'strategy', 'resolution strategy'),
          'resolution strategy',
        );
        const currentRevision = parseInput(
          revisionOptionSchema,
          requiredOption(options, 'revision', 'current revision'),
          'current revision',
        );
        const { parseConflictResolutionRequest } = await import('./contracts.js');
        const request = parseConflictResolutionRequest({
          conflictId,
          currentRevision,
          strategy,
        });
        let raw: unknown;
        if (context.ports?.resolveConflict !== undefined) {
          raw = await context.ports.resolveConflict(request);
        } else {
          const { executeProductionConflictResolution } =
            await import('./production/conflicts.js');
          raw = await executeProductionConflictResolution(
            {
              environment: context.environment ?? process.env,
              secrets: secretInput(context, 'sync conflicts resolve'),
              backendPolicy: parseStatusBackendPolicy(options),
            },
            request,
          );
        }
        const { parseConflictResolutionResult } = await import('./contracts.js');
        const { renderConflictResolution } = await import('./render.js');
        context.stdout.write(
          renderConflictResolution(
            parseConflictResolutionResult(raw),
            optionBoolean(options, 'json'),
          ),
        );
      },
    },
  ],
});

const syncCommand: CliCommandDescriptor = Object.freeze({
  name: 'sync',
  description: 'Synchronize vault data with server and print updated status.',
  options: [jsonOption, secretBackendOption, backendPassphraseStdinOption],
  children: [syncConflictsCommand],
  execute: async (context, _arguments, options) => {
    let rawStatus: unknown;
    if (context.ports?.sync !== undefined) {
      rawStatus = await context.ports.sync();
    } else {
      const { executeProductionSync } = await import('./production/sync.js');
      const backendPolicy = parseStatusBackendPolicy(options);
      rawStatus = await executeProductionSync({
        environment: context.environment ?? process.env,
        secrets: secretInput(context, 'sync'),
        backendPolicy,
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

const backupCommand: CliCommandDescriptor = Object.freeze({
  name: 'backup',
  description: 'Create and verify authenticated encrypted vault archives.',
  children: [
    {
      name: 'create',
      description: 'Create one bounded encrypted archive without replacing a file.',
      options: [
        {
          flags: '--file <path>',
          description: 'New archive path; existing files and links are refused.',
        },
        vaultOption,
        jsonOption,
        secretBackendOption,
        backendPassphraseStdinOption,
      ],
      execute: async (context, _arguments, options) => {
        const { parseBackupCreateRequest, parseBackupCreateResult } =
          await import('./contracts.js');
        const request = parseBackupCreateRequest({
          destination: requiredOption(options, 'file', 'backup destination'),
          ...(options['vault'] === undefined
            ? {}
            : {
                vaultId: parseInputString(options, 'vault', (value) =>
                  vaultIdSchema.parse(value),
                ),
              }),
        });
        let raw: unknown;
        if (context.ports?.createBackup !== undefined) {
          raw = await context.ports.createBackup(request);
        } else {
          if (context.environment === undefined) {
            throw new CliUnavailableError('backup create');
          }
          const { executeProductionBackupCreate } =
            await import('./production/backups.js');
          raw = await executeProductionBackupCreate({
            environment: context.environment,
            secrets: secretInput(context, 'backup create'),
            backendPolicy: parseStatusBackendPolicy(options),
            destination: request.destination,
            ...(request.vaultId === undefined ? {} : { vaultId: request.vaultId }),
          });
        }
        const { renderBackupCreate } = await import('./render.js');
        context.stdout.write(
          renderBackupCreate(
            parseBackupCreateResult(raw),
            optionBoolean(options, 'json'),
          ),
        );
      },
    },
    {
      name: 'verify',
      description: 'Authenticate one complete archive without publishing it.',
      options: [
        {
          flags: '--file <path>',
          description: 'Existing archive path; it is opened read-only.',
        },
        vaultOption,
        jsonOption,
        secretBackendOption,
        backendPassphraseStdinOption,
      ],
      execute: async (context, _arguments, options) => {
        const { parseBackupVerifyRequest, parseBackupVerifyResult } =
          await import('./contracts.js');
        const request = parseBackupVerifyRequest({
          source: requiredOption(options, 'file', 'backup archive'),
          ...(options['vault'] === undefined
            ? {}
            : {
                vaultId: parseInputString(options, 'vault', (value) =>
                  vaultIdSchema.parse(value),
                ),
              }),
        });
        let raw: unknown;
        if (context.ports?.verifyBackup !== undefined) {
          raw = await context.ports.verifyBackup(request);
        } else {
          if (context.environment === undefined) {
            throw new CliUnavailableError('backup verify');
          }
          const { executeProductionBackupVerify } =
            await import('./production/backups.js');
          raw = await executeProductionBackupVerify({
            environment: context.environment,
            secrets: secretInput(context, 'backup verify'),
            backendPolicy: parseStatusBackendPolicy(options),
            source: request.source,
            ...(request.vaultId === undefined ? {} : { vaultId: request.vaultId }),
          });
        }
        const { renderBackupVerify } = await import('./render.js');
        context.stdout.write(
          renderBackupVerify(
            parseBackupVerifyResult(raw),
            optionBoolean(options, 'json'),
          ),
        );
      },
    },
    {
      name: 'restore',
      description: 'Restore one authenticated archive into an isolated target.',
      options: [
        {
          flags: '--file <path>',
          description: 'Existing archive path; it is opened read-only.',
        },
        vaultOption,
        {
          flags: '--slot <slot-id>',
          description: 'Exact archived portable, passphrase, or recovery slot to use.',
        },
        jsonOption,
        secretBackendOption,
        backendPassphraseStdinOption,
      ],
      execute: async (context, _arguments, options) => {
        const { parseBackupRestoreRequest, parseBackupRestoreResult } =
          await import('./contracts.js');
        const request = parseBackupRestoreRequest({
          source: requiredOption(options, 'file', 'backup archive'),
          ...(options['vault'] === undefined
            ? {}
            : {
                vaultId: parseInputString(options, 'vault', (value) =>
                  vaultIdSchema.parse(value),
                ),
              }),
          ...(options['slot'] === undefined
            ? {}
            : {
                slotId: parseInputString(options, 'slot', (value) =>
                  keySlotIdSchema.parse(value),
                ),
              }),
        });
        if (context.ports?.restoreBackup === undefined) {
          throw new CliUnavailableError('backup restore');
        }
        const raw = await context.ports.restoreBackup(request);
        const { renderBackupRestore } = await import('./render.js');
        context.stdout.write(
          renderBackupRestore(
            parseBackupRestoreResult(raw),
            optionBoolean(options, 'json'),
          ),
        );
      },
    },
  ],
});

const transferPassphraseStdinOption: CliOptionDescriptor = Object.freeze({
  flags: '--transfer-passphrase-stdin',
  description:
    'Read the transfer passphrase from standard input instead of a masked prompt.',
});

/**
 * Acquire the passphrase that protects a transfer file.
 *
 * A transfer passphrase is never the vault passphrase: it protects one portable
 * file and nothing else. Export confirms it twice because a mistyped passphrase
 * would produce a file nobody can ever open.
 */
async function readTransferPassphrase(
  context: CliCommandContext,
  feature: Extract<CliFeature, 'transfer export' | 'transfer import'>,
  fromStdin: boolean,
): Promise<Uint8Array> {
  const secrets = secretInput(context, feature);
  if (feature === 'transfer import') {
    return Buffer.from(await secrets.read({ kind: 'passphrase', fromStdin }), 'utf8');
  }
  const values = await secrets.readBatch({
    kinds: ['passphrase', 'passphrase'],
    fromStdin,
    requireEnd: fromStdin,
  });
  const first = values[0];
  const second = values[1];
  if (first === undefined || second === undefined) {
    throw new CliUsageError('Transfer passphrase confirmation is incomplete.');
  }
  await assertMatchingPassphrases(first, second);
  return Buffer.from(first, 'utf8');
}

const transferCommand: CliCommandDescriptor = Object.freeze({
  name: 'transfer',
  description:
    'Move groups between vaults through a guarded, separately encrypted transfer file.',
  children: [
    {
      name: 'export',
      description:
        'Write one policy-filtered encrypted transfer without replacing a file.',
      options: [
        {
          flags: '--file <path>',
          description: 'New transfer path; existing files and links are refused.',
        },
        {
          flags: '--group <group>',
          description: 'Export one group only, by ID, unique name, or alias.',
        },
        vaultOption,
        jsonOption,
        secretBackendOption,
        backendPassphraseStdinOption,
        transferPassphraseStdinOption,
      ],
      execute: async (context, _arguments, options) => {
        const { parseTransferExportRequest, parseTransferExportResult } =
          await import('./contracts.js');
        const request = parseTransferExportRequest({
          destination: requiredOption(options, 'file', 'transfer destination'),
          ...(options['group'] === undefined
            ? {}
            : { groupQuery: requiredOption(options, 'group', 'group query') }),
          ...(options['vault'] === undefined
            ? {}
            : {
                vaultId: parseInputString(options, 'vault', (value) =>
                  vaultIdSchema.parse(value),
                ),
              }),
        });
        let raw: unknown;
        if (context.ports?.exportTransfer !== undefined) {
          raw = await context.ports.exportTransfer(request);
        } else {
          const passphrase = await readTransferPassphrase(
            context,
            'transfer export',
            optionBoolean(options, 'transferPassphraseStdin'),
          );
          try {
            const { executeProductionTransferExport } =
              await import('./production/transfers.js');
            raw = await withUnlockedVault(
              context,
              'transfer export',
              options,
              async (unlocked, store, rootKey) =>
                executeProductionTransferExport(
                  { source: store, vaultId: unlocked.profile.vaultId, rootKey },
                  {
                    destination: request.destination,
                    passphrase,
                    ...(request.groupQuery === undefined
                      ? {}
                      : { groupQuery: request.groupQuery }),
                  },
                ),
            );
          } finally {
            zeroizeBytes(passphrase);
          }
        }
        const { renderTransferExport } = await import('./render.js');
        context.stdout.write(
          renderTransferExport(
            parseTransferExportResult(raw),
            optionBoolean(options, 'json'),
          ),
        );
      },
    },
    {
      name: 'import',
      description:
        'Apply one authenticated encrypted transfer after it verifies completely.',
      options: [
        {
          flags: '--file <path>',
          description: 'Existing transfer path; it is opened read-only.',
        },
        {
          flags: '--on-collision <strategy>',
          description:
            'How to treat a group name that already exists: fail, skip, or rename.',
        },
        vaultOption,
        jsonOption,
        secretBackendOption,
        backendPassphraseStdinOption,
        transferPassphraseStdinOption,
      ],
      execute: async (context, _arguments, options) => {
        const { parseTransferImportRequest, parseTransferImportResult } =
          await import('./contracts.js');
        const request = parseTransferImportRequest({
          source: requiredOption(options, 'file', 'transfer archive'),
          onCollision: parseInput(
            transferCollisionStrategySchema,
            options['onCollision'] ?? 'fail',
            'collision strategy',
          ),
          ...(options['vault'] === undefined
            ? {}
            : {
                vaultId: parseInputString(options, 'vault', (value) =>
                  vaultIdSchema.parse(value),
                ),
              }),
        });
        let raw: unknown;
        if (context.ports?.importTransfer !== undefined) {
          raw = await context.ports.importTransfer(request);
        } else {
          const passphrase = await readTransferPassphrase(
            context,
            'transfer import',
            optionBoolean(options, 'transferPassphraseStdin'),
          );
          try {
            const { executeProductionTransferImport } =
              await import('./production/transfers.js');
            raw = await withUnlockedVault(
              context,
              'transfer import',
              options,
              async (unlocked, store, rootKey) =>
                executeProductionTransferImport(
                  {
                    source: store,
                    queue: store,
                    vaultId: unlocked.profile.vaultId,
                    rootKey,
                  },
                  {
                    source: request.source,
                    passphrase,
                    onCollision: request.onCollision,
                  },
                ),
            );
          } finally {
            zeroizeBytes(passphrase);
          }
        }
        const { renderTransferImport } = await import('./render.js');
        context.stdout.write(
          renderTransferImport(
            parseTransferImportResult(raw),
            optionBoolean(options, 'json'),
          ),
        );
      },
    },
  ],
});

export const CLI_COMMAND_CATALOG: readonly CliCommandDescriptor[] = Object.freeze([
  versionCommand,
  generationCommand,
  totpCommand,
  keyCommand,
  initializationCommand,
  connectCommand,
  recoverCommand,
  unlockCommand,
  lockCommand,
  statusCommand,
  templateCommand,
  groupCommand,
  credentialCommand,
  fieldCommand,
  noteCommand,
  attachmentCommand,
  historyCommand,
  recoveryCommand,
  auditCommand,
  showCommand,
  copyCommand,
  revealCommand,
  getCommand,
  setCommand,
  updateCommand,
  runCommand,
  syncCommand,
  backupCommand,
  transferCommand,
  {
    name: 'device',
    description: 'Manage this device and zero-knowledge enrollment.',
    children: [
      {
        name: 'invite',
        description: 'Create, list, revoke, or redeem device invites.',
        children: [
          {
            name: 'create',
            description: 'Issue one short-lived device enrollment invite.',
            options: [
              vaultOption,
              {
                flags: '--scope <scope...>',
                description:
                  'Granted API scope(s): sync:read, sync:write, or device:manage.',
              },
              {
                flags: '--expires-in-seconds <60..86400>',
                description: 'Invite lifetime in seconds.',
                defaultValue: '600',
              },
              secretStdoutOption,
              jsonOption,
              secretBackendOption,
              backendPassphraseStdinOption,
            ],
            execute: async (context, _arguments, options) => {
              const vaultId = parseInputString(options, 'vault', (value) =>
                vaultIdSchema.parse(value),
              );
              const request = parseInviteIssueRequest(options);
              requireSecretOutputAuthorization(context, options);
              const raw = await withAuthorizedPorts(
                context,
                'device invite create',
                options,
                (ports) => {
                  if (ports.issueInvite === undefined) {
                    throw new CliUnavailableError('device invite create');
                  }
                  return ports.issueInvite(vaultId, request);
                },
              );
              const { inviteIssueResponseSchema } = await import('@kavrix/schemas');
              const { renderInviteIssue } = await import('./render.js');
              context.stdout.write(
                renderInviteIssue(
                  inviteIssueResponseSchema.parse(raw),
                  optionBoolean(options, 'json'),
                ),
              );
            },
          },
          {
            name: 'list',
            description: 'List public invite metadata.',
            options: [
              vaultOption,
              {
                flags: '--limit <1..200>',
                description: 'Maximum number of invites to return.',
              },
              {
                flags: '--cursor <opaque>',
                description: 'Continue from an opaque invite page cursor.',
              },
              jsonOption,
              secretBackendOption,
              backendPassphraseStdinOption,
            ],
            execute: async (context, _arguments, options) => {
              const [{ parseInvitePage, parseVaultId }, { renderInvites }] =
                await Promise.all([import('./contracts.js'), import('./render.js')]);
              const vaultId = parseInputString(options, 'vault', parseVaultId);
              const pageOptions = parseInput(
                controlListPageQuerySchema,
                {
                  ...(options['limit'] === undefined
                    ? {}
                    : { limit: options['limit'] }),
                  ...(options['cursor'] === undefined
                    ? {}
                    : { cursor: options['cursor'] }),
                },
                'invite list options',
              );
              const page = parseInvitePage(
                await withAuthorizedPorts(
                  context,
                  'device invite list',
                  options,
                  (ports) => ports.listInvitePage(vaultId, pageOptions),
                ),
              );
              context.stdout.write(renderInvites(page, optionBoolean(options, 'json')));
            },
          },
          {
            name: 'revoke',
            description: 'Revoke an unused invite by opaque ID.',
            arguments: [
              { syntax: '<invite-id>', description: 'Opaque invite identifier.' },
            ],
            options: [vaultOption, secretBackendOption, backendPassphraseStdinOption],
            execute: async (context, arguments_, options) => {
              const { parseInviteId, parseVaultId } = await import('./contracts.js');
              const vaultId = parseInputString(options, 'vault', parseVaultId);
              const inviteId = parseInputValue(
                requiredArgument(arguments_[0], 'invite ID'),
                'invite ID',
                parseInviteId,
              );
              await withAuthorizedPorts(
                context,
                'device invite revoke',
                options,
                (ports) => ports.revokeInvite(vaultId, inviteId),
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
      {
        name: 'list',
        description: 'List canonical public device metadata.',
        options: [
          vaultOption,
          {
            flags: '--limit <1..200>',
            description: 'Maximum number of devices to return.',
          },
          {
            flags: '--cursor <opaque>',
            description: 'Continue from an opaque device page cursor.',
          },
          jsonOption,
          secretBackendOption,
          backendPassphraseStdinOption,
        ],
        execute: async (context, _arguments, options) => {
          const [{ parseDevicePage, parseVaultId }, { renderDevices }] =
            await Promise.all([import('./contracts.js'), import('./render.js')]);
          const vaultId = parseInputString(options, 'vault', parseVaultId);
          const pageOptions = parseInput(
            controlListPageQuerySchema,
            {
              ...(options['limit'] === undefined ? {} : { limit: options['limit'] }),
              ...(options['cursor'] === undefined ? {} : { cursor: options['cursor'] }),
            },
            'device list options',
          );
          const page = parseDevicePage(
            await withAuthorizedPorts(context, 'device list', options, (ports) => {
              if (ports.listDevicePage === undefined) {
                throw new CliUnavailableError('device list');
              }
              return ports.listDevicePage(vaultId, pageOptions);
            }),
          );
          context.stdout.write(renderDevices(page, optionBoolean(options, 'json')));
        },
      },
      {
        name: 'revoke',
        description: 'Revoke the current or another device by opaque ID.',
        arguments: [
          { syntax: '<device-id>', description: 'Opaque device identifier.' },
        ],
        options: [
          vaultOption,
          {
            flags: '--confirm',
            description:
              'Confirm revocation, including current-device revocation when another active device remains.',
          },
          secretBackendOption,
          backendPassphraseStdinOption,
        ],
        execute: async (context, arguments_, options) => {
          const { parseVaultId } = await import('./contracts.js');
          const vaultId = parseInputString(options, 'vault', parseVaultId);
          const deviceId = parseInputValue(
            requiredArgument(arguments_[0], 'device ID'),
            'device ID',
            (value) => deviceIdSchema.parse(value),
          );
          if (!optionBoolean(options, 'confirm')) {
            throw new CliUsageError(
              'Device revocation requires explicit --confirm acknowledgement.',
            );
          }
          await withAuthorizedPorts(context, 'device revoke', options, (ports) => {
            if (ports.revokeDevice === undefined) {
              throw new CliUnavailableError('device revoke');
            }
            return ports.revokeDevice(vaultId, deviceId);
          });
          context.stdout.write('Device revoked.\n');
        },
      },
      {
        name: 'remember',
        description: 'Create a device unlock slot in the native keychain.',
        options: slotLifecycleOptions(false),
        execute: async (context, _arguments, options) => {
          const operation = await acquireCreateSlotOperation(
            context,
            options,
            'device-key',
          );
          const raw =
            context.ports?.createKeySlot === undefined
              ? await executeProductionKeySlotOperation(
                  context,
                  options,
                  operation,
                  'device remember',
                )
              : await context.ports.createKeySlot(operation);
          const { renderDeviceKeyAction } = await import('./render.js');
          context.stdout.write(
            renderDeviceKeyAction(
              cliKeySlotResultSchema.parse(raw),
              'remembered',
              optionBoolean(options, 'json'),
            ),
          );
        },
      },
      {
        name: 'forget',
        description: 'Remove one exact local device unlock entry.',
        arguments: [
          { syntax: '<slot-id>', description: 'Opaque device-key slot identifier.' },
        ],
        options: slotLifecycleOptions(false),
        execute: async (context, arguments_, options) => {
          const slotId = parseInputValue(
            requiredArgument(arguments_[0], 'slot ID'),
            'slot ID',
            (value) => keySlotIdSchema.parse(value),
          );
          const operation = await acquireLifecycleSlotOperation(context, options, {
            kind: 'disable',
            slotId,
          });
          const raw =
            context.ports?.disableKeySlot === undefined
              ? await executeProductionKeySlotOperation(
                  context,
                  options,
                  operation,
                  'device forget',
                )
              : await context.ports.disableKeySlot(slotId);
          const { renderDeviceKeyAction } = await import('./render.js');
          context.stdout.write(
            renderDeviceKeyAction(
              cliKeySlotResultSchema.parse(raw),
              'forgotten',
              optionBoolean(options, 'json'),
            ),
          );
        },
      },
      deviceJoinCommand,
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
    initializationCommand,
    connectCommand,
    recoverCommand,
    unlockCommand,
    lockCommand,
    statusCommand,
    templateCommand,
    groupCommand,
    credentialCommand,
    fieldCommand,
    noteCommand,
    attachmentCommand,
    historyCommand,
    recoveryCommand,
    auditCommand,
    showCommand,
    copyCommand,
    revealCommand,
    getCommand,
    setCommand,
    updateCommand,
    runCommand,
    syncCommand,
    publicBackupCommand(),
    transferCommand,
    publicDeviceCommand(),
    completionCommand(() => PUBLIC_CLI_COMMAND_CATALOG),
  ]);

function publicBackupCommand(): CliCommandDescriptor {
  const children = backupCommand.children;
  if (children === undefined) throw new Error('The backup catalog is incomplete');
  return Object.freeze({
    ...backupCommand,
    children: Object.freeze(children.filter(({ name }) => name !== 'restore')),
  });
}

function publicDeviceCommand(): CliCommandDescriptor {
  const device = CLI_COMMAND_CATALOG.find((descriptor) => descriptor.name === 'device');
  const invite = device?.children?.find((descriptor) => descriptor.name === 'invite');
  const list = device?.children?.find((descriptor) => descriptor.name === 'list');
  const revoke = device?.children?.find((descriptor) => descriptor.name === 'revoke');
  const remember = device?.children?.find(
    (descriptor) => descriptor.name === 'remember',
  );
  const forget = device?.children?.find((descriptor) => descriptor.name === 'forget');
  const join = device?.children?.find((descriptor) => descriptor.name === 'join');
  if (
    device === undefined ||
    invite === undefined ||
    list === undefined ||
    revoke === undefined ||
    remember === undefined ||
    forget === undefined ||
    join === undefined
  ) {
    throw new Error('The device catalog is incomplete');
  }
  const publicInvite = Object.freeze({
    name: invite.name,
    description: 'Create, list, or revoke device invites.',
    ...(invite.arguments === undefined ? {} : { arguments: invite.arguments }),
    ...(invite.options === undefined ? {} : { options: invite.options }),
    children: (invite.children ?? []).filter(
      (descriptor) => descriptor.name !== 'join',
    ),
  });
  return Object.freeze({
    name: device.name,
    description: device.description,
    children: [publicInvite, list, revoke, remember, forget, join],
  });
}

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
      if (option.repeatable === true) {
        // Commander keeps only the final occurrence of a repeated flag. A
        // collector is required so every occurrence survives instead of the
        // earlier ones being silently dropped.
        command.option(
          option.flags,
          option.description,
          (value: string, previous: readonly string[]) => [...previous, value],
          [] as readonly string[],
        );
        continue;
      }
      command.option(option.flags, option.description, option.defaultValue);
    }
    if (descriptor.passThrough === true) {
      // Commander resolves an unrecognized flag against ancestor commands, so
      // without this a relayed --version or --json is claimed by this CLI and
      // never reaches the program being run. Positional options on the parent
      // are Commander's documented precondition for passing options through,
      // and they only require this CLI's own flags to precede the operands.
      program.enablePositionalOptions();
      command.passThroughOptions();
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
        // A variadic argument arrives as an array. Spreading it keeps the flat
        // string list that every execute handler already expects, so a trailing
        // variadic simply extends the positional list.
        const positionals = actionArguments.slice(0, argumentCount).flatMap((value) => {
          if (typeof value === 'string') return [value];
          if (Array.isArray(value)) {
            return value.filter((entry): entry is string => typeof entry === 'string');
          }
          return [''];
        });
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

type RecoverySourceOptions = Readonly<{
  inviteFromStdin: boolean;
  portableKeyFromStdin: boolean;
  keyFilePassphraseFromStdin: boolean;
  keyFilePath?: string;
}>;

function parseRecoverRequestFromOptions(
  options: Readonly<Record<string, unknown>>,
  environment: Readonly<Record<string, string | undefined>>,
): ReturnType<typeof parseRecoverRequest> {
  const serverUrl = optionString(options, 'server') ?? environment['CREDS_SERVER_URL'];
  if (serverUrl === undefined || serverUrl.length === 0) {
    throw new CliUsageError('A server URL is required.');
  }
  return parseRecoverRequest({
    serverUrl,
    vaultId: parseInputString(options, 'vault', (value) => vaultIdSchema.parse(value)),
  });
}

function parseRecoverySourceOptions(
  options: Readonly<Record<string, unknown>>,
  resume: boolean,
): RecoverySourceOptions {
  const inviteFromStdin = optionBoolean(options, 'inviteStdin');
  const portableKeyFromStdin = optionBoolean(options, 'portableKeyStdin');
  const keyFilePassphraseFromStdin = optionBoolean(options, 'keyFilePassphraseStdin');
  const rawKeyFilePath = options['keyFile'];
  if (rawKeyFilePath !== undefined && typeof rawKeyFilePath !== 'string') {
    throw new CliUsageError('The portable key file path is invalid.');
  }
  const keyFilePath = rawKeyFilePath;
  if (keyFilePath?.length === 0) {
    throw new CliUsageError('The portable key file path is invalid.');
  }
  if (resume && inviteFromStdin) {
    throw new CliUsageError('--invite-stdin is valid only when starting recovery.');
  }
  if (keyFilePath !== undefined && portableKeyFromStdin) {
    throw new CliUsageError('Choose exactly one portable-key source.');
  }
  if (keyFilePassphraseFromStdin && keyFilePath === undefined) {
    throw new CliUsageError('--key-file-passphrase-stdin requires --key-file.');
  }
  if (
    !resume &&
    keyFilePath === undefined &&
    inviteFromStdin !== portableKeyFromStdin
  ) {
    throw new CliUsageError(
      'Invite and portable-key stdin sources must be supplied together.',
    );
  }
  if (
    !resume &&
    keyFilePath !== undefined &&
    keyFilePassphraseFromStdin &&
    !inviteFromStdin
  ) {
    throw new CliUsageError(
      'Use --invite-stdin with --key-file-passphrase-stdin for framed recovery input.',
    );
  }
  return {
    inviteFromStdin,
    portableKeyFromStdin,
    keyFilePassphraseFromStdin,
    ...(keyFilePath === undefined ? {} : { keyFilePath }),
  };
}

async function parseRecoveryOperationId(
  value: string | undefined,
): Promise<LifecycleOperationId> {
  const { lifecycleOperationIdSchema } = await import('@kavrix/client/cli-contracts');
  const parsed = lifecycleOperationIdSchema.safeParse(
    requiredArgument(value, 'operation ID'),
  );
  if (!parsed.success) throw new CliUsageError('The operation ID is invalid.');
  return parsed.data;
}

async function executeRecoveryStart(
  context: CliCommandContext,
  options: Readonly<Record<string, unknown>>,
  feature: 'recover' | 'device join',
): Promise<CliRecoverResult> {
  const request = parseRecoverRequestFromOptions(
    options,
    context.environment ?? process.env,
  );
  const source = parseRecoverySourceOptions(options, false);
  let raw: unknown;
  if (context.ports?.recover !== undefined) {
    if (source.keyFilePath !== undefined) {
      throw new CliUsageError('Injected recovery does not support key files.');
    }
    const frames = await secretInput(context, feature).readBatch({
      kinds: ['invite', 'portable-key'],
      fromStdin: source.inviteFromStdin || source.portableKeyFromStdin,
      requireEnd: source.inviteFromStdin || source.portableKeyFromStdin,
    });
    raw = await context.ports.recover(
      request,
      requiredSecretFrame(frames, 0),
      requiredSecretFrame(frames, 1),
    );
  } else {
    const { executeProductionRecovery } = await import('./production/recovery.js');
    raw = await executeProductionRecovery({
      environment: context.environment ?? process.env,
      secrets: secretInput(context, feature),
      backendPolicy: parseStatusBackendPolicy(options),
      request,
      ...(source.inviteFromStdin ? { inviteFromStdin: true } : {}),
      ...(source.portableKeyFromStdin ? { portableKeyFromStdin: true } : {}),
      ...(source.keyFilePath === undefined ? {} : { keyFilePath: source.keyFilePath }),
      ...(source.keyFilePassphraseFromStdin
        ? { keyFilePassphraseFromStdin: true }
        : {}),
    });
  }
  const { parseRecoverResult } = await import('./contracts.js');
  return parseRecoverResult(raw);
}

async function parseRotationOperationId(
  value: string | undefined,
): Promise<LifecycleOperationId> {
  const { lifecycleOperationIdSchema } = await import('@kavrix/client/cli-contracts');
  const parsed = lifecycleOperationIdSchema.safeParse(
    requiredArgument(value, 'operation ID'),
  );
  if (!parsed.success) throw new CliUsageError('The rotation operation ID is invalid.');
  return parsed.data;
}

function parseInviteIssueRequest(
  options: Readonly<Record<string, unknown>>,
): InviteIssueRequest {
  const rawExpiry = options['expiresInSeconds'];
  const expiresInSeconds = parseInput(
    inviteExpiryOptionSchema,
    rawExpiry === undefined ? '600' : rawExpiry,
    'invite expiry',
  );
  const scopes = optionStrings(options, 'scope', 'invite scopes') ?? [
    ...DEFAULT_INVITE_SCOPES,
  ];
  return parseInput(
    inviteIssueRequestSchema,
    { scopes, expiresInSeconds },
    'invite options',
  );
}

function optionStrings(
  options: Readonly<Record<string, unknown>>,
  key: string,
  label: string,
): readonly string[] | undefined {
  const value = options[key];
  if (value === undefined) return undefined;
  if (!Array.isArray(value) || value.length === 0) {
    throw new CliUsageError(`The ${label} are invalid.`);
  }
  const strings: string[] = [];
  for (const entry of value) {
    if (typeof entry !== 'string' || entry.length === 0) {
      throw new CliUsageError(`The ${label} are invalid.`);
    }
    strings.push(entry);
  }
  return strings;
}

function requireSecretOutputAuthorization(
  context: CliCommandContext,
  options: Readonly<Record<string, unknown>>,
): void {
  if (context.stdoutIsTty || optionBoolean(options, 'stdout')) return;
  throw new CliUsageError(
    'Secret output requires an interactive terminal or explicit --stdout acknowledgement.',
  );
}

async function withAuthorizedPorts<Output>(
  context: CliCommandContext,
  feature: CliFeature,
  options: Readonly<Record<string, unknown>>,
  operation: (ports: CliUseCasePorts) => Promise<Output>,
): Promise<Output> {
  if (context.ports !== undefined) return operation(context.ports);
  if (context.environment === undefined) throw new CliUnavailableError(feature);
  const { runProductionUnlocked } = await import('./production/unlock.js');
  return runProductionUnlocked(
    {
      environment: context.environment,
      secrets: secretInput(context, feature),
      backendPolicy: parseStatusBackendPolicy(options),
    },
    async ({ ports }) => operation(ports),
  );
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

function slotLifecycleOptions(
  includeCredential: boolean,
): readonly CliOptionDescriptor[] {
  return [
    {
      flags: '--reauth <device-key|portable-key|passphrase|recovery-key>',
      description: 'Explicit local reauthentication method.',
    },
    {
      flags: '--reauth-slot <slot-id>',
      description: 'Existing slot used when reauthentication selection is ambiguous.',
    },
    {
      flags: '--reauth-stdin',
      description: 'Read the reauthentication credential from a bounded stdin frame.',
    },
    {
      flags: '--auth-key-file <path>',
      description: 'Guarded portable-key file used for portable reauthentication.',
    },
    keyFilePassphraseStdinOption,
    ...(includeCredential
      ? [
          {
            flags: '--credential-stdin',
            description: 'Read the new credential from bounded stdin frames.',
          },
          {
            flags: '--credential-file <path>',
            description: 'Guarded portable-key file for a new portable slot.',
          },
          {
            flags: '--credential-file-passphrase-stdin',
            description:
              'Read a credential-file passphrase from a bounded stdin frame.',
          },
          {
            flags: '--device-provider <name>',
            description: 'Public native provider label for a new device slot.',
          },
        ]
      : []),
    jsonOption,
    secretBackendOption,
    backendPassphraseStdinOption,
  ];
}

function portableKeyRotationOptions(): readonly CliOptionDescriptor[] {
  return [
    ...slotLifecycleOptions(false),
    {
      flags: '--slot <slot-id>',
      description: 'Existing active portable-key slot to replace.',
    },
    {
      flags: '--generate-file <path>',
      description: 'Generate a fresh bound replacement key file at this path.',
    },
    {
      flags: '--replacement-file <path>',
      description: 'Import an existing unbound portable-key file.',
    },
    {
      flags: '--protect-with-passphrase',
      description: 'Encrypt a generated replacement file with a confirmed passphrase.',
    },
    {
      flags: '--replacement-passphrase-stdin',
      description: 'Read generated-file passphrase and confirmation from stdin frames.',
    },
    {
      flags: '--replacement-file-passphrase-stdin',
      description: 'Read an imported replacement-file passphrase from stdin.',
    },
  ];
}

function portableKeyRotationResumeOptions(): readonly CliOptionDescriptor[] {
  return [
    ...slotLifecycleOptions(false),
    {
      flags: '--replacement-file <path>',
      description: 'The original replacement portable-key file.',
    },
    {
      flags: '--replacement-file-passphrase-stdin',
      description: 'Read the replacement-file passphrase from stdin.',
    },
  ];
}

async function acquirePortableKeyRotationStart(
  context: CliCommandContext,
  options: Readonly<Record<string, unknown>>,
): Promise<PortableKeyRotationOperation> {
  const generateFile = optionString(options, 'generateFile');
  const replacementFile = optionString(options, 'replacementFile');
  if ((generateFile === undefined) === (replacementFile === undefined)) {
    throw new CliUsageError(
      'Choose exactly one of --generate-file or --replacement-file.',
    );
  }
  const generatedPassphraseFromStdin = optionBoolean(
    options,
    'replacementPassphraseStdin',
  );
  const replacementFilePassphraseFromStdin = optionBoolean(
    options,
    'replacementFilePassphraseStdin',
  );
  if (generateFile !== undefined) {
    if (replacementFilePassphraseFromStdin) {
      throw new CliUsageError(
        '--replacement-file-passphrase-stdin applies only to imported files.',
      );
    }
    if (
      generatedPassphraseFromStdin &&
      !optionBoolean(options, 'protectWithPassphrase')
    ) {
      throw new CliUsageError(
        '--replacement-passphrase-stdin requires --protect-with-passphrase.',
      );
    }
  } else if (
    optionBoolean(options, 'protectWithPassphrase') ||
    generatedPassphraseFromStdin
  ) {
    throw new CliUsageError(
      'Generated-file protection options require --generate-file.',
    );
  }
  rejectRotationStdinCollision(options);
  const reauthentication = await acquireReauthentication(context, options);
  const sourceSlotId = optionalKeySlotId(options, 'slot');
  return {
    kind: 'start',
    ...(sourceSlotId === undefined ? {} : { sourceSlotId }),
    replacement:
      generateFile === undefined
        ? {
            kind: 'import-file',
            path: requiredValue(replacementFile, 'replacement key file'),
            passphraseFromStdin: replacementFilePassphraseFromStdin,
          }
        : {
            kind: 'generate-file',
            path: generateFile,
            protectWithPassphrase: optionBoolean(options, 'protectWithPassphrase'),
            passphraseFromStdin: generatedPassphraseFromStdin,
          },
    reauthentication,
  };
}

function rejectRotationStdinCollision(
  options: Readonly<Record<string, unknown>>,
): void {
  const reauthenticationUsesStdin =
    optionBoolean(options, 'reauthStdin') ||
    (optionString(options, 'authKeyFile') !== undefined &&
      optionBoolean(options, 'keyFilePassphraseStdin'));
  const replacementUsesStdin =
    optionBoolean(options, 'replacementPassphraseStdin') ||
    optionBoolean(options, 'replacementFilePassphraseStdin');
  if (reauthenticationUsesStdin && replacementUsesStdin) {
    throw new CliUsageError(
      'Reauthentication and replacement-file secrets cannot share stdin in one command.',
    );
  }
}

async function executeProductionPortableKeyRotationOperation(
  context: CliCommandContext,
  options: Readonly<Record<string, unknown>>,
  operation: PortableKeyRotationOperation,
): Promise<unknown> {
  if (context.environment === undefined) {
    throw new CliUnavailableError(
      operation.kind === 'list' ? 'key rotate list' : 'key rotate',
    );
  }
  const { executeProductionPortableKeyRotation } =
    await import('./production/portable-key-rotation.js');
  return executeProductionPortableKeyRotation({
    environment: context.environment,
    secrets: secretInput(
      context,
      `key rotate${operation.kind === 'resume' ? ' resume' : ''}` as CliFeature,
    ),
    backendPolicy: parseStatusBackendPolicy(options),
    operation,
  });
}

function requiredValue(value: string | undefined, label: string): string {
  if (value === undefined || value.length === 0) {
    throw new CliUsageError(`A ${label} is required.`);
  }
  return value;
}

type SlotCredentialType = 'portable-key' | 'passphrase' | 'recovery-key' | 'device-key';

async function acquireCreateSlotOperation(
  context: CliCommandContext,
  options: Readonly<Record<string, unknown>>,
  slotType: SlotCredentialType,
): Promise<KeySlotOperation> {
  const authKeyFile = optionString(options, 'authKeyFile');
  const authFilePassphraseFromStdin = optionBoolean(options, 'keyFilePassphraseStdin');
  const authFromStdin = optionBoolean(options, 'reauthStdin');
  const credentialFile = optionString(options, 'credentialFile');
  const credentialFromStdin = optionBoolean(options, 'credentialStdin');
  const credentialFilePassphraseFromStdin = optionBoolean(
    options,
    'credentialFilePassphraseStdin',
  );
  const stdinConsumers =
    Number(authFromStdin) +
    Number(authKeyFile !== undefined && authFilePassphraseFromStdin) +
    Number(credentialFromStdin) +
    Number(credentialFile !== undefined && credentialFilePassphraseFromStdin);
  if (stdinConsumers > 1) {
    return acquireCreateSlotOperationFromFrames(context, options, slotType);
  }
  const reauthentication = await acquireReauthentication(context, options);
  const deviceProvider = optionString(options, 'deviceProvider');
  if (slotType === 'device-key') {
    if (
      optionBoolean(options, 'credentialStdin') ||
      options['credentialFile'] !== undefined
    ) {
      throw new CliUsageError(
        'Device slots generate their protected credential locally.',
      );
    }
    return {
      kind: 'create',
      slotType,
      reauthentication,
      ...(deviceProvider === undefined ? {} : { deviceProvider }),
    };
  }

  const credential = await acquireNewSlotCredential(context, options, slotType);
  return {
    kind: 'create',
    slotType,
    credential,
    reauthentication,
    ...(deviceProvider === undefined ? {} : { deviceProvider }),
  };
}

async function acquireCreateSlotOperationFromFrames(
  context: CliCommandContext,
  options: Readonly<Record<string, unknown>>,
  slotType: SlotCredentialType,
): Promise<KeySlotOperation> {
  if (slotType === 'device-key') {
    throw new CliUsageError(
      'Device slots generate their protected credential locally.',
    );
  }
  const authType = parseInput(
    z.enum(['device-key', 'portable-key', 'passphrase', 'recovery-key']),
    requiredOption(options, 'reauth', 'reauthentication method'),
    'reauthentication method',
  );
  const authSlot = optionalKeySlotId(options, 'reauthSlot');
  const authKeyFile = optionString(options, 'authKeyFile');
  const authFromStdin = optionBoolean(options, 'reauthStdin');
  const authFilePassphraseFromStdin = optionBoolean(options, 'keyFilePassphraseStdin');
  const credentialFile = optionString(options, 'credentialFile');
  const credentialFromStdin = optionBoolean(options, 'credentialStdin');
  const credentialFilePassphraseFromStdin = optionBoolean(
    options,
    'credentialFilePassphraseStdin',
  );
  if (authType === 'device-key' && (authFromStdin || authKeyFile !== undefined)) {
    throw new CliUsageError('Device reauthentication does not consume secret input.');
  }
  if (authKeyFile !== undefined && authType !== 'portable-key') {
    throw new CliUsageError('The selected reauthentication source is invalid.');
  }
  if (authKeyFile !== undefined && authFromStdin) {
    throw new CliUsageError('Choose either --auth-key-file or --reauth-stdin.');
  }
  if (authType === 'passphrase' && authSlot === undefined) {
    throw new CliUsageError('Passphrase reauthentication requires --reauth-slot.');
  }
  if (credentialFile !== undefined && slotType !== 'portable-key') {
    throw new CliUsageError(
      'A credential file can be used only for a portable-key slot.',
    );
  }
  if (credentialFile !== undefined && credentialFromStdin) {
    throw new CliUsageError('Choose either --credential-file or --credential-stdin.');
  }
  if (credentialFilePassphraseFromStdin && credentialFile === undefined) {
    throw new CliUsageError(
      '--credential-file-passphrase-stdin requires --credential-file.',
    );
  }
  const frameKinds: ('passphrase' | 'portable-key' | 'recovery-key')[] = [];
  if (authFromStdin) {
    if (authType === 'device-key') {
      throw new CliUsageError('Device reauthentication does not consume secret input.');
    }
    frameKinds.push(authType);
  }
  if (authKeyFile !== undefined && authFilePassphraseFromStdin) {
    frameKinds.push('passphrase');
  }
  if (credentialFile !== undefined && credentialFilePassphraseFromStdin) {
    frameKinds.push('passphrase');
  } else if (credentialFromStdin) {
    frameKinds.push(slotType);
    if (slotType === 'passphrase') frameKinds.push('passphrase');
  }
  const frames = await secretInput(context, 'key slot create').readBatch({
    kinds: frameKinds,
    fromStdin: true,
    requireEnd: true,
  });
  let frameIndex = 0;
  const takeFrame = (): AcquiredSecret => {
    const frame = frames[frameIndex];
    frameIndex += 1;
    if (frame === undefined)
      throw new CliUsageError('Secret input used invalid framing.');
    return frame;
  };
  const authFrame = authFromStdin ? takeFrame() : undefined;
  const authFilePassphrase =
    authKeyFile !== undefined && authFilePassphraseFromStdin ? takeFrame() : undefined;
  let reauthentication: SlotReauthentication;
  if (authType === 'device-key') {
    reauthentication = {
      kind: 'device-key',
      ...(authSlot === undefined ? {} : { slotId: authSlot }),
    };
  } else if (authKeyFile !== undefined) {
    reauthentication = {
      kind: 'portable-key',
      formattedKey: await readPortableKeyFileForSlot(
        authKeyFile,
        secretInput(context, 'key slot create'),
        authFilePassphraseFromStdin,
        authFilePassphrase,
      ),
      ...(authSlot === undefined ? {} : { slotId: authSlot }),
    };
  } else {
    const value =
      authFrame ??
      (await secretInput(context, 'key slot create').read({
        kind: authType,
        fromStdin: false,
      }));
    reauthentication =
      authType === 'passphrase'
        ? (() => {
            if (authSlot === undefined) {
              throw new CliUsageError(
                'Passphrase reauthentication requires --reauth-slot.',
              );
            }
            return { kind: 'passphrase', passphrase: value, slotId: authSlot };
          })()
        : {
            kind: authType,
            formattedKey: value,
            ...(authSlot === undefined ? {} : { slotId: authSlot }),
          };
  }

  let credential: NewSlotCredential;
  if (credentialFile !== undefined) {
    const credentialFilePassphrase = credentialFilePassphraseFromStdin
      ? takeFrame()
      : undefined;
    credential = {
      kind: 'portable-key',
      formattedKey: await readPortableKeyFileForSlot(
        credentialFile,
        secretInput(context, 'key slot create'),
        credentialFilePassphraseFromStdin,
        credentialFilePassphrase,
      ),
    };
  } else {
    const maskedPassphraseValues =
      !credentialFromStdin && slotType === 'passphrase'
        ? await secretInput(context, 'key slot create').readBatch({
            kinds: ['passphrase', 'passphrase'],
            fromStdin: false,
            requireEnd: false,
          })
        : undefined;
    const first = credentialFromStdin
      ? takeFrame()
      : (maskedPassphraseValues?.[0] ??
        (await readCredential(context, slotType, false)));
    if (slotType === 'passphrase') {
      const confirmation = credentialFromStdin
        ? takeFrame()
        : maskedPassphraseValues?.[1];
      if (confirmation === undefined) {
        throw new CliUsageError('Passphrase confirmation is incomplete.');
      }
      await assertMatchingPassphrases(first, confirmation);
      credential = { kind: 'passphrase', passphrase: first };
    } else {
      credential = { kind: slotType, formattedKey: first };
    }
  }
  const deviceProvider = optionString(options, 'deviceProvider');
  return {
    kind: 'create',
    slotType,
    credential,
    reauthentication,
    ...(deviceProvider === undefined ? {} : { deviceProvider }),
  };
}

async function acquireLifecycleSlotOperation(
  context: CliCommandContext,
  options: Readonly<Record<string, unknown>>,
  operation: Readonly<{
    kind: 'disable' | 'revoke';
    slotId: KeySlotId;
  }>,
): Promise<KeySlotOperation> {
  return {
    ...operation,
    reauthentication: await acquireReauthentication(context, options),
  };
}

async function acquireReauthentication(
  context: CliCommandContext,
  options: Readonly<Record<string, unknown>>,
): Promise<SlotReauthentication> {
  const authType = parseInput(
    z.enum(['device-key', 'portable-key', 'passphrase', 'recovery-key']),
    requiredOption(options, 'reauth', 'reauthentication method'),
    'reauthentication method',
  );
  const slotId = optionalKeySlotId(options, 'reauthSlot');
  const keyFile = optionString(options, 'authKeyFile');
  const fromStdin = optionBoolean(options, 'reauthStdin');
  const passphraseFromStdin = optionBoolean(options, 'keyFilePassphraseStdin');
  if (authType === 'device-key') {
    if (fromStdin || keyFile !== undefined || passphraseFromStdin) {
      throw new CliUsageError('Device reauthentication does not consume secret input.');
    }
    return { kind: 'device-key', ...(slotId === undefined ? {} : { slotId }) };
  }
  if (authType !== 'portable-key' && keyFile !== undefined) {
    throw new CliUsageError('A key file can reauthenticate only a portable-key slot.');
  }
  if (keyFile !== undefined && fromStdin) {
    throw new CliUsageError('Choose either --auth-key-file or --reauth-stdin.');
  }
  if (authType === 'passphrase' && slotId === undefined) {
    throw new CliUsageError('Passphrase reauthentication requires --reauth-slot.');
  }
  const acquired =
    keyFile === undefined
      ? await secretInput(context, 'key slot create').read({
          kind: authType,
          fromStdin,
        })
      : await readPortableKeyFileForSlot(
          keyFile,
          secretInput(context, 'key slot create'),
          passphraseFromStdin,
        );
  if (authType === 'passphrase') {
    if (slotId === undefined) {
      throw new CliUsageError('Passphrase reauthentication requires --reauth-slot.');
    }
    return {
      kind: 'passphrase',
      passphrase: acquired,
      slotId,
    };
  }
  return {
    kind: authType,
    formattedKey: acquired,
    ...(slotId === undefined ? {} : { slotId }),
  };
}

async function acquireNewSlotCredential(
  context: CliCommandContext,
  options: Readonly<Record<string, unknown>>,
  slotType: Exclude<SlotCredentialType, 'device-key'>,
): Promise<NewSlotCredential> {
  const keyFile = optionString(options, 'credentialFile');
  const fromStdin = optionBoolean(options, 'credentialStdin');
  const passphraseFromStdin = optionBoolean(options, 'credentialFilePassphraseStdin');
  if (keyFile !== undefined && slotType !== 'portable-key') {
    throw new CliUsageError(
      'A credential file can be used only for a portable-key slot.',
    );
  }
  if (keyFile !== undefined && fromStdin) {
    throw new CliUsageError('Choose either --credential-file or --credential-stdin.');
  }
  if (passphraseFromStdin && keyFile === undefined) {
    throw new CliUsageError(
      '--credential-file-passphrase-stdin requires --credential-file.',
    );
  }
  const acquired =
    keyFile === undefined
      ? await readCredential(context, slotType, fromStdin)
      : await readPortableKeyFileForSlot(
          keyFile,
          secretInput(context, 'key slot create'),
          passphraseFromStdin,
        );
  return slotType === 'passphrase'
    ? { kind: 'passphrase', passphrase: acquired }
    : { kind: slotType, formattedKey: acquired };
}

async function readCredential(
  context: CliCommandContext,
  slotType: Exclude<SlotCredentialType, 'device-key'>,
  fromStdin: boolean,
): Promise<AcquiredSecret> {
  const secrets = secretInput(context, 'key slot create');
  if (slotType !== 'passphrase') {
    return secrets.read({ kind: slotType, fromStdin });
  }
  const values = await secrets.readBatch({
    kinds: ['passphrase', 'passphrase'],
    fromStdin,
    requireEnd: fromStdin,
  });
  const first = values[0];
  const second = values[1];
  if (first === undefined || second === undefined) {
    throw new CliUsageError('Passphrase confirmation is incomplete.');
  }
  const crypto = await import('@kavrix/crypto');
  const firstBytes = new TextEncoder().encode(first);
  const secondBytes = new TextEncoder().encode(second);
  try {
    if (!crypto.constantTimeEqual(firstBytes, secondBytes)) {
      throw new CliUsageError('Passphrase confirmation did not match.');
    }
  } finally {
    crypto.zeroize(firstBytes);
    crypto.zeroize(secondBytes);
  }
  return first;
}

async function readPortableKeyFileForSlot(
  path: string,
  secrets: SecretInputPort,
  passphraseFromStdin: boolean,
  stagedPassphrase?: AcquiredSecret,
): Promise<AcquiredSecret> {
  const { createProductionPortableKeyFileReader } =
    await import('./production/portable-key-files.js');
  const reader = createProductionPortableKeyFileReader({
    secrets,
    passphraseFromStdin,
  });
  return acquiredSecretSchema.parse(
    String(
      await reader.readFormattedPortableKey(
        path,
        { kind: 'unbound' },
        stagedPassphrase === undefined
          ? undefined
          : () => Promise.resolve(stagedPassphrase),
      ),
    ),
  );
}

async function assertMatchingPassphrases(
  first: AcquiredSecret,
  second: AcquiredSecret,
): Promise<void> {
  const crypto = await import('@kavrix/crypto');
  const firstBytes = new TextEncoder().encode(first);
  const secondBytes = new TextEncoder().encode(second);
  try {
    if (!crypto.constantTimeEqual(firstBytes, secondBytes)) {
      throw new CliUsageError('Passphrase confirmation did not match.');
    }
  } finally {
    crypto.zeroize(firstBytes);
    crypto.zeroize(secondBytes);
  }
}

function optionalKeySlotId(
  options: Readonly<Record<string, unknown>>,
  key: string,
): KeySlotId | undefined {
  const value = options[key];
  if (value === undefined) return undefined;
  return parseInputValue(value, 'slot ID', (candidate) =>
    keySlotIdSchema.parse(candidate),
  );
}

async function executeProductionKeySlotOperation(
  context: CliCommandContext,
  options: Readonly<Record<string, unknown>>,
  operation: KeySlotOperation,
  feature: CliFeature = `key slot ${operation.kind}` as CliFeature,
): Promise<unknown> {
  if (context.environment === undefined) {
    throw new CliUnavailableError(feature);
  }
  const { executeProductionKeySlotLifecycle } =
    await import('./production/slot-lifecycle.js');
  return executeProductionKeySlotLifecycle({
    environment: context.environment,
    secrets: secretInput(context, feature),
    backendPolicy: parseStatusBackendPolicy(options),
    operation,
  });
}

async function withInitialization<Output>(
  context: CliCommandContext,
  options: Readonly<Record<string, unknown>>,
  action: (dependencies: CliInitializationDependencies) => Promise<Output>,
): Promise<Output> {
  if (context.initialization !== undefined) {
    return action(context.initialization);
  }
  if (context.environment === undefined) {
    throw new CliUnavailableError('init');
  }
  const backendPolicy = parseStatusBackendPolicy(options);
  const serverUrl = optionString(options, 'server');
  const { runProductionInitialization } = await import('./production/initialize.js');
  return runProductionInitialization(
    {
      environment: context.environment,
      secrets: secretInput(context, 'init'),
      backendPolicy,
      terminal: { input: context.stdin, output: context.stderr },
      keyFilePassphraseFromStdin: optionBoolean(options, 'keyFilePassphraseStdin'),
      ...(serverUrl !== undefined ? { serverUrl } : {}),
    },
    action,
  );
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
  const keyFilePassphraseStdin = optionBoolean(options, 'keyFilePassphraseStdin');
  const confirmationFromStdin = optionBoolean(options, 'confirmationStdin');
  const sourceCount = Number(masked) + Number(stdin) + Number(keyFile !== undefined);
  if (sourceCount > 1) {
    throw new CliUsageError('Choose exactly one existing portable-key source.');
  }
  if (stdin) {
    if (keyFilePassphraseStdin) {
      throw new CliUsageError('--key-file-passphrase-stdin requires --key-file.');
    }
    if (confirmationFromStdin) {
      throw new CliUsageError('--key-stdin already includes both confirmation frames.');
    }
    return { source: 'stdin-protocol', confirmationFromStdin: true };
  }
  if (masked) {
    if (keyFilePassphraseStdin) {
      throw new CliUsageError('--key-file-passphrase-stdin requires --key-file.');
    }
    if (confirmationFromStdin) {
      throw new CliUsageError('Masked portable import requires masked confirmation.');
    }
    return { source: 'masked-portable', confirmationFromStdin: false };
  }
  if (keyFile !== undefined) {
    if (typeof keyFile !== 'string') {
      throw new CliUsageError('The portable key file path is invalid.');
    }
    return {
      source: 'key-file',
      path: keyFile,
      confirmationFromStdin,
      passphraseFromStdin: keyFilePassphraseStdin,
    };
  }
  if (keyFilePassphraseStdin) {
    throw new CliUsageError('--key-file-passphrase-stdin requires --key-file.');
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
