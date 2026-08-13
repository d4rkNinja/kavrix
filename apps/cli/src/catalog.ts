import type { Writable } from 'node:stream';

import { Command } from 'commander';
import {
  controlListPageQuerySchema,
  type GroupPayload,
  type ItemPayload,
} from '@kavrix/schemas';
import { z } from 'zod';
import type { VaultRootKey } from '@kavrix/crypto';
import type { SqliteSyncLocalStore } from '@kavrix/local-store';

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
import { safeJson, sanitizeTerminalText } from './terminal.js';
import { CLI_VERSION } from './version.js';
import type { SecretBackendPolicy } from './production/secret-backend.js';
import type { ProductionStatusRequest } from './production/status.js';
import type { ProductionUnlockedContext } from './production/unlock.js';

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
  const { unlockDeviceKeySlot } = await import('@kavrix/crypto');
  const { slotBinding } = await import('@kavrix/client');
  const store = await unlocked.environment.openSyncStore(unlocked.profile);
  const vaultRecord = await store.getVault(unlocked.profile.vaultId);
  if (vaultRecord === null) {
    throw new Error('Vault record not found');
  }
  const deviceSecret = await unlocked.backend.keychain.load(
    unlocked.profile.deviceLocator,
  );
  if (deviceSecret === null) {
    throw new Error('Device secret not found');
  }
  const slot = vaultRecord.keySlots.find(
    (candidate) => candidate.id === unlocked.profile.deviceLocator.keySlotId,
  );
  if (slot?.type !== 'device-key') {
    throw new Error('Device key slot not found');
  }
  if (slot.deviceId !== unlocked.profile.deviceId) {
    throw new Error('Device key slot not found');
  }
  try {
    return await unlockDeviceKeySlot(
      slot,
      deviceSecret,
      slotBinding(vaultRecord, slot),
    );
  } finally {
    deviceSecret.fill(0);
  }
}

/**
 * Opens the unlocked production store, derives the vault root key, runs the
 * bounded operation, and always zeroizes the derived root key on exit. The
 * operation must not retain the root key or store beyond its promise.
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
      try {
        return await operation(unlocked, store, rootKey);
      } finally {
        zeroize(rootKey);
      }
    },
  );
}

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
        secretBackendOption,
        backendPassphraseStdinOption,
      ],
      execute: async (context, arguments_, options) => {
        const name = requiredArgument(arguments_[0], 'group name');
        const description = optionString(options, 'description');
        const { cliCreateGroupRequestSchema } = await import('./mutation-contracts.js');
        const request = cliCreateGroupRequestSchema.parse({
          name,
          ...(description ? { description } : {}),
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
        { flags: '--value <text>', description: 'Initial text field value.' },
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
        const textValue = optionString(options, 'value');
        const fromStdin = optionBoolean(options, 'valueStdin');

        let secretBytes: Uint8Array | undefined;
        if (fromStdin) {
          const acquired = await secretInput(context, 'field add').read({
            kind: 'field-value',
            fromStdin: true,
          });
          secretBytes = Buffer.from(acquired, 'utf8');
        } else if (textValue !== undefined) {
          secretBytes = Buffer.from(textValue, 'utf8');
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
      description: 'Set or update the value of a credential field.',
      arguments: [
        { syntax: '<group>', description: 'Group ID, unique name, or alias.' },
        {
          syntax: '<credential>',
          description: 'Credential ID, unique name, or alias.',
        },
        { syntax: '<field-key>', description: 'Stable field key.' },
        { syntax: '[value]', description: 'Text value for non-sensitive fields.' },
      ],
      options: [
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
        const positionalValue = arguments_[3];
        const fromStdin = optionBoolean(options, 'valueStdin');

        let secretBytes: Uint8Array;
        if (fromStdin) {
          const acquired = await secretInput(context, 'field set').read({
            kind: 'field-value',
            fromStdin: true,
          });
          secretBytes = Buffer.from(acquired, 'utf8');
        } else if (positionalValue !== undefined && positionalValue.length > 0) {
          secretBytes = Buffer.from(positionalValue, 'utf8');
        } else {
          throw new CliUsageError(
            'Provide a value argument or use --value-stdin to supply secret input.',
          );
        }

        const { cliSetFieldRequestSchema } = await import('./mutation-contracts.js');
        const request = cliSetFieldRequestSchema.parse({
          groupQuery,
          credentialQuery,
          fieldKey,
          value: secretBytes,
        });

        try {
          if (context.ports?.setField !== undefined) {
            await context.ports.setField(request);
          } else {
            const { executeProductionSetField } =
              await import('./production/mutations.js');
            await withUnlockedVault(
              context,
              'field set',
              options,
              async (unlocked, store, rootKey) =>
                executeProductionSetField(
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
            `Field "${request.fieldKey}" set for credential "${credentialQuery}".\n`,
          );
        } finally {
          zeroizeBytes(secretBytes);
        }
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
        { syntax: '<field-key>', description: 'Stable field key.' },
      ],
      options: [
        { flags: '--label <text>', description: 'Updated field display label.' },
        { flags: '--type <type>', description: 'Updated canonical field type.' },
        { flags: '--sensitive', description: 'Mark field as sensitive.' },
        { flags: '--no-sensitive', description: 'Mark field as non-sensitive.' },
        secretBackendOption,
        backendPassphraseStdinOption,
      ],
      execute: async (context, arguments_, options) => {
        const groupQuery = requiredArgument(arguments_[0], 'group query');
        const credentialQuery = requiredArgument(arguments_[1], 'credential query');
        const fieldKey = requiredArgument(arguments_[2], 'field key');
        const label = optionString(options, 'label');
        const typeStr = optionString(options, 'type');
        const sensitiveFlag = options['sensitive'];
        const sensitive =
          typeof sensitiveFlag === 'boolean' ? sensitiveFlag : undefined;

        const { cliUpdateFieldRequestSchema } = await import('./mutation-contracts.js');
        const request = cliUpdateFieldRequestSchema.parse({
          groupQuery,
          credentialQuery,
          fieldKey,
          ...(label ? { label } : {}),
          ...(typeStr ? { fieldType: typeStr } : {}),
          ...(sensitive !== undefined ? { sensitive } : {}),
        });

        if (context.ports?.updateField !== undefined) {
          await context.ports.updateField(request);
        } else {
          const { executeProductionUpdateField } =
            await import('./production/mutations.js');
          await withUnlockedVault(
            context,
            'field update',
            options,
            async (unlocked, store, rootKey) =>
              executeProductionUpdateField(
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
          `Field "${request.fieldKey}" updated for credential "${credentialQuery}".\n`,
        );
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
      await withUnlockedVault(
        context,
        'show',
        options,
        async (unlocked, store, rootKey) => {
          rawResult = await executeProductionShow(
            {
              source: store,
              vaultId: unlocked.profile.vaultId,
              rootKey,
            },
            groupQuery,
            credentialQuery,
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

    let result: {
      groupName: string;
      credentialTitle: string;
      fieldLabel: string;
      fieldKey: string;
      fieldType: string;
      sensitive: boolean;
      value: string;
    };

    if (context.ports?.get !== undefined) {
      result = await context.ports.get(
        groupQuery,
        credentialQuery,
        fieldQuery,
        getOpts,
      );
    } else {
      const { executeProductionGet } = await import('./production/get.js');
      let resultVal: typeof result | undefined;
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

    if (asJson) {
      context.stdout.write(
        safeJson({
          group: result.groupName,
          credential: result.credentialTitle,
          field: result.fieldLabel,
          key: result.fieldKey,
          type: result.fieldType,
          sensitive: result.sensitive,
          value: result.value,
        }) + '\n',
      );
    } else {
      context.stdout.write(`${sanitizeTerminalText(result.value)}\n`);
    }
  },
});

export const CLI_COMMAND_CATALOG: readonly CliCommandDescriptor[] = Object.freeze([
  versionCommand,
  generationCommand,
  totpCommand,
  keyCommand,
  initializationCommand,
  unlockCommand,
  lockCommand,
  statusCommand,
  groupCommand,
  credentialCommand,
  fieldCommand,
  noteCommand,
  showCommand,
  copyCommand,
  revealCommand,
  getCommand,
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
                await useCases(context, 'device invite list').listInvitePage(
                  vaultId,
                  pageOptions,
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
    initializationCommand,
    unlockCommand,
    lockCommand,
    statusCommand,
    groupCommand,
    credentialCommand,
    fieldCommand,
    noteCommand,
    showCommand,
    copyCommand,
    revealCommand,
    getCommand,
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
