import { PassThrough, Readable, Writable } from 'node:stream';

import {
  VaultLifecycleError,
  lifecycleOperationIdSchema,
  vaultProfileSchema,
  type VaultImportedPortableInitializationCreation,
  type VaultInitializationConfirmation,
  type VaultInitializationCreation,
  type VaultInitializationInput,
  type VaultInitializationReceipt,
} from '@kavrix/client';
import { deviceIdSchema, vaultIdSchema, type VaultPreferences } from '@kavrix/schemas';
import { describe, expect, it, vi } from 'vitest';

import {
  CLI_EXIT_CODES,
  CliUsageError,
  NodeSecretInput,
  acquiredSecretSchema,
  runCli,
  runPublicCli,
  type CliDependencies,
  type CliInitializationDependencies,
  type CliUseCasePorts,
  type CliVaultInitializationPort,
  type ProtectedPortableKeyFileReaderPort,
  type SecretInputPort,
  type SensitiveInitializationDisplayPort,
  type SensitiveInitializationDisplayRequest,
} from '../src/index.js';

const OPERATION_ID = lifecycleOperationIdSchema.parse('operation.cli.init.0001');
const RECEIPT_VAULT_ID = vaultIdSchema.parse('vault.cli.init');
const RECEIPT_DEVICE_ID = deviceIdSchema.parse('device.cli.init');
const RECEIPT: VaultInitializationReceipt = {
  operationId: OPERATION_ID,
  vaultId: RECEIPT_VAULT_ID,
  deviceId: RECEIPT_DEVICE_ID,
  profile: vaultProfileSchema.parse({
    version: 1,
    serverUrl: 'https://vault.example/',
    vaultId: RECEIPT_VAULT_ID,
    deviceId: RECEIPT_DEVICE_ID,
    deviceLocator: {
      version: 1,
      vaultId: RECEIPT_VAULT_ID,
      deviceId: RECEIPT_DEVICE_ID,
      keySlotId: 'slot.cli.init',
    },
    sessionLocator: {
      version: 1,
      vaultId: RECEIPT_VAULT_ID,
      deviceId: RECEIPT_DEVICE_ID,
      purpose: 'api-session',
    },
  }),
};
const PORTABLE = acquiredSecretSchema.parse('KAVRIX-PORTABLE-CLI-CANARY');
const RECOVERY = acquiredSecretSchema.parse('KAVRIX-RECOVERY-CLI-CANARY');
const FILE_PASSPHRASE = acquiredSecretSchema.parse('KAVRIX-FILE-PASSPHRASE-CANARY');

describe('injectable initialization commands', () => {
  it('runs generated initialization only after acknowledged display and two-key re-entry', async () => {
    const events: string[] = [];
    const confirmation: VaultInitializationConfirmation = {
      portableKey: PORTABLE,
      recoveryKey: RECOVERY,
    };
    const generated = generatedAttempt(events, confirmation);
    const coordinator = coordinatorWith({
      begin: vi.fn((input: VaultInitializationInput) => {
        events.push('begin');
        expect(input.preferences).toMatchObject(defaultPreferences());
        return generated;
      }),
    });
    const display = recordingDisplay(events);
    const secrets = secretInput({
      readBatch: ({ kinds, fromStdin, requireEnd }) => {
        events.push('confirm-read');
        expect(kinds).toEqual(['portable-key', 'recovery-key']);
        expect(fromStdin).toBe(false);
        expect(requireEnd).toBe(false);
        return Promise.resolve([PORTABLE, RECOVERY]);
      },
    });

    const result = await executeInit(
      ['init'],
      {
        coordinator,
        sensitiveDisplay: display.port,
      },
      secrets,
    );

    expect(result).toEqual({
      exitCode: CLI_EXIT_CODES.success,
      stdout: 'Vault initialized.\n',
      stderr: '',
    });
    expect(events).toEqual(['begin', 'take', 'display', 'confirm-read', 'confirm']);
    expect(display.requests).toEqual([
      expect.objectContaining({
        operationId: OPERATION_ID,
        material: { portableKey: PORTABLE, recoveryKey: RECOVERY },
        requiresInteractiveTty: true,
        requiresExplicitAcknowledgement: true,
      }),
    ]);
    expect(`${result.stdout}${result.stderr}`).not.toContain(PORTABLE);
    expect(`${result.stdout}${result.stderr}`).not.toContain(RECOVERY);
  });

  it('supports masked imported portable input with recovery-only display', async () => {
    const events: string[] = [];
    const imported = importedAttempt(events);
    const beginImportedPortable = vi.fn((_input, portable: string) => {
      events.push('begin-import');
      expect(portable).toBe(PORTABLE);
      return imported;
    });
    const coordinator = coordinatorWith({ beginImportedPortable });
    const display = recordingDisplay(events);
    const secrets = secretInput({
      read: ({ kind, fromStdin }) => {
        events.push('import-read');
        expect({ kind, fromStdin }).toEqual({
          kind: 'portable-key',
          fromStdin: false,
        });
        return Promise.resolve(PORTABLE);
      },
      readBatch: ({ kinds, fromStdin, requireEnd }) => {
        events.push('confirm-read');
        expect(kinds).toEqual(['portable-key', 'recovery-key']);
        expect(fromStdin).toBe(false);
        expect(requireEnd).toBe(false);
        return Promise.resolve([PORTABLE, RECOVERY]);
      },
    });

    const result = await executeInit(
      ['init', '--existing-portable'],
      { coordinator, sensitiveDisplay: display.port },
      secrets,
    );

    expect(result.exitCode).toBe(CLI_EXIT_CODES.success);
    expect(events).toEqual([
      'import-read',
      'begin-import',
      'take',
      'display',
      'confirm-read',
      'confirm',
    ]);
    expect(display.requests[0]?.material).toEqual({ recoveryKey: RECOVERY });
    expect(JSON.stringify(display.requests[0]?.material)).not.toContain(PORTABLE);
    expect(beginImportedPortable).toHaveBeenCalledOnce();
    expect(`${result.stdout}${result.stderr}`).not.toContain(PORTABLE);
    expect(`${result.stdout}${result.stderr}`).not.toContain(RECOVERY);
  });

  it('supports protected key-file import and two-frame stdin confirmation', async () => {
    const events: string[] = [];
    const keyFiles: ProtectedPortableKeyFileReaderPort = {
      readFormattedPortableKey: (path, expectedBinding) => {
        events.push('key-file');
        expect(path).toBe('D:\\protected\\vault.cvk');
        expect(expectedBinding).toEqual({ kind: 'unbound' });
        return Promise.resolve(PORTABLE);
      },
    };
    const coordinator = coordinatorWith({
      beginImportedPortable: vi.fn(() => {
        events.push('begin-import');
        return importedAttempt(events);
      }),
    });
    const display = recordingDisplay(events);
    const secrets = secretInput({
      readBatch: ({ kinds, fromStdin, requireEnd }) => {
        events.push('confirm-read');
        expect(kinds).toEqual(['portable-key', 'recovery-key']);
        expect(fromStdin).toBe(true);
        expect(requireEnd).toBe(true);
        return Promise.resolve([PORTABLE, RECOVERY]);
      },
    });

    const result = await executeInit(
      ['init', '--key-file', 'D:\\protected\\vault.cvk', '--confirmation-stdin'],
      { coordinator, sensitiveDisplay: display.port, keyFiles },
      secrets,
    );

    expect(result.exitCode).toBe(CLI_EXIT_CODES.success);
    expect(events).toEqual([
      'key-file',
      'begin-import',
      'take',
      'display',
      'confirm-read',
      'confirm',
    ]);
  });

  it('stages a protected key-file passphrase before stdin confirmation frames', async () => {
    const events: string[] = [];
    const keyFiles: ProtectedPortableKeyFileReaderPort = {
      readFormattedPortableKey: async (_path, expectedBinding, acquirePassphrase) => {
        events.push('key-file');
        expect(expectedBinding).toEqual({ kind: 'unbound' });
        if (acquirePassphrase === undefined)
          throw new Error('Missing passphrase reader');
        await expect(acquirePassphrase()).resolves.toBe(FILE_PASSPHRASE);
        events.push('passphrase-read');
        return PORTABLE;
      },
    };
    const coordinator = coordinatorWith({
      beginImportedPortable: vi.fn(() => {
        events.push('begin-import');
        return importedAttempt(events);
      }),
    });
    let batch = 0;
    const result = await executeInit(
      [
        'init',
        '--key-file',
        'D:\\protected\\vault.cvk',
        '--key-file-passphrase-stdin',
        '--confirmation-stdin',
      ],
      { coordinator, sensitiveDisplay: recordingDisplay(events).port, keyFiles },
      secretInput({
        readBatch: ({ kinds, fromStdin, requireEnd }) => {
          batch += 1;
          expect(fromStdin).toBe(true);
          if (batch === 1) {
            expect(kinds).toEqual(['passphrase']);
            expect(requireEnd).toBe(false);
            return Promise.resolve([FILE_PASSPHRASE]);
          }
          expect(kinds).toEqual(['portable-key', 'recovery-key']);
          expect(requireEnd).toBe(true);
          return Promise.resolve([PORTABLE, RECOVERY]);
        },
      }),
    );

    expect(result.exitCode).toBe(CLI_EXIT_CODES.success);
    expect(batch).toBe(2);
    expect(`${result.stdout}${result.stderr}`).not.toContain(FILE_PASSPHRASE);
  });

  it('supports generated initialization with exact stdin confirmation frames', async () => {
    const events: string[] = [];
    const result = await executeInit(
      ['init', '--confirmation-stdin'],
      {
        coordinator: coordinatorWith({
          begin: () => generatedAttempt(events),
        }),
        sensitiveDisplay: recordingDisplay(events).port,
      },
      secretInput({
        readBatch: ({ kinds, fromStdin, requireEnd }) => {
          expect(kinds).toEqual(['portable-key', 'recovery-key']);
          expect({ fromStdin, requireEnd }).toEqual({
            fromStdin: true,
            requireEnd: true,
          });
          events.push('confirm-read');
          return Promise.resolve([PORTABLE, RECOVERY]);
        },
      }),
    );

    expect(result.exitCode).toBe(CLI_EXIT_CODES.success);
    expect(events).toEqual(['take', 'display', 'confirm-read', 'confirm']);
  });

  it('pauses the three-frame stdin protocol for recovery display before confirmation', async () => {
    const events: string[] = [];
    const beginImportedPortable = vi.fn((_input, portable: string) => {
      events.push('begin-import');
      expect(portable).toBe(PORTABLE);
      return importedAttempt(events);
    });
    const coordinator = coordinatorWith({ beginImportedPortable });
    const input = new PassThrough();
    const secrets = new NodeSecretInput(input, captureWritable());
    const display: SensitiveInitializationDisplayPort = {
      display: () => {
        events.push('display');
        input.end(`${PORTABLE}\n${RECOVERY}\n`);
        return Promise.resolve({ acknowledged: true, interactiveTty: true });
      },
    };
    const pending = executeInit(
      ['init', '--key-stdin'],
      { coordinator, sensitiveDisplay: display },
      secrets,
    );
    await Promise.resolve();
    expect(events).toEqual([]);
    input.write(`${PORTABLE}\n`);
    const result = await pending;

    expect(result.exitCode).toBe(CLI_EXIT_CODES.success);
    expect(events).toEqual(['begin-import', 'take', 'display', 'confirm']);
  });

  it.each([
    ['missing', `${PORTABLE}\n`],
    ['extra', `${PORTABLE}\n${RECOVERY}\nEXTRA-SECRET-FRAME\n`],
  ])('rejects %s trailing stdin protocol frames', async (_label, tail) => {
    const events: string[] = [];
    const input = new PassThrough();
    const pending = executeInit(
      ['init', '--key-stdin'],
      {
        coordinator: coordinatorWith({
          beginImportedPortable: () => importedAttempt(events),
        }),
        sensitiveDisplay: {
          display: () => {
            events.push('display');
            input.end(tail);
            return Promise.resolve({ acknowledged: true, interactiveTty: true });
          },
        },
      },
      new NodeSecretInput(input, captureWritable()),
    );
    input.write(`${PORTABLE}\n`);

    const result = await pending;

    expect(result.exitCode).toBe(CLI_EXIT_CODES.usage);
    expect(events).toEqual(['take', 'display', 'cancel']);
    expect(`${result.stdout}${result.stderr}`).not.toContain(PORTABLE);
    expect(`${result.stdout}${result.stderr}`).not.toContain(RECOVERY);
  });

  it('rejects malformed import and conflicting sources before display or confirmation', async () => {
    const malformed = acquiredSecretSchema.parse('MALFORMED-PORTABLE-CLI-CANARY');
    const display = recordingDisplay([]);
    const beginImportedPortable = vi.fn(() => {
      throw new VaultLifecycleError('invalid-input');
    });
    const secrets = secretInput({ read: () => Promise.resolve(malformed) });
    const result = await executeInit(
      ['init', '--existing-portable'],
      {
        coordinator: coordinatorWith({ beginImportedPortable }),
        sensitiveDisplay: display.port,
      },
      secrets,
    );
    expect(result).toEqual({
      exitCode: CLI_EXIT_CODES.failure,
      stdout: '',
      stderr: 'Error [VAULT_LIFECYCLE_FAILED]: The vault lifecycle operation failed.\n',
    });
    expect(display.requests).toHaveLength(0);

    const conflict = await executeInit(
      ['init', '--existing-portable', '--key-file', 'vault.cvk'],
      {
        coordinator: coordinatorWith(),
        sensitiveDisplay: display.port,
      },
      secretInput(),
    );
    expect(conflict.exitCode).toBe(CLI_EXIT_CODES.usage);
    expect(beginImportedPortable).toHaveBeenCalledOnce();
  });

  it('rejects invalid key-file boundaries and operation IDs before lifecycle side effects', async () => {
    const beginImportedPortable = vi.fn();
    const display = recordingDisplay([]);
    const missingReader = await executeInit(
      ['init', '--key-file', 'vault.cvk'],
      {
        coordinator: coordinatorWith({ beginImportedPortable }),
        sensitiveDisplay: display.port,
      },
      secretInput(),
    );
    expect(missingReader.exitCode).toBe(CLI_EXIT_CODES.unavailable);

    const invalidFile = await executeInit(
      ['init', '--key-file', 'vault.cvk'],
      {
        coordinator: coordinatorWith({ beginImportedPortable }),
        sensitiveDisplay: display.port,
        keyFiles: { readFormattedPortableKey: () => Promise.resolve('') },
      },
      secretInput(),
    );
    expect(invalidFile.exitCode).toBe(CLI_EXIT_CODES.usage);

    const invalidPath = await executeInit(
      ['init', '--key-file', 'bad\npath'],
      {
        coordinator: coordinatorWith({ beginImportedPortable }),
        sensitiveDisplay: display.port,
        keyFiles: { readFormattedPortableKey: () => Promise.resolve(PORTABLE) },
      },
      secretInput(),
    );
    expect(invalidPath.exitCode).toBe(CLI_EXIT_CODES.usage);

    const invalidOperation = await executeInit(
      ['init', 'resume', 'short'],
      {
        coordinator: coordinatorWith(),
        sensitiveDisplay: display.port,
      },
      secretInput(),
    );
    expect(invalidOperation.exitCode).toBe(CLI_EXIT_CODES.usage);
    expect(beginImportedPortable).not.toHaveBeenCalled();
    expect(display.requests).toHaveLength(0);
  });

  it('fails closed when an injected confirmation port violates exact framing', async () => {
    const events: string[] = [];
    const result = await executeInit(
      ['init'],
      {
        coordinator: coordinatorWith({ begin: () => generatedAttempt(events) }),
        sensitiveDisplay: recordingDisplay(events).port,
      },
      secretInput({ readBatch: () => Promise.resolve([PORTABLE]) }),
    );

    expect(result.exitCode).toBe(CLI_EXIT_CODES.usage);
    expect(events).toEqual(['take', 'display', 'cancel']);
    expect(`${result.stdout}${result.stderr}`).not.toContain(PORTABLE);
  });

  it('cancels in-memory material on non-TTY display refusal and Ctrl+C confirmation', async () => {
    const displayEvents: string[] = [];
    const nonTtyAttempt = generatedAttempt(displayEvents);
    const nonTty = await executeInit(
      ['init'],
      {
        coordinator: coordinatorWith({ begin: () => nonTtyAttempt }),
        sensitiveDisplay: {
          display: () => Promise.resolve({ acknowledged: false }),
        },
      },
      secretInput(),
    );
    expect(nonTty.exitCode).toBe(CLI_EXIT_CODES.usage);
    expect(displayEvents).toEqual(['take', 'cancel']);

    const cancelEvents: string[] = [];
    const ctrlC = await executeInit(
      ['init'],
      {
        coordinator: coordinatorWith({
          begin: () => generatedAttempt(cancelEvents),
        }),
        sensitiveDisplay: recordingDisplay(cancelEvents).port,
      },
      secretInput({
        readBatch: () =>
          Promise.reject(new CliUsageError('Secret entry was cancelled.')),
      }),
    );
    expect(ctrlC.exitCode).toBe(CLI_EXIT_CODES.usage);
    expect(cancelEvents).toEqual(['take', 'display', 'cancel']);
    expect(`${ctrlC.stdout}${ctrlC.stderr}`).not.toContain(PORTABLE);
    expect(`${ctrlC.stdout}${ctrlC.stderr}`).not.toContain(RECOVERY);
  });

  it('resumes crash-safe operations and keeps unsafe cancellation generic', async () => {
    const resume = vi.fn(() => Promise.resolve(RECEIPT));
    const cancel = vi.fn(() =>
      Promise.reject(new VaultLifecycleError('unsafe-cancel')),
    );
    const dependencies = {
      coordinator: coordinatorWith({ resume, cancel }),
      sensitiveDisplay: recordingDisplay([]).port,
    };
    const resumed = await executeInit(
      ['init', 'resume', OPERATION_ID],
      dependencies,
      secretInput(),
    );
    expect(resumed).toMatchObject({
      exitCode: CLI_EXIT_CODES.success,
      stdout: 'Vault initialized.\n',
    });
    expect(resume).toHaveBeenCalledWith(OPERATION_ID);

    const cancelled = await executeInit(
      ['init', 'cancel', OPERATION_ID],
      dependencies,
      secretInput(),
    );
    expect(cancelled).toEqual({
      exitCode: CLI_EXIT_CODES.failure,
      stdout: '',
      stderr: 'Error [VAULT_LIFECYCLE_FAILED]: The vault lifecycle operation failed.\n',
    });
    expect(cancel).toHaveBeenCalledWith(OPERATION_ID);
  });

  it('forwards the initialization server only when explicitly supplied', async () => {
    const begin = vi.fn(() => generatedAttempt([]));
    const resume = vi.fn(() => Promise.resolve(RECEIPT));
    const cancel = vi.fn(() => Promise.resolve());
    const dependencies = {
      coordinator: coordinatorWith({ begin, resume, cancel }),
      sensitiveDisplay: recordingDisplay([]).port,
    };
    const secrets = secretInput({
      readBatch: () => Promise.resolve([PORTABLE, RECOVERY]),
    });

    await executeInit(['init'], dependencies, secrets);
    await executeInit(
      ['init', '--server', 'https://sync.example/'],
      dependencies,
      secrets,
    );
    await executeInit(['init', 'resume', OPERATION_ID], dependencies, secrets);
    await executeInit(
      ['init', 'resume', OPERATION_ID, '--server', 'https://sync.example/'],
      dependencies,
      secrets,
    );
    await executeInit(['init', 'cancel', OPERATION_ID], dependencies, secrets);
    await executeInit(
      ['init', 'cancel', OPERATION_ID, '--server', 'https://sync.example/'],
      dependencies,
      secrets,
    );

    expect(begin).toHaveBeenNthCalledWith(1, expect.any(Object));
    expect(begin).toHaveBeenNthCalledWith(
      2,
      expect.any(Object),
      'https://sync.example/',
    );
    expect(resume).toHaveBeenNthCalledWith(1, OPERATION_ID);
    expect(resume).toHaveBeenNthCalledWith(2, OPERATION_ID, 'https://sync.example/');
    expect(cancel).toHaveBeenNthCalledWith(1, OPERATION_ID);
    expect(cancel).toHaveBeenNthCalledWith(2, OPERATION_ID, 'https://sync.example/');
  });

  it.each([
    ['start', ['init', '--server', '']],
    ['resume', ['init', 'resume', OPERATION_ID, '--server', '']],
    ['cancel', ['init', 'cancel', OPERATION_ID, '--server', '']],
  ])('rejects an explicitly empty server before init %s', async (_name, argv) => {
    const begin = vi.fn();
    const resume = vi.fn();
    const cancel = vi.fn();
    const result = await executeInit(
      argv,
      {
        coordinator: coordinatorWith({ begin, resume, cancel }),
        sensitiveDisplay: recordingDisplay([]).port,
      },
      secretInput(),
    );

    expect(result).toEqual({
      exitCode: CLI_EXIT_CODES.usage,
      stdout: '',
      stderr: 'Error [CLI_USAGE]: The server URL is invalid.\n',
    });
    expect(begin).not.toHaveBeenCalled();
    expect(resume).not.toHaveBeenCalled();
    expect(cancel).not.toHaveBeenCalled();
  });

  it('keeps argv, environment, completion, output, and errors free of canaries', async () => {
    const environmentCanary = 'KAVRIX_INIT_ENV_SECRET_CANARY';
    vi.stubEnv('KAVRIX_PORTABLE_KEY', environmentCanary);
    const initialization = {
      coordinator: coordinatorWith(),
      sensitiveDisplay: recordingDisplay([]).port,
    };
    const argv = await executeInit(
      ['init', '--portable-key', PORTABLE],
      initialization,
      secretInput(),
    );
    expect(argv.exitCode).toBe(CLI_EXIT_CODES.usage);
    expect(`${argv.stdout}${argv.stderr}`).not.toContain(PORTABLE);
    expect(`${argv.stdout}${argv.stderr}`).not.toContain(environmentCanary);

    const completion = await executeInit(
      ['completion', 'bash'],
      initialization,
      secretInput(),
    );
    expect(completion.stdout).toContain('init');
    expect(completion.stdout).not.toContain(PORTABLE);
    expect(completion.stdout).not.toContain(environmentCanary);

    const publicCompletion = await executePublic(['completion', 'bash']);
    expect(publicCompletion.stdout).toContain(
      "'version generate totp key init connect recover unlock lock status template group credential field note attachment history recovery audit show copy reveal get set update run sync backup transfer device completion'",
    );
    expect(publicCompletion.stdout).not.toContain(PORTABLE);

    const hostileReceipt = await executeInit(
      ['init', 'resume', OPERATION_ID],
      {
        coordinator: coordinatorWith({
          resume: () =>
            Promise.resolve({
              operationId: OPERATION_ID,
              vaultId: PORTABLE,
              deviceId: RECOVERY,
            } as never),
        }),
        sensitiveDisplay: recordingDisplay([]).port,
      },
      secretInput(),
    );
    expect(hostileReceipt.stdout).toBe('Vault initialized.\n');
    expect(`${hostileReceipt.stdout}${hostileReceipt.stderr}`).not.toContain(PORTABLE);
    expect(`${hostileReceipt.stdout}${hostileReceipt.stderr}`).not.toContain(RECOVERY);
  });
});

function coordinatorWith(
  overrides: Partial<CliVaultInitializationPort> = {},
): CliVaultInitializationPort {
  const unexpected = (): never => {
    throw new Error('Unexpected initialization operation');
  };
  return {
    begin: unexpected,
    beginImportedPortable: unexpected,
    resume: () => Promise.reject(new Error('Unexpected initialization resume')),
    cancel: () => Promise.reject(new Error('Unexpected initialization cancel')),
    ...overrides,
  };
}

function generatedAttempt(
  events: string[],
  expectedConfirmation: VaultInitializationConfirmation = {
    portableKey: PORTABLE,
    recoveryKey: RECOVERY,
  },
): VaultInitializationCreation {
  return attempt(
    events,
    { portableKey: PORTABLE, recoveryKey: RECOVERY },
    expectedConfirmation,
  ) as unknown as VaultInitializationCreation;
}

function importedAttempt(
  events: string[],
  expectedConfirmation: VaultInitializationConfirmation = {
    portableKey: PORTABLE,
    recoveryKey: RECOVERY,
  },
): VaultImportedPortableInitializationCreation {
  return attempt(
    events,
    { recoveryKey: RECOVERY },
    expectedConfirmation,
  ) as unknown as VaultImportedPortableInitializationCreation;
}

function attempt(
  events: string[],
  displayMaterial: Readonly<Record<string, string>>,
  expectedConfirmation: VaultInitializationConfirmation,
): Readonly<{
  operationId: typeof OPERATION_ID;
  takeDisplayMaterial: () => Readonly<Record<string, string>>;
  confirm: (
    confirmation: VaultInitializationConfirmation,
  ) => Promise<VaultInitializationReceipt>;
  cancel: () => void;
}> {
  return {
    operationId: OPERATION_ID,
    takeDisplayMaterial: () => {
      events.push('take');
      return displayMaterial;
    },
    confirm: (confirmation) => {
      events.push('confirm');
      expect(confirmation).toEqual(expectedConfirmation);
      return Promise.resolve(RECEIPT);
    },
    cancel: () => {
      events.push('cancel');
    },
  };
}

function recordingDisplay(events: string[]): Readonly<{
  port: SensitiveInitializationDisplayPort;
  requests: SensitiveInitializationDisplayRequest[];
}> {
  const requests: SensitiveInitializationDisplayRequest[] = [];
  return {
    requests,
    port: {
      display: (request) => {
        events.push('display');
        requests.push(request);
        return Promise.resolve({ acknowledged: true, interactiveTty: true });
      },
    },
  };
}

function secretInput(overrides: Partial<SecretInputPort> = {}): SecretInputPort {
  return {
    read: () => Promise.reject(new Error('Unexpected secret read')),
    readBatch: () => Promise.reject(new Error('Unexpected secret batch read')),
    ...overrides,
  };
}

async function executeInit(
  arguments_: readonly string[],
  initialization: CliInitializationDependencies,
  secrets: SecretInputPort,
): Promise<Readonly<{ exitCode: number; stdout: string; stderr: string }>> {
  const output = memoryOutput();
  const dependencies: CliDependencies = {
    ports: useCases(),
    secrets,
    initialization,
    runtime: {
      stdin: Readable.from([]),
      stdout: output.stdout.stream,
      stderr: output.stderr.stream,
    },
  };
  const exitCode = await runCli(arguments_, dependencies);
  return { exitCode, stdout: output.stdout.value(), stderr: output.stderr.value() };
}

async function executePublic(
  arguments_: readonly string[],
): Promise<Readonly<{ exitCode: number; stdout: string; stderr: string }>> {
  const output = memoryOutput();
  const exitCode = await runPublicCli(arguments_, {
    stdin: Readable.from([]),
    stdout: output.stdout.stream,
    stderr: output.stderr.stream,
  });
  return { exitCode, stdout: output.stdout.value(), stderr: output.stderr.value() };
}

function useCases(): CliUseCasePorts {
  const unexpected = (): Promise<never> =>
    Promise.reject(new Error('Unexpected use-case operation'));
  return {
    status: unexpected,
    lock: unexpected,
    show: unexpected,
    copy: unexpected,
    listInvitePage: unexpected,
    revokeInvite: unexpected,
    joinInvite: unexpected,
  };
}

function defaultPreferences(): VaultPreferences {
  return {
    productLabel: 'CredVault',
    executableName: 'creds',
    clipboardClearSeconds: 30,
    revealHideSeconds: 15,
    historyRetentionDays: 365,
    telemetryEnabled: false,
  };
}

function memoryOutput(): Readonly<{
  stdout: MemoryWritable;
  stderr: MemoryWritable;
}> {
  return { stdout: writable(), stderr: writable() };
}

type MemoryWritable = Readonly<{ stream: Writable; value: () => string }>;

function writable(): MemoryWritable {
  let content = '';
  const stream = new Writable({
    write(chunk, _encoding, callback) {
      content += Buffer.from(chunk).toString('utf8');
      callback();
    },
  });
  return { stream, value: () => content };
}

function captureWritable(): Writable {
  return new Writable({
    write(_chunk, _encoding, callback) {
      callback();
    },
  });
}
