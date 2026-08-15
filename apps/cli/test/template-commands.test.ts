import { describe, expect, it, vi } from 'vitest';
import { Readable, Writable } from 'node:stream';

import {
  CLI_EXIT_CODES,
  runCli,
  type CliDependencies,
  type CliUseCasePorts,
} from '../src/index.js';
import { builtInTemplates, getBuiltInTemplate } from '@kavrix/core';
import {
  groupIdSchema,
  recordRevisionSchema,
  templateIdSchema,
  templateVersionSchema,
  vaultIdSchema,
  type GroupPayload,
  type GroupTemplate,
} from '@kavrix/schemas';

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

function memoryOutput(): Readonly<{
  stdout: MemoryWritable;
  stderr: MemoryWritable;
}> {
  return { stdout: writable(), stderr: writable() };
}

function useCases(overrides: Partial<CliUseCasePorts>): CliUseCasePorts {
  const unexpected = (): Promise<never> => Promise.reject(new Error('Unexpected call'));
  return {
    status: unexpected,
    lock: unexpected,
    show: unexpected,
    copy: unexpected,
    listInvitePage: unexpected,
    revokeInvite: unexpected,
    joinInvite: unexpected,
    ...overrides,
  };
}

async function execute(
  arguments_: readonly string[],
  portsOverrides: Partial<CliUseCasePorts> = {},
): Promise<Readonly<{ exitCode: number; stdout: string; stderr: string }>> {
  const output = memoryOutput();
  const dependencies: CliDependencies = {
    ports: useCases(portsOverrides),
    secrets: {
      read: () => Promise.reject(new Error('secrets unneeded')),
      readBatch: () => Promise.reject(new Error('secrets unneeded')),
    },
    runtime: {
      stdin: Readable.from([]),
      stdout: output.stdout.stream,
      stderr: output.stderr.stream,
    },
  };
  const exitCode = await runCli(arguments_, dependencies);
  return { exitCode, stdout: output.stdout.value(), stderr: output.stderr.value() };
}

describe('CLI template commands', () => {
  it('lists built-in and active group templates in text and JSON mode', async () => {
    const customTemplate: GroupTemplate = {
      id: templateIdSchema.parse('template.custom101'),
      name: 'Custom Team Template',
      description: 'Custom team schema',
      version: templateVersionSchema.parse(1),
      fields: [],
      createdAt: '1970-01-01T00:00:00.000Z',
      updatedAt: '1970-01-01T00:00:00.000Z',
    };
    const sampleGroup: GroupPayload = {
      id: groupIdSchema.parse('group.team1'),
      vaultId: vaultIdSchema.parse('vault.1'),
      name: 'Engineering',
      aliases: [],
      tags: [],
      notes: [],
      template: customTemplate,
      sortOrder: 0,
      revision: recordRevisionSchema.parse(1),
      createdAt: '1970-01-01T00:00:00.000Z',
      updatedAt: '1970-01-01T00:00:00.000Z',
    };

    const listTemplates = vi.fn(() =>
      Promise.resolve([
        ...builtInTemplates.map((t) => ({
          id: t.id,
          name: t.name,
          description: t.description,
          builtInKey: t.builtInKey,
          version: t.version,
          fieldCount: t.fields.length,
        })),
        {
          id: sampleGroup.template.id,
          name: sampleGroup.template.name,
          description: sampleGroup.template.description,
          version: sampleGroup.template.version,
          fieldCount: sampleGroup.template.fields.length,
          groupName: sampleGroup.name,
          groupId: sampleGroup.id,
        },
      ]),
    );

    const resultText = await execute(['template', 'list'], { listTemplates });
    expect(resultText.exitCode).toBe(CLI_EXIT_CODES.success);
    expect(resultText.stdout).toContain('Templates (11):');
    expect(resultText.stdout).toContain('Email Account (builtin.email)');
    expect(resultText.stdout).toContain('Custom Team Template (template.custom101)');

    const resultJson = await execute(['template', 'list', '--json'], { listTemplates });
    expect(resultJson.exitCode).toBe(CLI_EXIT_CODES.success);
    const parsed = JSON.parse(resultJson.stdout) as { name: string; id: string }[];
    expect(parsed).toHaveLength(11);
    expect(parsed.some((item) => item.name === 'Email Account')).toBe(true);
    expect(parsed.some((item) => item.name === 'Custom Team Template')).toBe(true);
  });

  it('inspects a built-in template by key or name', async () => {
    const emailTemplate = getBuiltInTemplate('email');
    const inspectTemplate = vi.fn((query: string) => {
      if (query === 'email' || query === 'Email Account' || query === 'builtin.email') {
        return Promise.resolve(emailTemplate);
      }
      return Promise.reject(new Error('Template not found'));
    });

    const result = await execute(['template', 'inspect', 'email'], { inspectTemplate });
    expect(result.exitCode).toBe(CLI_EXIT_CODES.success);
    expect(result.stdout).toContain('Template: Email Account (builtin.email)');
    expect(result.stdout).toContain('Email address (email): email, required');
    expect(result.stdout).toContain('Password (password): secret, required, sensitive');

    const resultJson = await execute(['template', 'inspect', 'email', '--json'], {
      inspectTemplate,
    });
    expect(resultJson.exitCode).toBe(CLI_EXIT_CODES.success);
    const jsonParsed = JSON.parse(resultJson.stdout) as GroupTemplate;
    expect(jsonParsed.id).toBe('builtin.email');
    expect(jsonParsed.fields.length).toBe(12);
  });

  it('creates a new group template / container via template create', async () => {
    const createTemplate = vi.fn(
      (request: { name: string; description?: string; fromTemplate?: string }) =>
        Promise.resolve({
          vaultId: vaultIdSchema.parse('vault.1'),
          groupId: groupIdSchema.parse('group.201'),
          name: request.name,
        }),
    );

    const result = await execute(
      [
        'template',
        'create',
        'Cloud Secrets',
        '--from',
        'cloud-provider',
        '--description',
        'Cloud infrastructure',
      ],
      { createTemplate },
    );

    expect(result.exitCode).toBe(CLI_EXIT_CODES.success);
    expect(createTemplate).toHaveBeenCalledWith({
      name: 'Cloud Secrets',
      description: 'Cloud infrastructure',
      fromTemplate: 'cloud-provider',
    });
    expect(result.stdout).toContain('Template "Cloud Secrets" created.');
  });

  it('edits a group template metadata', async () => {
    const updateTemplate = vi.fn(() => Promise.resolve());

    const result = await execute(
      [
        'template',
        'edit',
        'Engineering',
        '--name',
        'Core Engineering',
        '--description',
        'Updated schema',
      ],
      { updateTemplate },
    );

    expect(result.exitCode).toBe(CLI_EXIT_CODES.success);
    expect(updateTemplate).toHaveBeenCalledWith({
      groupQuery: 'Engineering',
      name: 'Core Engineering',
      description: 'Updated schema',
    });
    expect(result.stdout).toContain('Template for "Engineering" updated.');
  });

  it('archives, restores, and deletes a group template', async () => {
    const archiveTemplate = vi.fn(() => Promise.resolve());
    const restoreTemplate = vi.fn(() => Promise.resolve());
    const deleteTemplate = vi.fn(() => Promise.resolve());

    const resultArchive = await execute(['template', 'archive', 'Engineering'], {
      archiveTemplate,
    });
    expect(resultArchive.exitCode).toBe(CLI_EXIT_CODES.success);
    expect(archiveTemplate).toHaveBeenCalledWith({ groupQuery: 'Engineering' });
    expect(resultArchive.stdout).toContain('Template for "Engineering" archived.');

    const resultRestore = await execute(['template', 'restore', 'group.1'], {
      restoreTemplate,
    });
    expect(resultRestore.exitCode).toBe(CLI_EXIT_CODES.success);
    expect(restoreTemplate).toHaveBeenCalledWith({ groupQuery: 'group.1' });
    expect(resultRestore.stdout).toContain('Template for "group.1" restored.');

    const resultDeleteNoForce = await execute(['template', 'delete', 'Engineering'], {
      deleteTemplate,
    });
    expect(resultDeleteNoForce.exitCode).toBe(CLI_EXIT_CODES.usage);
    expect(resultDeleteNoForce.stderr).toContain('--force');

    const resultDelete = await execute(
      ['template', 'delete', 'Engineering', '--force'],
      {
        deleteTemplate,
      },
    );
    expect(resultDelete.exitCode).toBe(CLI_EXIT_CODES.success);
    expect(deleteTemplate).toHaveBeenCalledWith('Engineering');
    expect(resultDelete.stdout).toContain('Template for "Engineering" deleted.');
  });

  it('supports --template option on group create', async () => {
    const createGroup = vi.fn(
      (request: { name: string; description?: string; template?: string }) =>
        Promise.resolve({
          vaultId: vaultIdSchema.parse('vault.1'),
          groupId: groupIdSchema.parse('group.301'),
          name: request.name,
        }),
    );

    const result = await execute(
      [
        'group',
        'create',
        'DB Admins',
        '--template',
        'database',
        '--description',
        'Database credentials',
      ],
      { createGroup },
    );

    expect(result.exitCode).toBe(CLI_EXIT_CODES.success);
    expect(createGroup).toHaveBeenCalledWith({
      name: 'DB Admins',
      description: 'Database credentials',
      template: 'database',
    });
    expect(result.stdout).toContain('Group "DB Admins" created.');
  });

  it('supports template show alias identically to template inspect', async () => {
    const emailTemplate = getBuiltInTemplate('email');
    const inspectTemplate = vi.fn(() => Promise.resolve(emailTemplate));

    const result = await execute(['template', 'show', 'email'], { inspectTemplate });
    expect(result.exitCode).toBe(CLI_EXIT_CODES.success);
    expect(inspectTemplate).toHaveBeenCalledWith('email');
    expect(result.stdout).toContain('Template: Email Account (builtin.email)');
  });

  it('sanitizes ANSI and control characters in template output', async () => {
    const listTemplates = vi.fn(() =>
      Promise.resolve([
        {
          id: 'template.malicious1',
          name: '\u001B[31mInjected Name\u001B[0m',
          description: '\u001B[32mInjected Description\u001B[0m',
          version: 1,
          fieldCount: 2,
        },
      ]),
    );

    const result = await execute(['template', 'list'], { listTemplates });
    expect(result.exitCode).toBe(CLI_EXIT_CODES.success);
    expect(result.stdout).not.toContain('\u001B[');
    expect(result.stdout).toContain('Injected Name');
  });

  it('fails closed when required arguments are missing', async () => {
    const resultInspect = await execute(['template', 'inspect']);
    expect(resultInspect.exitCode).toBe(CLI_EXIT_CODES.usage);
    expect(resultInspect.stderr).toContain('Invalid command usage');

    const resultCreate = await execute(['template', 'create']);
    expect(resultCreate.exitCode).toBe(CLI_EXIT_CODES.usage);
    expect(resultCreate.stderr).toContain('Invalid command usage');

    const resultEdit = await execute(['template', 'edit']);
    expect(resultEdit.exitCode).toBe(CLI_EXIT_CODES.usage);
    expect(resultEdit.stderr).toContain('Invalid command usage');
  });
});
