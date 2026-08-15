import { describe, expect, it, vi } from 'vitest';
import { Readable, Writable } from 'node:stream';

import {
  CLI_EXIT_CODES,
  runCli,
  type CliDependencies,
  type CliTemplateMigrationApplyResult,
  type CliTemplateMigrationStatusResult,
  type CliUseCasePorts,
} from '../src/index.js';
import type { CliApplyTemplateMigrationRequest } from '../src/mutation-contracts.js';
import {
  auditEventIdSchema,
  fieldDefinitionSchema,
  fieldIdSchema,
  groupIdSchema,
  templateIdSchema,
  templateMigrationIdSchema,
  templateVersionSchema,
  type GroupTemplate,
  type TemplateMigrationPlan,
} from '@kavrix/schemas';
import {
  getBuiltInTemplate,
  planTemplateMigration,
  SchemaMigrationError,
} from '@kavrix/core';

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
  return {
    exitCode,
    stdout: output.stdout.value(),
    stderr: output.stderr.value(),
  };
}

describe('CLI template migration commands', () => {
  const baseEmail = getBuiltInTemplate('email');
  const sourceTemplate: GroupTemplate = {
    ...baseEmail,
    id: templateIdSchema.parse('template.custom-team'),
    name: 'Custom Team Email',
    version: templateVersionSchema.parse(1),
  };

  const newField = fieldDefinitionSchema.parse({
    id: fieldIdSchema.parse('field.custom-team.department'),
    stableKey: 'department',
    label: 'Department Name',
    type: 'text',
    required: false,
    sensitive: false,
    repeatable: false,
    copyable: true,
    searchableLocally: true,
    showInPreview: true,
    copyPolicy: 'allowed',
    revealPolicy: 'never',
    reauthenticationPolicy: 'never',
    exportPolicy: 'encrypted-only',
    sortOrder: sourceTemplate.fields.length,
    createdAt: '1970-01-01T00:00:00.000Z',
    updatedAt: '1970-01-01T00:00:00.000Z',
  });

  const targetTemplate: GroupTemplate = {
    ...sourceTemplate,
    version: templateVersionSchema.parse(2),
    fields: [
      ...sourceTemplate.fields.slice(1), // remove first field (email)
      newField, // add new department field
    ],
  };

  const samplePlan: TemplateMigrationPlan = planTemplateMigration({
    migrationId: templateMigrationIdSchema.parse('migration.plan101'),
    auditEventId: auditEventIdSchema.parse('audit.evt101'),
    fromTemplate: sourceTemplate,
    toTemplate: targetTemplate,
    items: [],
    timestamp: '1970-01-01T00:00:00.000Z',
  });

  it('plans a template migration and displays steps with affected item counts', async () => {
    const planTemplateMigration = vi.fn(() => Promise.resolve(samplePlan));

    const resultText = await execute(
      ['template', 'migrate', 'plan', 'Engineering', '--target', 'database'],
      { planTemplateMigration },
    );

    expect(resultText.exitCode).toBe(CLI_EXIT_CODES.success);
    expect(planTemplateMigration).toHaveBeenCalledWith({
      groupQuery: 'Engineering',
      targetTemplateQuery: 'database',
    });
    expect(resultText.stdout).toContain('Migration Plan: migration.plan101');
    expect(resultText.stdout).toContain('From Version: 1 -> To Version: 2');
    expect(resultText.stdout).toContain('Total Items: 0');
    expect(resultText.stdout).toContain('archive-field: Email address');
    expect(resultText.stdout).toContain('add-field: Department Name');

    const resultJson = await execute(
      ['template', 'migrate', 'plan', 'Engineering', '--target', 'database', '--json'],
      { planTemplateMigration },
    );
    expect(resultJson.exitCode).toBe(CLI_EXIT_CODES.success);
    const parsed = JSON.parse(resultJson.stdout) as TemplateMigrationPlan;
    expect(parsed.id).toBe('migration.plan101');
    expect(parsed.steps.length).toBeGreaterThan(0);
  });

  it('fails closed when applying a risky migration without --confirm-risky', async () => {
    const applyTemplateMigration = vi.fn(
      (request: CliApplyTemplateMigrationRequest) => {
        if (!request.confirmRisky) {
          throw new SchemaMigrationError(
            'The migration contains changes that require explicit confirmation.',
          );
        }
        return Promise.resolve({
          migrationId: samplePlan.id,
          groupId: groupIdSchema.parse('group.team1'),
          fromVersion: 1,
          toVersion: 2,
          totalItems: 1,
          affectedSteps: 2,
        });
      },
    );

    const resultWithoutConfirm = await execute(
      ['template', 'migrate', 'apply', 'Engineering', '--target', 'database'],
      { applyTemplateMigration },
    );

    expect(resultWithoutConfirm.exitCode).toBe(CLI_EXIT_CODES.failure);
    expect(resultWithoutConfirm.stderr).toContain('confirmation');

    const resultWithConfirm = await execute(
      [
        'template',
        'migrate',
        'apply',
        'Engineering',
        '--target',
        'database',
        '--confirm-risky',
      ],
      { applyTemplateMigration },
    );

    expect(resultWithConfirm.exitCode).toBe(CLI_EXIT_CODES.success);
    expect(applyTemplateMigration).toHaveBeenCalledWith(
      expect.objectContaining({
        groupQuery: 'Engineering',
        targetTemplateQuery: 'database',
        confirmRisky: true,
      }),
    );
    expect(resultWithConfirm.stdout).toContain('Migration applied successfully.');
    expect(resultWithConfirm.stdout).toContain(
      'Migrated 1 item(s) to template version 2.',
    );
  });

  it('shows migration status for a group template', async () => {
    const getTemplateMigrationStatus = vi.fn(() =>
      Promise.resolve({
        groupId: groupIdSchema.parse('group.team1'),
        groupName: 'Engineering',
        templateId: sourceTemplate.id,
        templateName: sourceTemplate.name,
        currentVersion: 1,
        itemCount: 5,
        fieldCount: sourceTemplate.fields.length,
      }),
    );

    const result = await execute(['template', 'migrate', 'status', 'Engineering'], {
      getTemplateMigrationStatus,
    });

    expect(result.exitCode).toBe(CLI_EXIT_CODES.success);
    expect(getTemplateMigrationStatus).toHaveBeenCalledWith('Engineering');
    expect(result.stdout).toContain('Group: Engineering');
    expect(result.stdout).toContain('Template: Custom Team Email');
    expect(result.stdout).toContain('Current Version: 1');
    expect(result.stdout).toContain('Active Items: 5');
  });

  it('sanitizes ANSI and control characters in migration output', async () => {
    const maliciousPlan = {
      ...samplePlan,
      sourceTemplate: {
        ...sourceTemplate,
        name: '\u001B[31mMalicious Template\u001B[0m',
      },
    };
    const planTemplateMigration = vi.fn(() => Promise.resolve(maliciousPlan));

    const result = await execute(
      ['template', 'migrate', 'plan', 'Engineering', '--target', 'database'],
      {
        planTemplateMigration,
      },
    );

    expect(result.exitCode).toBe(CLI_EXIT_CODES.success);
    expect(result.stdout).not.toContain('\u001B[');
    expect(result.stdout).toContain('Malicious Template');
  });

  it('fails closed when required arguments are missing', async () => {
    const resultPlan = await execute(['template', 'migrate', 'plan']);
    expect(resultPlan.exitCode).toBe(CLI_EXIT_CODES.usage);
    expect(resultPlan.stderr).toContain('Invalid command usage');

    const resultApply = await execute(['template', 'migrate', 'apply']);
    expect(resultApply.exitCode).toBe(CLI_EXIT_CODES.usage);
    expect(resultApply.stderr).toContain('Invalid command usage');

    const resultStatus = await execute(['template', 'migrate', 'status']);
    expect(resultStatus.exitCode).toBe(CLI_EXIT_CODES.usage);
    expect(resultStatus.stderr).toContain('Invalid command usage');
  });

  it('renders JSON output for apply and status subcommands', async () => {
    const applyTemplateMigration = vi.fn(() =>
      Promise.resolve({
        migrationId: samplePlan.id,
        groupId: groupIdSchema.parse('group.team1'),
        fromVersion: 1,
        toVersion: 2,
        totalItems: 3,
        affectedSteps: 2,
      }),
    );
    const resultApplyJson = await execute(
      [
        'template',
        'migrate',
        'apply',
        'Engineering',
        '--target',
        'database',
        '--confirm-risky',
        '--json',
      ],
      { applyTemplateMigration },
    );
    expect(resultApplyJson.exitCode).toBe(CLI_EXIT_CODES.success);
    const applyParsed = JSON.parse(
      resultApplyJson.stdout,
    ) as CliTemplateMigrationApplyResult;
    expect(applyParsed.migrationId).toBe('migration.plan101');
    expect(applyParsed.totalItems).toBe(3);

    const getTemplateMigrationStatus = vi.fn(() =>
      Promise.resolve({
        groupId: groupIdSchema.parse('group.team1'),
        groupName: 'Engineering',
        templateId: sourceTemplate.id,
        templateName: sourceTemplate.name,
        currentVersion: 1,
        itemCount: 5,
        fieldCount: 3,
      }),
    );
    const resultStatusJson = await execute(
      ['template', 'migrate', 'status', 'Engineering', '--json'],
      { getTemplateMigrationStatus },
    );
    expect(resultStatusJson.exitCode).toBe(CLI_EXIT_CODES.success);
    const statusParsed = JSON.parse(
      resultStatusJson.stdout,
    ) as CliTemplateMigrationStatusResult;
    expect(statusParsed.groupName).toBe('Engineering');
    expect(statusParsed.currentVersion).toBe(1);
    expect(statusParsed.itemCount).toBe(5);
  });
});
