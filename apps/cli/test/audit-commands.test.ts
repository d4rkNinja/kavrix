import { describe, expect, it, vi } from 'vitest';
import { Readable, Writable } from 'node:stream';

import {
  CLI_EXIT_CODES,
  runCli,
  type CliAuditEventPage,
  type CliDependencies,
  type CliUseCasePorts,
} from '../src/index.js';
import { deviceIdSchema, vaultIdSchema } from '@kavrix/schemas';
import { NotFoundError } from '@kavrix/core';

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

describe('CLI audit commands', () => {
  const sampleVaultId = vaultIdSchema.parse('vault.acme');
  const sampleDeviceId = deviceIdSchema.parse('device.workstation');
  /** Built from code points so this source file stays free of control bytes. */
  const ESCAPE = String.fromCodePoint(0x1b);
  const REPLACEMENT = String.fromCodePoint(0xfffd);

  const samplePage: CliAuditEventPage = {
    events: [
      {
        version: 1,
        eventId: 'audit.slot.slot.device-1.create',
        eventClass: 'device',
        action: 'create',
        subject: 'slot.device-1',
        occurredAt: '2026-08-05T00:00:00.000Z',
        state: 'active',
        deviceId: sampleDeviceId,
      },
      {
        version: 1,
        eventId: 'audit.slot.slot.portable-1.revoke',
        eventClass: 'slot',
        action: 'revoke',
        subject: 'slot.portable-1',
        occurredAt: '2026-08-01T00:00:00.000Z',
        state: 'revoked',
      },
    ],
    nextCursor: 'audit.slot.slot.portable-1.revoke',
    totalCount: 5,
  };

  it('lists audit events newest first in text and JSON format', async () => {
    const listAuditEvents = vi.fn(() => Promise.resolve(samplePage));

    const resultText = await execute(['audit', 'list'], { listAuditEvents });
    expect(resultText.exitCode).toBe(CLI_EXIT_CODES.success);
    expect(listAuditEvents).toHaveBeenCalledWith({});
    expect(resultText.stdout).toContain('Audit Events (2 of 5):');
    expect(resultText.stdout).toContain('device/create');
    expect(resultText.stdout).toContain('Subject: slot.device-1');
    expect(resultText.stdout).toContain('slot/revoke');
    expect(resultText.stdout).toContain(
      'Next cursor: audit.slot.slot.portable-1.revoke',
    );

    const resultJson = await execute(['audit', 'list', '--json'], { listAuditEvents });
    expect(resultJson.exitCode).toBe(CLI_EXIT_CODES.success);
    const parsed = JSON.parse(resultJson.stdout) as {
      events: readonly { eventId: string; eventClass: string }[];
      nextCursor: string | null;
      totalCount: number;
    };
    expect(parsed.events.length).toBe(2);
    expect(parsed.events[0]?.eventClass).toBe('device');
    expect(parsed.nextCursor).toBe('audit.slot.slot.portable-1.revoke');
    expect(parsed.totalCount).toBe(5);
  });

  it('renders an empty audit message when the projection holds no events', async () => {
    const listAuditEvents = vi.fn(() =>
      Promise.resolve({ events: [], nextCursor: null, totalCount: 0 }),
    );
    const result = await execute(['audit', 'list'], { listAuditEvents });
    expect(result.exitCode).toBe(CLI_EXIT_CODES.success);
    expect(result.stdout).toContain('No audit events found for this vault.');
  });

  it('forwards the class filter, page size, and cursor as a parsed request', async () => {
    const listAuditEvents = vi.fn(() =>
      Promise.resolve({ events: [], nextCursor: null, totalCount: 0 }),
    );
    const result = await execute(
      [
        'audit',
        'list',
        '--class',
        'mutation',
        '--limit',
        '25',
        '--cursor',
        'audit.mutation.item.db-creds.r4',
      ],
      { listAuditEvents },
    );
    expect(result.exitCode).toBe(CLI_EXIT_CODES.success);
    expect(listAuditEvents).toHaveBeenCalledWith({
      eventClass: 'mutation',
      limit: 25,
      cursor: 'audit.mutation.item.db-creds.r4',
    });
  });

  it('rejects out-of-range and non-canonical page sizes as usage errors', async () => {
    const listAuditEvents = vi.fn(() =>
      Promise.resolve({ events: [], nextCursor: null, totalCount: 0 }),
    );
    for (const limit of ['0', '201', 'abc', '-1', '1e2', '025']) {
      const result = await execute(['audit', 'list', '--limit', limit], {
        listAuditEvents,
      });
      expect(result.exitCode).toBe(CLI_EXIT_CODES.usage);
      expect(result.stderr).toBe(
        'Error [CLI_USAGE]: The audit list request is invalid.\n',
      );
    }
    expect(listAuditEvents).not.toHaveBeenCalled();

    const boundary = await execute(['audit', 'list', '--limit', '200'], {
      listAuditEvents,
    });
    expect(boundary.exitCode).toBe(CLI_EXIT_CODES.success);
    expect(listAuditEvents).toHaveBeenCalledWith({ limit: 200 });
  });

  it('fails closed on an unknown event class and a hostile cursor', async () => {
    const listAuditEvents = vi.fn(() =>
      Promise.resolve({ events: [], nextCursor: null, totalCount: 0 }),
    );
    const unknownClass = await execute(['audit', 'list', '--class', 'everything'], {
      listAuditEvents,
    });
    expect(unknownClass.exitCode).toBe(CLI_EXIT_CODES.usage);
    expect(unknownClass.stderr).toBe(
      'Error [CLI_USAGE]: The audit list request is invalid.\n',
    );

    const hostileCursor = await execute(
      ['audit', 'list', '--cursor', `audit.${ESCAPE}[31mhostile${ESCAPE}[0m`],
      { listAuditEvents },
    );
    expect(hostileCursor.exitCode).toBe(CLI_EXIT_CODES.usage);
    expect(hostileCursor.stderr).not.toContain(`${ESCAPE}[`);
    expect(listAuditEvents).not.toHaveBeenCalled();
  });

  it('inspects a single audit event by identifier in text and JSON format', async () => {
    const showAuditEvent = vi.fn(() =>
      Promise.resolve({
        vaultId: sampleVaultId,
        event: {
          version: 1 as const,
          eventId: 'audit.mutation.item.db-creds.r4',
          eventClass: 'mutation' as const,
          action: 'queue' as const,
          subject: 'item.db-creds',
          occurredAt: '2026-08-10T00:00:00.000Z',
          recordRevision: 4,
        },
      }),
    );

    const resultText = await execute(
      ['audit', 'show', 'audit.mutation.item.db-creds.r4'],
      { showAuditEvent },
    );
    expect(resultText.exitCode).toBe(CLI_EXIT_CODES.success);
    expect(showAuditEvent).toHaveBeenCalledWith({
      eventId: 'audit.mutation.item.db-creds.r4',
    });
    expect(resultText.stdout).toContain('Audit Event audit.mutation.item.db-creds.r4:');
    expect(resultText.stdout).toContain('Vault ID: vault.acme');
    expect(resultText.stdout).toContain('Class: mutation');
    expect(resultText.stdout).toContain('Action: queue');
    expect(resultText.stdout).toContain('Record Revision: 4');

    const resultJson = await execute(
      ['audit', 'show', 'audit.mutation.item.db-creds.r4', '--json'],
      { showAuditEvent },
    );
    expect(resultJson.exitCode).toBe(CLI_EXIT_CODES.success);
    const parsed = JSON.parse(resultJson.stdout) as {
      vaultId: string;
      event: { eventId: string; action: string };
    };
    expect(parsed.vaultId).toBe('vault.acme');
    expect(parsed.event.action).toBe('queue');
  });

  it('reports a missing audit event as not found', async () => {
    const showAuditEvent = vi.fn(() => Promise.reject(new NotFoundError()));
    const result = await execute(['audit', 'show', 'audit.slot.absent.create'], {
      showAuditEvent,
    });
    expect(result.exitCode).toBe(CLI_EXIT_CODES.notFound);
  });

  it('sanitizes terminal ANSI sequences in audit output', async () => {
    const hostileSubject = `slot.${ESCAPE}[31mhostile${ESCAPE}[0m`;
    const listAuditEvents = vi.fn(() =>
      Promise.resolve({
        events: [
          {
            version: 1 as const,
            eventId: `audit.slot.${hostileSubject}.create`,
            eventClass: 'slot' as const,
            action: 'create' as const,
            subject: hostileSubject,
            occurredAt: '2026-08-01T00:00:00.000Z',
            state: 'active' as const,
          },
        ],
        nextCursor: null,
        totalCount: 1,
      }),
    );

    const result = await execute(['audit', 'list'], { listAuditEvents });
    expect(result.exitCode).toBe(CLI_EXIT_CODES.success);
    expect(result.stdout).not.toContain(`${ESCAPE}[`);
    // Each ANSI escape sequence is replaced with the U+FFFD replacement character.
    expect(result.stdout).toContain(`slot.${REPLACEMENT}hostile${REPLACEMENT}`);
  });

  it('fails closed when the audit event identifier is missing or malformed', async () => {
    const showAuditEvent = vi.fn(() => Promise.reject(new Error('Unexpected call')));

    const missing = await execute(['audit', 'show'], { showAuditEvent });
    expect(missing.exitCode).toBe(CLI_EXIT_CODES.usage);
    expect(missing.stderr).toContain('Invalid command usage');

    const malformed = await execute(['audit', 'show', 'audit event/with spaces'], {
      showAuditEvent,
    });
    expect(malformed.exitCode).toBe(CLI_EXIT_CODES.usage);
    expect(malformed.stderr).toBe(
      'Error [CLI_USAGE]: The audit event identifier is invalid.\n',
    );
    expect(showAuditEvent).not.toHaveBeenCalled();
  });
});
