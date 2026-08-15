import { describe, expect, it, vi } from 'vitest';
import { Readable, Writable } from 'node:stream';

import {
  CLI_EXIT_CODES,
  runCli,
  type CliDependencies,
  type CliUseCasePorts,
} from '../src/index.js';
import {
  attachmentIdSchema,
  groupIdSchema,
  itemIdSchema,
  sha256DigestSchema,
} from '@kavrix/schemas';
import { PermissionError } from '@kavrix/core';

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

describe('CLI attachment commands', () => {
  const sampleAttachmentId = attachmentIdSchema.parse('attachment.test-file-1');
  const sampleGroupId = groupIdSchema.parse('group.team-a');
  const sampleItemId = itemIdSchema.parse('item.db-creds');
  const sampleDigest = sha256DigestSchema.parse(
    Buffer.alloc(32, 7).toString('base64url'),
  );

  it('lists attachments for a credential item in text and JSON format', async () => {
    const listAttachments = vi.fn(() =>
      Promise.resolve([
        {
          id: sampleAttachmentId,
          groupId: sampleGroupId,
          itemId: sampleItemId,
          chunkCount: 2,
          totalPlaintextBytes: 1024,
          createdAt: '2026-08-10T00:00:00.000Z',
          updatedAt: '2026-08-10T00:00:00.000Z',
        },
      ]),
    );

    const resultText = await execute(
      ['attachment', 'list', 'Engineering', 'Database'],
      { listAttachments },
    );
    expect(resultText.exitCode).toBe(CLI_EXIT_CODES.success);
    expect(listAttachments).toHaveBeenCalledWith('Engineering', 'Database');
    expect(resultText.stdout).toContain('attachment.test-file-1');
    expect(resultText.stdout).toContain('Chunks: 2');
    expect(resultText.stdout).toContain('1024 bytes');

    const resultJson = await execute(
      ['attachment', 'list', 'Engineering', 'Database', '--json'],
      { listAttachments },
    );
    expect(resultJson.exitCode).toBe(CLI_EXIT_CODES.success);
    const parsed = JSON.parse(resultJson.stdout) as readonly { id: string }[];
    expect(Array.isArray(parsed)).toBe(true);
    expect(parsed[0]?.id).toBe('attachment.test-file-1');
  });

  it('uploads an encrypted attachment to a credential item', async () => {
    const uploadAttachment = vi.fn(() =>
      Promise.resolve({
        attachmentId: sampleAttachmentId,
        groupId: sampleGroupId,
        itemId: sampleItemId,
        chunkCount: 1,
        totalPlaintextBytes: 512,
        plaintextSha256: sampleDigest,
      }),
    );

    const resultText = await execute(
      ['attachment', 'upload', 'Engineering', 'Database', './secrets.txt'],
      { uploadAttachment },
    );
    expect(resultText.exitCode).toBe(CLI_EXIT_CODES.success);
    expect(uploadAttachment).toHaveBeenCalledWith({
      groupQuery: 'Engineering',
      credentialQuery: 'Database',
      filePath: './secrets.txt',
    });
    expect(resultText.stdout).toContain('Attachment uploaded successfully.');
    expect(resultText.stdout).toContain('Attachment ID: attachment.test-file-1');
    expect(resultText.stdout).toContain('Size: 512 bytes');

    const resultJson = await execute(
      ['attachment', 'upload', 'Engineering', 'Database', './secrets.txt', '--json'],
      { uploadAttachment },
    );
    expect(resultJson.exitCode).toBe(CLI_EXIT_CODES.success);
    const parsed = JSON.parse(resultJson.stdout) as {
      attachmentId: string;
      totalPlaintextBytes: number;
    };
    expect(parsed.attachmentId).toBe('attachment.test-file-1');
    expect(parsed.totalPlaintextBytes).toBe(512);
  });

  it('downloads an attachment to a local path with overwrite protection', async () => {
    const downloadAttachment = vi.fn((request: { force?: boolean | undefined }) => {
      if (!request.force) {
        throw new PermissionError();
      }
      return Promise.resolve({
        attachmentId: sampleAttachmentId,
        destinationPath: './downloaded.txt',
        totalPlaintextBytes: 512,
        plaintextSha256: sampleDigest,
      });
    });

    const resultWithoutForce = await execute(
      [
        'attachment',
        'download',
        'Engineering',
        'Database',
        sampleAttachmentId,
        './downloaded.txt',
      ],
      { downloadAttachment },
    );
    expect(resultWithoutForce.exitCode).toBe(CLI_EXIT_CODES.failure);

    const resultWithForce = await execute(
      [
        'attachment',
        'download',
        'Engineering',
        'Database',
        sampleAttachmentId,
        './downloaded.txt',
        '--force',
      ],
      { downloadAttachment },
    );
    expect(resultWithForce.exitCode).toBe(CLI_EXIT_CODES.success);
    expect(downloadAttachment).toHaveBeenCalledWith({
      groupQuery: 'Engineering',
      credentialQuery: 'Database',
      attachmentId: sampleAttachmentId,
      destinationPath: './downloaded.txt',
      force: true,
    });
    expect(resultWithForce.stdout).toContain('Attachment downloaded successfully.');
    expect(resultWithForce.stdout).toContain('Destination: ./downloaded.txt');
  });

  it('deletes an attachment with explicit --force authorization', async () => {
    const deleteAttachment = vi.fn((request: { force?: boolean | undefined }) => {
      if (!request.force) {
        throw new PermissionError();
      }
      return Promise.resolve({
        attachmentId: sampleAttachmentId,
        groupId: sampleGroupId,
        itemId: sampleItemId,
        deleted: true,
      });
    });

    const resultWithoutForce = await execute(
      ['attachment', 'delete', 'Engineering', 'Database', sampleAttachmentId],
      { deleteAttachment },
    );
    expect(resultWithoutForce.exitCode).toBe(CLI_EXIT_CODES.failure);

    const resultWithForce = await execute(
      [
        'attachment',
        'delete',
        'Engineering',
        'Database',
        sampleAttachmentId,
        '--force',
      ],
      { deleteAttachment },
    );
    expect(resultWithForce.exitCode).toBe(CLI_EXIT_CODES.success);
    expect(deleteAttachment).toHaveBeenCalledWith({
      groupQuery: 'Engineering',
      credentialQuery: 'Database',
      attachmentId: sampleAttachmentId,
      force: true,
    });
    expect(resultWithForce.stdout).toContain(
      `Attachment "${sampleAttachmentId}" deleted.`,
    );
  });

  it('sanitizes ANSI sequences in attachment terminal output', async () => {
    const listAttachments = vi.fn(() =>
      Promise.resolve([
        {
          id: '\u001B[31mattachment.malicious\u001B[0m',
          groupId: sampleGroupId,
          itemId: sampleItemId,
          chunkCount: 1,
          totalPlaintextBytes: 100,
          createdAt: '2026-08-10T00:00:00.000Z',
          updatedAt: '2026-08-10T00:00:00.000Z',
        },
      ]),
    );

    const result = await execute(['attachment', 'list', 'Engineering', 'Database'], {
      listAttachments,
    });
    expect(result.exitCode).toBe(CLI_EXIT_CODES.success);
    expect(result.stdout).not.toContain('\u001B[');
    expect(result.stdout).toContain('attachment.malicious');
  });

  it('renders empty message when no attachments are found', async () => {
    const listAttachments = vi.fn(() => Promise.resolve([]));
    const result = await execute(['attachment', 'list', 'Engineering', 'Database'], {
      listAttachments,
    });
    expect(result.exitCode).toBe(CLI_EXIT_CODES.success);
    expect(result.stdout).toContain('No attachments found for this credential item.');
  });

  it('deletes an attachment with --json output', async () => {
    const deleteAttachment = vi.fn(() =>
      Promise.resolve({
        attachmentId: sampleAttachmentId,
        groupId: sampleGroupId,
        itemId: sampleItemId,
        deleted: true,
      }),
    );

    const result = await execute(
      [
        'attachment',
        'delete',
        'Engineering',
        'Database',
        sampleAttachmentId,
        '--force',
        '--json',
      ],
      { deleteAttachment },
    );
    expect(result.exitCode).toBe(CLI_EXIT_CODES.success);
    const parsed = JSON.parse(result.stdout) as {
      attachmentId: string;
      deleted: boolean;
    };
    expect(parsed.attachmentId).toBe('attachment.test-file-1');
    expect(parsed.deleted).toBe(true);
  });

  it('fails closed when required arguments are missing', async () => {
    const resList = await execute(['attachment', 'list']);
    expect(resList.exitCode).toBe(CLI_EXIT_CODES.usage);
    expect(resList.stderr).toContain('Invalid command usage');

    const resUpload = await execute(['attachment', 'upload', 'Engineering']);
    expect(resUpload.exitCode).toBe(CLI_EXIT_CODES.usage);
    expect(resUpload.stderr).toContain('Invalid command usage');

    const resDownload = await execute(['attachment', 'download', 'Engineering']);
    expect(resDownload.exitCode).toBe(CLI_EXIT_CODES.usage);
    expect(resDownload.stderr).toContain('Invalid command usage');

    const resDelete = await execute(['attachment', 'delete', 'Engineering']);
    expect(resDelete.exitCode).toBe(CLI_EXIT_CODES.usage);
    expect(resDelete.stderr).toContain('Invalid command usage');
  });
});
