import { chmod, readFile, rm, symlink } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { z } from 'zod';

import {
  type CanonicalJsonDocumentSchema,
  readProtectedJsonDocument,
  transitionProtectedJsonDocument,
  writeProtectedJsonDocument,
} from '../src/index.js';
import * as keyFiles from '../src/index.js';
import {
  createSecureTestDirectory as mkdtemp,
  writeSecureTestFile as writeFile,
} from './secure-temporary-directory.js';

const schema = z
  .object({
    entries: z.array(z.string().min(1).max(32)).max(4),
    version: z.literal(1),
  })
  .strict();
const options = { schema, maximumBytes: 1_024 };
const typedSchema: CanonicalJsonDocumentSchema<z.infer<typeof schema>> = schema;

let directory = '';

beforeEach(async () => {
  directory = await mkdtemp(join(tmpdir(), 'kavrix-canonical-json-'));
});

afterEach(async () => {
  await rm(directory, { force: true, recursive: true });
});

function path(name = 'document.json'): string {
  return join(directory, name);
}

describe('protected canonical JSON documents', () => {
  it('does not export raw exclusive transition capabilities', () => {
    expect(keyFiles).not.toHaveProperty('withExclusiveSecureFile');
    expect(keyFiles).not.toHaveProperty('readSecureFileWhileExclusive');
    expect(keyFiles).not.toHaveProperty('replaceSecureFileWhileExclusive');
    expect(keyFiles).not.toHaveProperty('writeSecureFile');
    expect(typedSchema.parse({ version: 1, entries: ['one'] })).toEqual({
      version: 1,
      entries: ['one'],
    });
  });

  it('creates, clones, and atomically transitions strict canonical documents', async () => {
    const file = path();
    await writeProtectedJsonDocument(
      file,
      { version: 1, entries: ['one'] },
      'create',
      options,
    );
    const read = await readProtectedJsonDocument(file, options);
    read.entries.push('mutated');
    expect(await readProtectedJsonDocument(file, options)).toEqual({
      version: 1,
      entries: ['one'],
    });

    const result = await transitionProtectedJsonDocument(
      file,
      options,
      async (current) => {
        expect(current).toEqual({ version: 1, entries: ['one'] });
        return {
          document: { version: 1, entries: [...current.entries, 'two'] },
          result: 'updated',
        };
      },
    );
    expect(result).toBe('updated');
    expect(await readFile(file, 'utf8')).toBe('{"entries":["one","two"],"version":1}');
  });

  it('rejects noncanonical, malformed, and unsafe existing documents', async () => {
    const file = path();
    await writeFile(file, '{"version":1,"entries":["one"]}', { mode: 0o600 });
    await expect(readProtectedJsonDocument(file, options)).rejects.toThrow('invalid');
    await writeFile(file, '{"entries":["one"],"version":1}\n', { mode: 0o600 });
    await expect(readProtectedJsonDocument(file, options)).rejects.toThrow('invalid');
    if (process.platform !== 'win32') {
      await writeProtectedJsonDocument(
        file,
        { version: 1, entries: ['one'] },
        'replace',
        options,
      );
      await chmod(file, 0o644);
      await expect(readProtectedJsonDocument(file, options)).rejects.toThrow('safe');
    }
  });

  it('preserves the existing bytes when a transition rejects its replacement', async () => {
    const file = path();
    await writeProtectedJsonDocument(
      file,
      { version: 1, entries: ['one'] },
      'create',
      options,
    );
    const before = await readFile(file, 'utf8');
    await expect(
      transitionProtectedJsonDocument(file, options, async () => ({
        document: { version: 2, entries: ['two'] } as never,
        result: undefined,
      })),
    ).rejects.toThrow('invalid');
    expect(await readFile(file, 'utf8')).toBe(before);
  });

  it('rejects a path replacement race before publishing through an attacker path', async () => {
    if (process.platform === 'win32') return;
    const file = path();
    const target = path('attacker-controlled.json');
    await writeProtectedJsonDocument(
      file,
      { version: 1, entries: ['one'] },
      'create',
      options,
    );
    await writeFile(target, '{"attacker":"unchanged"}', { mode: 0o600 });
    await expect(
      transitionProtectedJsonDocument(file, options, async (current) => {
        await rm(file);
        await symlink(target, file);
        return {
          document: { ...current, entries: ['replacement'] },
          result: undefined,
        };
      }),
    ).rejects.toThrow('safe');
    expect(await readFile(target, 'utf8')).toBe('{"attacker":"unchanged"}');
  });
});
