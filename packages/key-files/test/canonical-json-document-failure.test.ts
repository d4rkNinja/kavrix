import { mkdtemp, readFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { z } from 'zod';

const replacementFailure = vi.hoisted(() => ({ enabled: false }));

vi.mock('../src/filesystem.js', async (importOriginal) => {
  const filesystem = await importOriginal<typeof import('../src/filesystem.js')>();
  return {
    ...filesystem,
    replaceSecureFileWhileExclusive: async (
      ...args: Parameters<typeof filesystem.replaceSecureFileWhileExclusive>
    ) => {
      if (replacementFailure.enabled) throw new Error('injected replacement failure');
      await filesystem.replaceSecureFileWhileExclusive(...args);
    },
  };
});

import {
  transitionProtectedJsonDocument,
  writeProtectedJsonDocument,
} from '../src/canonical-json-document.js';

const schema = z.object({ version: z.literal(1), value: z.string() }).strict();
const options = { schema, maximumBytes: 1_024 };
let directory = '';

beforeEach(async () => {
  directory = await mkdtemp(join(tmpdir(), 'kavrix-json-failure-'));
  replacementFailure.enabled = false;
});

afterEach(async () => {
  await rm(directory, { force: true, recursive: true });
});

describe('protected canonical JSON publication failures', () => {
  it('preserves exact prior bytes when protected replacement publication fails', async () => {
    const path = join(directory, 'document.json');
    await writeProtectedJsonDocument(
      path,
      { version: 1, value: 'before' },
      'create',
      options,
    );
    const before = await readFile(path, 'utf8');
    replacementFailure.enabled = true;

    await expect(
      transitionProtectedJsonDocument(path, options, () => ({
        document: { version: 1, value: 'after' },
        result: undefined,
      })),
    ).rejects.toThrow('injected replacement failure');
    expect(await readFile(path, 'utf8')).toBe(before);
  });
});
