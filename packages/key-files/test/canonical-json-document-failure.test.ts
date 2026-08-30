import type * as FsPromises from 'node:fs/promises';

import { readFile, realpath, readdir, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { z } from 'zod';

import { createSecureTestDirectory as mkdtemp } from './secure-temporary-directory.js';

type FaultPhase =
  | 'none'
  | 'pre-publication'
  | 'post-rename'
  | 'final-verification'
  | 'directory-sync'
  | 'foreign-replacement'
  | 'transient-pre-publication'
  | 'transient-target-replacement';

const fault = vi.hoisted(() => ({
  phase: 'none' as FaultPhase,
  target: '',
  directory: '',
  renamed: false,
  fired: false,
  foreignContents: '',
  transientRenameFailures: 0,
  transientRenameLimit: 0,
}));

vi.mock('../src/windows-acl.js', () => ({
  setWindowsUserOnlyAcl: vi.fn(async () => undefined),
  verifyWindowsDirectoryAcl: vi.fn(async () => undefined),
  verifyWindowsUserOnlyAcl: vi.fn(async () => undefined),
}));

vi.mock('node:fs/promises', async (importOriginal) => {
  const actual = await importOriginal<typeof FsPromises>();
  const injected = (): NodeJS.ErrnoException => {
    const error = new Error(
      'injected publication secret canary',
    ) as NodeJS.ErrnoException;
    error.code = 'EIO';
    return error;
  };
  const transient = (): NodeJS.ErrnoException => {
    const error = injected();
    error.code = 'EPERM';
    return error;
  };
  return {
    ...actual,
    rename: async (oldPath: FsPromises.PathLike, newPath: FsPromises.PathLike) => {
      if (String(newPath) !== fault.target || fault.fired) {
        return actual.rename(oldPath, newPath);
      }
      if (
        (fault.phase === 'transient-pre-publication' ||
          fault.phase === 'transient-target-replacement') &&
        fault.transientRenameFailures < fault.transientRenameLimit
      ) {
        fault.transientRenameFailures += 1;
        if (fault.phase === 'transient-target-replacement') {
          await actual.unlink(newPath);
          await actual.writeFile(newPath, fault.foreignContents, { mode: 0o600 });
        }
        throw transient();
      }
      if (fault.phase === 'pre-publication') {
        fault.fired = true;
        throw injected();
      }
      await actual.rename(oldPath, newPath);
      fault.renamed = true;
      if (fault.phase === 'post-rename') {
        fault.fired = true;
        throw injected();
      }
      if (fault.phase === 'foreign-replacement') {
        await actual.unlink(newPath);
        await actual.writeFile(newPath, fault.foreignContents, { mode: 0o600 });
        fault.fired = true;
        throw injected();
      }
    },
    lstat: async (path: FsPromises.PathLike, options?: unknown) => {
      const result = await actual.lstat(path, options as never);
      if (
        fault.phase === 'final-verification' &&
        String(path) === fault.target &&
        fault.renamed &&
        !fault.fired
      ) {
        fault.fired = true;
        throw injected();
      }
      return result;
    },
    open: async (
      path: FsPromises.PathLike,
      flags: string | number,
      mode?: FsPromises.Mode,
    ) => {
      const handle = await actual.open(path, flags, mode);
      if (
        fault.phase !== 'directory-sync' ||
        String(path) !== fault.directory ||
        !fault.renamed ||
        fault.fired
      ) {
        return handle;
      }
      return new Proxy(handle, {
        get(target, property) {
          if (property === 'sync') {
            return async () => {
              fault.fired = true;
              throw injected();
            };
          }
          const value: unknown = Reflect.get(target, property, target);
          return typeof value === 'function' ? value.bind(target) : value;
        },
      });
    },
  };
});

import {
  transitionProtectedJsonDocument,
  transitionProtectedJsonDocumentWithPublicationStatus,
  writeProtectedJsonDocument,
} from '../src/canonical-json-document.js';

const schema = z.object({ version: z.literal(1), value: z.string() }).strict();
const options = { schema, maximumBytes: 1_024 };
let directory = '';

beforeEach(async () => {
  directory = await realpath(await mkdtemp(join(tmpdir(), 'kavrix-json-failure-')));
  resetFault();
});

afterEach(async () => {
  resetFault();
  await rm(directory, { force: true, recursive: true });
});

function resetFault(): void {
  fault.phase = 'none';
  fault.target = '';
  fault.directory = '';
  fault.renamed = false;
  fault.fired = false;
  fault.foreignContents = '';
  fault.transientRenameFailures = 0;
  fault.transientRenameLimit = 0;
}

function armFault(
  phase: Exclude<FaultPhase, 'none'>,
  target: string,
  foreignContents = '',
): void {
  fault.phase = phase;
  fault.target = target;
  fault.directory = directory;
  fault.renamed = false;
  fault.fired = false;
  fault.foreignContents = foreignContents;
}

function armTransientRename(
  target: string,
  limit: number,
  phase:
    | 'transient-pre-publication'
    | 'transient-target-replacement' = 'transient-pre-publication',
  foreignContents = '',
): void {
  fault.phase = phase;
  fault.target = target;
  fault.directory = directory;
  fault.renamed = false;
  fault.fired = false;
  fault.foreignContents = foreignContents;
  fault.transientRenameFailures = 0;
  fault.transientRenameLimit = limit;
}

describe(
  'protected canonical JSON publication failures',
  // A transient Windows rename failure under load reports a genuine
  // not-published outcome instead of the armed fault scenario; retries keep
  // every assertion intact while absorbing that platform noise.
  { retry: process.platform === 'win32' ? 2 : 0 },
  () => {
    it('preserves the throwing transition API and exact prior bytes before publication', async () => {
      const path = join(directory, 'document.json');
      await writeProtectedJsonDocument(
        path,
        { version: 1, value: 'before' },
        'create',
        options,
      );
      const before = await readFile(path, 'utf8');
      armFault('pre-publication', path);

      await expect(
        transitionProtectedJsonDocument(path, options, () => ({
          document: { version: 1, value: 'after' },
          result: undefined,
        })),
      ).rejects.toThrow('operation failed');
      expect(await readFile(path, 'utf8')).toBe(before);
    });

    it('returns definitely-not-published when authenticated readback matches the prior document', async () => {
      const path = join(directory, 'not-published.json');
      await writeProtectedJsonDocument(
        path,
        { version: 1, value: 'before' },
        'create',
        options,
      );
      armFault('pre-publication', path);

      const transition = await transitionProtectedJsonDocumentWithPublicationStatus(
        path,
        options,
        () => ({
          document: { version: 1, value: 'after' },
          result: 'updated',
        }),
      );

      expect(transition).toMatchObject({ status: 'not-published' });
      expect(transition).not.toHaveProperty('publication');
      expect(await readFile(path, 'utf8')).toBe('{"value":"before","version":1}');
    });

    it('retries an observed burst of transient Windows replacement rename failures', async () => {
      const path = join(directory, 'transient.json');
      await writeProtectedJsonDocument(
        path,
        { version: 1, value: 'before' },
        'create',
        options,
      );
      armTransientRename(path, 8);

      const transition = await transitionProtectedJsonDocumentWithPublicationStatus(
        path,
        options,
        () => ({
          document: { version: 1, value: 'after' },
          result: 'updated',
        }),
      );

      if (process.platform === 'win32') {
        expect(transition).toMatchObject({ status: 'published', result: 'updated' });
      } else {
        expect(transition).toMatchObject({ status: 'not-published' });
      }
      expect(fault.transientRenameFailures).toBe(process.platform === 'win32' ? 8 : 1);
      expect(await readFile(path, 'utf8')).toBe(
        process.platform === 'win32'
          ? '{"value":"after","version":1}'
          : '{"value":"before","version":1}',
      );
      await expect(readdir(directory)).resolves.toEqual(['transient.json']);
    });

    it('fails closed after exhausting transient Windows replacement retries', async () => {
      const path = join(directory, 'exhausted.json');
      await writeProtectedJsonDocument(
        path,
        { version: 1, value: 'before' },
        'create',
        options,
      );
      armTransientRename(path, 16);

      const transition = await transitionProtectedJsonDocumentWithPublicationStatus(
        path,
        options,
        () => ({
          document: { version: 1, value: 'after' },
          result: 'updated',
        }),
      );

      expect(transition).toMatchObject({ status: 'not-published' });
      expect(fault.transientRenameFailures).toBe(process.platform === 'win32' ? 16 : 1);
      expect(await readFile(path, 'utf8')).toBe('{"value":"before","version":1}');
      await expect(readdir(directory)).resolves.toEqual(['exhausted.json']);
    });

    it('rejects a target identity substitution before retrying the replacement', async () => {
      const path = join(directory, 'substituted.json');
      const foreign = '{"value":"foreign","version":1}';
      await writeProtectedJsonDocument(
        path,
        { version: 1, value: 'before' },
        'create',
        options,
      );
      armTransientRename(path, 1, 'transient-target-replacement', foreign);

      const transition = await transitionProtectedJsonDocumentWithPublicationStatus(
        path,
        options,
        () => ({
          document: { version: 1, value: 'after' },
          result: 'updated',
        }),
      );

      expect(transition).toMatchObject({ status: 'publication-uncertain' });
      expect(await readFile(path, 'utf8')).toBe(foreign);
      expect(fault.transientRenameFailures).toBe(1);
      await expect(readdir(directory)).resolves.toEqual(['substituted.json']);
    });

    it.each(['post-rename', 'final-verification', 'directory-sync'] as const)(
      'returns inspectable uncertainty after %s and retains the exact intended document',
      async (phase) => {
        const path = join(directory, `${phase}.json`);
        await writeProtectedJsonDocument(
          path,
          { version: 1, value: 'before' },
          'create',
          options,
        );
        armFault(phase, path);

        const transition = await transitionProtectedJsonDocumentWithPublicationStatus(
          path,
          options,
          () => ({
            document: { version: 1, value: 'after' },
            result: 'updated',
          }),
        );

        expect(transition).toMatchObject({ status: 'publication-uncertain' });
        if (transition.status !== 'publication-uncertain') {
          throw new Error('Expected uncertain publication');
        }
        expect(Object.isFrozen(transition.publication)).toBe(true);
        expect(Reflect.ownKeys(transition.publication)).toEqual([]);
        expect(JSON.stringify(transition.publication)).toBe('{}');
        expect(JSON.stringify(transition)).not.toContain(directory);
        expect(JSON.stringify(transition)).not.toContain(
          'injected publication secret canary',
        );
        expect(await readFile(path, 'utf8')).toBe('{"value":"after","version":1}');
      },
    );

    it('fails closed when a foreign replacement wins readback after rename', async () => {
      const path = join(directory, 'foreign.json');
      const foreign = '{"value":"foreign","version":1}';
      await writeProtectedJsonDocument(
        path,
        { version: 1, value: 'before' },
        'create',
        options,
      );
      armFault('foreign-replacement', path, foreign);

      const transition = await transitionProtectedJsonDocumentWithPublicationStatus(
        path,
        options,
        () => ({
          document: { version: 1, value: 'after' },
          result: 'updated',
        }),
      );

      expect(transition).toMatchObject({ status: 'publication-uncertain' });
      expect(await readFile(path, 'utf8')).toBe(foreign);
    });
  },
);
