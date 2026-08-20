import { execFile } from 'node:child_process';
import { createHash } from 'node:crypto';
import {
  AuthenticationError,
  formatPortableKey,
  generatePortableKey,
} from '@kavrix/crypto';
import {
  link,
  mkdir,
  mkdtemp,
  open,
  readFile,
  readdir,
  realpath,
  rm,
  stat,
  symlink,
  writeFile,
} from 'node:fs/promises';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { promisify } from 'node:util';

import { afterEach, beforeEach, describe, expect, it } from 'vitest';

import {
  PortableKeyFileError,
  readPortableKeyFile,
  writePortableKeyFile,
} from '../src/index.js';
import {
  MAX_PORTABLE_KEY_FILE_BYTES,
  readSecureFile,
  writeSecureFile,
} from '../src/filesystem.js';
import { setWindowsUserOnlyAcl, verifyWindowsUserOnlyAcl } from '../src/windows-acl.js';

const execFileAsync = promisify(execFile);
const UNBOUND = { kind: 'unbound' } as const;
const UNPROTECTED = { kind: 'unprotected' } as const;

let testDirectory = '';

beforeEach(async () => {
  testDirectory = await mkdtemp(join(tmpdir(), 'kavrix-key-files-'));
  if (process.platform === 'win32') {
    await setWindowsUserOnlyAcl(testDirectory);
  }
});

afterEach(async () => {
  await rm(testDirectory, { force: true, recursive: true });
});

function key(fill: number): Uint8Array {
  return new Uint8Array(32).fill(fill);
}

function target(name = 'portable-key.cvk'): string {
  return join(testDirectory, name);
}

async function grantWindowsEveryoneRead(path: string): Promise<void> {
  const systemRoot = process.env['SystemRoot'];
  if (systemRoot === undefined) throw new Error('SystemRoot is required on Windows');
  await execFileAsync(join(systemRoot, 'System32', 'icacls.exe'), [
    path,
    '/grant',
    '*S-1-1-0:(R)',
  ]);
}

async function grantWindowsEveryoneInheritedModify(path: string): Promise<void> {
  const systemRoot = process.env['SystemRoot'];
  if (systemRoot === undefined) throw new Error('SystemRoot is required on Windows');
  await execFileAsync(join(systemRoot, 'System32', 'icacls.exe'), [
    path,
    '/grant',
    '*S-1-1-0:(OI)(CI)(M)',
  ]);
}

describe('portable key filesystem adapter', () => {
  it('creates and reads a canonical unprotected key file without mutating inputs', async () => {
    const path = target();
    const portableKey = key(7);

    await writePortableKeyFile(path, portableKey, UNBOUND, {
      protection: UNPROTECTED,
    });

    expect(portableKey).toEqual(key(7));
    await expect(
      readPortableKeyFile(path, UNPROTECTED, UNBOUND),
    ).resolves.toMatchObject({
      key: portableKey,
      kind: 'unbound',
      protected: false,
    });
    expect(await readdir(testDirectory)).toEqual(['portable-key.cvk']);
  });

  it('creates and reads a protected key without persisting its copy form', async () => {
    const path = target();
    const portableKey = generatePortableKey();
    const passphrase = new TextEncoder().encode('portable file passphrase');
    const copyForm = formatPortableKey(portableKey);

    await writePortableKeyFile(path, portableKey, UNBOUND, {
      protection: { kind: 'passphrase', passphrase },
    });

    const bytes = await readFile(path);
    expect(bytes.toString('ascii')).not.toContain(copyForm);
    expect(passphrase).toEqual(new TextEncoder().encode('portable file passphrase'));
    await expect(
      readPortableKeyFile(path, { kind: 'passphrase', passphrase }, UNBOUND),
    ).resolves.toMatchObject({ key: portableKey, protected: true });
    await expect(
      readPortableKeyFile(
        path,
        { kind: 'passphrase', passphrase: new TextEncoder().encode('wrong') },
        UNBOUND,
      ),
    ).rejects.toBeInstanceOf(AuthenticationError);
  });

  it('uses create-new semantics under concurrency and never changes the winner', async () => {
    const path = target();
    const results = await Promise.allSettled([
      writePortableKeyFile(path, key(1), UNBOUND, { protection: UNPROTECTED }),
      writePortableKeyFile(path, key(2), UNBOUND, { protection: UNPROTECTED }),
    ]);
    expect(results.filter(({ status }) => status === 'fulfilled')).toHaveLength(1);
    expect(results.filter(({ status }) => status === 'rejected')).toHaveLength(1);

    const parsed = await readPortableKeyFile(path, UNPROTECTED);
    expect([key(1), key(2)]).toContainEqual(parsed.key);
    expect(await readdir(testDirectory)).toEqual(['portable-key.cvk']);
  });

  it('refuses an existing target and leaves its bytes unchanged', async () => {
    const path = target();
    await writePortableKeyFile(path, key(3), UNBOUND, { protection: UNPROTECTED });

    await expect(
      writePortableKeyFile(path, key(4), UNBOUND, { protection: UNPROTECTED }),
    ).rejects.toMatchObject({ code: 'KEY_FILE_ALREADY_EXISTS' });
    await expect(readPortableKeyFile(path, UNPROTECTED)).resolves.toMatchObject({
      key: key(3),
    });
    expect(await readdir(testDirectory)).toEqual(['portable-key.cvk']);
  });

  it('runtime-rejects unknown write modes before creating a file', async () => {
    await expect(
      writePortableKeyFile(target(), key(4), UNBOUND, {
        mode: 'overwrite' as never,
        protection: UNPROTECTED,
      }),
    ).rejects.toMatchObject({ code: 'KEY_FILE_OPERATION_FAILED' });
    expect(await readdir(testDirectory)).toEqual([]);
  });

  it('rejects empty and oversized raw writes at the filesystem boundary', async () => {
    await expect(
      writeSecureFile(target(), new Uint8Array(), 'create'),
    ).rejects.toMatchObject({ code: 'KEY_FILE_OPERATION_FAILED' });
    await expect(
      writeSecureFile(
        target(),
        new Uint8Array(MAX_PORTABLE_KEY_FILE_BYTES + 1),
        'create',
      ),
    ).rejects.toMatchObject({ code: 'KEY_FILE_OPERATION_FAILED' });
    expect(await readdir(testDirectory)).toEqual([]);
  });

  it('requires an existing safe target for explicit replacement', async () => {
    await expect(
      writePortableKeyFile(target(), key(4), UNBOUND, {
        mode: 'replace',
        protection: UNPROTECTED,
      }),
    ).rejects.toMatchObject({ code: 'KEY_FILE_NOT_FOUND' });
    expect(await readdir(testDirectory)).toEqual([]);
  });

  it('atomically replaces an existing safe file and removes staging artifacts', async () => {
    const path = target();
    await writePortableKeyFile(path, key(5), UNBOUND, { protection: UNPROTECTED });

    await writePortableKeyFile(path, key(6), UNBOUND, {
      mode: 'replace',
      protection: UNPROTECTED,
    });

    await expect(readPortableKeyFile(path, UNPROTECTED)).resolves.toMatchObject({
      key: key(6),
    });
    expect(await readdir(testDirectory)).toEqual(['portable-key.cvk']);
  });

  it('serializes concurrent replacements without publishing a partial document', async () => {
    const path = target();
    await writePortableKeyFile(path, key(5), UNBOUND, { protection: UNPROTECTED });

    const replacements = await Promise.allSettled([
      writePortableKeyFile(path, key(6), UNBOUND, {
        mode: 'replace',
        protection: UNPROTECTED,
      }),
      writePortableKeyFile(path, key(7), UNBOUND, {
        mode: 'replace',
        protection: UNPROTECTED,
      }),
    ]);

    expect(replacements.some(({ status }) => status === 'fulfilled')).toBe(true);
    const parsed = await readPortableKeyFile(path, UNPROTECTED);
    expect([key(6), key(7)]).toContainEqual(parsed.key);
    expect(await readdir(testDirectory)).toEqual(['portable-key.cvk']);
  });

  it('fails closed on a stale replacement lock without changing the file', async () => {
    const path = target();
    await writePortableKeyFile(path, key(7), UNBOUND, { protection: UNPROTECTED });
    const canonicalTarget = await realpath(path);
    const lockDigest = createHash('sha256')
      .update(canonicalTarget, 'utf8')
      .digest('hex');
    const staleLock = join(testDirectory, `.kavrix-${lockDigest}.lock`);
    const lockHandle = await open(staleLock, 'wx', 0o600);
    await lockHandle.close();

    await expect(
      writePortableKeyFile(path, key(8), UNBOUND, {
        mode: 'replace',
        protection: UNPROTECTED,
      }),
    ).rejects.toMatchObject({ code: 'KEY_FILE_BUSY' });
    await expect(readPortableKeyFile(path, UNPROTECTED)).resolves.toMatchObject({
      key: key(7),
    });
    expect(await readdir(testDirectory)).toContain(`.kavrix-${lockDigest}.lock`);
  });

  it('rejects directories and reparse-point or symlink targets', async () => {
    const directoryTarget = target('directory');
    const junctionTarget = target('junction');
    await mkdir(directoryTarget);
    await symlink(directoryTarget, junctionTarget, 'junction');

    await expect(
      readPortableKeyFile(directoryTarget, UNPROTECTED),
    ).rejects.toMatchObject({
      code: 'KEY_FILE_UNSAFE',
    });
    await expect(
      readPortableKeyFile(junctionTarget, UNPROTECTED),
    ).rejects.toMatchObject({
      code: 'KEY_FILE_UNSAFE',
    });
  });

  it('rejects hard-linked files because a second plaintext location is ambiguous', async () => {
    const path = target();
    const alias = target('alias.cvk');
    await writePortableKeyFile(path, key(8), UNBOUND, { protection: UNPROTECTED });
    await link(path, alias);

    await expect(readPortableKeyFile(path, UNPROTECTED)).rejects.toMatchObject({
      code: 'KEY_FILE_UNSAFE',
    });
  });

  it('bounds reads even when a safe file grows after creation', async () => {
    const path = target();
    await writePortableKeyFile(path, key(9), UNBOUND, { protection: UNPROTECTED });
    const handle = await open(path, 'a');
    await handle.write(Buffer.alloc(16_384));
    await handle.close();

    await expect(readPortableKeyFile(path, UNPROTECTED)).rejects.toMatchObject({
      code: 'KEY_FILE_UNSAFE',
    });
  });

  it('rejects an empty regular file before allocating a format buffer', async () => {
    const handle = await open(target(), 'wx', 0o600);
    await handle.close();
    await expect(readSecureFile(target())).rejects.toMatchObject({
      code: 'KEY_FILE_UNSAFE',
    });
  });

  it('accepts an exact relative target while keeping native errors path-free', async () => {
    await writePortableKeyFile(target(), key(9), UNBOUND, {
      protection: UNPROTECTED,
    });
    const previousDirectory = process.cwd();
    try {
      process.chdir(testDirectory);
      await expect(
        readPortableKeyFile('portable-key.cvk', UNPROTECTED),
      ).resolves.toMatchObject({ key: key(9) });
    } finally {
      process.chdir(previousDirectory);
    }
  });

  it('never includes a hostile path or native failure details in errors', async () => {
    const secretCanary = 'portable-secret-canary';
    const operation = readPortableKeyFile(target(secretCanary), UNPROTECTED);
    await expect(operation).rejects.toBeInstanceOf(PortableKeyFileError);
    await expect(operation).rejects.not.toThrow(secretCanary);
  });

  it.each(['bad\nname', 'bad\u007fname'])(
    'rejects the hostile basename %j without echoing it',
    async (name) => {
      const operation = writePortableKeyFile(target(name), key(9), UNBOUND, {
        protection: UNPROTECTED,
      });
      await expect(operation).rejects.toMatchObject({
        code: 'KEY_FILE_INVALID_PATH',
      });
      await expect(operation).rejects.not.toThrow(name);
    },
  );

  it('rejects missing or structurally invalid path values', async () => {
    await expect(readSecureFile('')).rejects.toMatchObject({
      code: 'KEY_FILE_INVALID_PATH',
    });
    const parentFile = target('parent-file');
    await writeFile(parentFile, 'not a directory');
    await expect(readSecureFile(join(parentFile, 'child'))).rejects.toBeInstanceOf(
      PortableKeyFileError,
    );
  });

  it.runIf(process.platform !== 'win32')(
    'requires current-user ownership and mode 0600 or stricter on Unix',
    async () => {
      const path = target();
      await writePortableKeyFile(path, key(10), UNBOUND, {
        protection: UNPROTECTED,
      });
      expect((await stat(path)).mode & 0o777).toBe(0o600);
      const handle = await open(path, 'r+');
      await handle.chmod(0o700);
      await expect(readPortableKeyFile(path, UNPROTECTED)).rejects.toMatchObject({
        code: 'KEY_FILE_UNSAFE',
      });
      await handle.chmod(0o640);
      await handle.close();
      await expect(readPortableKeyFile(path, UNPROTECTED)).rejects.toMatchObject({
        code: 'KEY_FILE_UNSAFE',
      });
    },
  );

  it.runIf(process.platform !== 'win32')(
    'rejects a Unix FIFO before attempting a blocking read',
    async () => {
      const path = target('pipe');
      await execFileAsync('mkfifo', [path]);
      await expect(readPortableKeyFile(path, UNPROTECTED)).rejects.toMatchObject({
        code: 'KEY_FILE_UNSAFE',
      });
    },
  );

  it.runIf(process.platform === 'win32')(
    'creates a protected Windows DACL and rejects an explicit Everyone grant',
    async () => {
      const path = target();
      await writePortableKeyFile(path, key(11), UNBOUND, {
        protection: UNPROTECTED,
      });
      await expect(readPortableKeyFile(path, UNPROTECTED)).resolves.toMatchObject({
        key: key(11),
      });

      await grantWindowsEveryoneRead(path);
      await expect(readPortableKeyFile(path, UNPROTECTED)).rejects.toMatchObject({
        code: 'KEY_FILE_UNSAFE',
      });
    },
  );

  it.runIf(process.platform === 'win32')(
    'ignores hostile Windows system-root environment overrides',
    async () => {
      const originalSystemRoot = process.env['SystemRoot'];
      const originalWindir = process.env['WINDIR'];
      try {
        process.env['SystemRoot'] = 'C:\\attacker-controlled';
        process.env['WINDIR'] = 'C:\\attacker-controlled';
        await expect(verifyWindowsUserOnlyAcl(testDirectory)).resolves.toBeUndefined();
      } finally {
        if (originalSystemRoot === undefined) delete process.env['SystemRoot'];
        else process.env['SystemRoot'] = originalSystemRoot;
        if (originalWindir === undefined) delete process.env['WINDIR'];
        else process.env['WINDIR'] = originalWindir;
      }
    },
  );

  it.runIf(process.platform === 'win32')(
    'rejects alternate data streams and reserved Windows device names',
    async () => {
      await expect(
        writePortableKeyFile(`${target()}:alternate`, key(12), UNBOUND, {
          protection: UNPROTECTED,
        }),
      ).rejects.toMatchObject({ code: 'KEY_FILE_INVALID_PATH' });
      await expect(
        writePortableKeyFile(target('NUL'), key(12), UNBOUND, {
          protection: UNPROTECTED,
        }),
      ).rejects.toMatchObject({ code: 'KEY_FILE_INVALID_PATH' });
      await expect(
        writePortableKeyFile(target('trailing.'), key(12), UNBOUND, {
          protection: UNPROTECTED,
        }),
      ).rejects.toMatchObject({ code: 'KEY_FILE_INVALID_PATH' });
      await expect(
        writePortableKeyFile(target('trailing '), key(12), UNBOUND, {
          protection: UNPROTECTED,
        }),
      ).rejects.toMatchObject({ code: 'KEY_FILE_INVALID_PATH' });
    },
  );

  it.runIf(process.platform === 'win32')(
    'does not replace a file after its DACL becomes unsafe',
    async () => {
      const path = target();
      await writePortableKeyFile(path, key(13), UNBOUND, {
        protection: UNPROTECTED,
      });
      const before = await readFile(path);
      await grantWindowsEveryoneRead(path);

      await expect(
        writePortableKeyFile(path, key(14), UNBOUND, {
          mode: 'replace',
          protection: UNPROTECTED,
        }),
      ).rejects.toMatchObject({ code: 'KEY_FILE_UNSAFE' });
      expect(await readFile(path)).toEqual(before);
      expect(await readdir(testDirectory)).toEqual(['portable-key.cvk']);
    },
  );

  it.runIf(process.platform === 'win32')(
    'refuses to create content in a directory with inherited world write access',
    async () => {
      const sharedDirectory = target('shared');
      await mkdir(sharedDirectory);
      await grantWindowsEveryoneInheritedModify(sharedDirectory);

      await expect(
        writePortableKeyFile(join(sharedDirectory, 'key.cvk'), key(15), UNBOUND, {
          protection: UNPROTECTED,
        }),
      ).rejects.toMatchObject({ code: 'KEY_FILE_UNSAFE' });
      expect(await readdir(sharedDirectory)).toEqual([]);
    },
  );
});
