import { EventEmitter } from 'node:events';
import { PassThrough, Writable } from 'node:stream';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

const spawnMock = vi.hoisted(() => vi.fn());

vi.mock('node:child_process', () => ({
  spawn: spawnMock,
}));

import { PortableKeyFileError } from '../src/errors.js';

const POWERSHELL = 'C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe';

interface FakeHelper {
  readonly emitted: string[];
  readonly stdout: PassThrough;
  readonly child: EventEmitter & {
    readonly stdin: Writable;
    readonly stdout: PassThrough;
    kill: () => void;
    ref: () => void;
    unref: () => void;
  };
}

/** Stands in for the long-lived interpreter and records every request line. */
function installFakeHelper(): FakeHelper {
  const emitted: string[] = [];
  const stdout = new PassThrough();
  const child = new EventEmitter() as FakeHelper['child'];
  const stdin = new Writable({
    write(chunk, _encoding, callback) {
      emitted.push(String(chunk));
      callback();
    },
  });
  Object.assign(child, {
    stdin,
    stdout,
    kill: vi.fn(),
    ref: vi.fn(),
    unref: vi.fn(),
  });
  spawnMock.mockReturnValue(child);
  return { emitted, stdout, child };
}

/**
 * Stands in for an interpreter that can never answer: every spawn dies
 * immediately. Retrying such a helper has to stay fast, so each attempt costs a
 * tick rather than the full reply deadline.
 */
function installDyingHelper(): void {
  spawnMock.mockImplementation(() => {
    const child = new EventEmitter() as FakeHelper['child'];
    const stdout = new PassThrough();
    Object.assign(child, {
      stdin: new Writable({
        write(_chunk, _encoding, callback) {
          callback();
        },
      }),
      stdout,
      kill: vi.fn(),
      ref: vi.fn(),
      unref: vi.fn(),
    });
    setImmediate(() => {
      child.emit('exit', 1);
    });
    return child;
  });
}

/** Loads a fresh copy of the boundary so singleton state never leaks between tests. */
async function loadBoundary(): Promise<typeof import('../src/windows-acl.js')> {
  vi.resetModules();
  return import('../src/windows-acl.js');
}

/** Parses the single request the boundary should have written to the helper. */
function readRequest(emitted: readonly string[]): Record<string, unknown> {
  const lines = emitted
    .join('')
    .split('\n')
    .filter((line) => line.length > 0);
  expect(lines).toHaveLength(1);
  return JSON.parse(lines[0] as string) as Record<string, unknown>;
}

/** Waits for the boundary to write exactly one request before answering it. */
async function awaitRequest(emitted: readonly string[]): Promise<void> {
  for (let attempt = 0; attempt < 200; attempt += 1) {
    if (emitted.length > 0) return;
    await new Promise((resolve) => setImmediate(resolve));
  }
  throw new Error('the boundary never sent a request');
}

/** Extracts the read-only parent-directory rule from the shared program. */
function readOnlyVerifierBody(program: string): string {
  const start = program.indexOf('function Verify-ParentDirectory');
  expect(start).toBeGreaterThanOrEqual(0);
  const end = program.indexOf('\n}\n', start);
  expect(end).toBeGreaterThan(start);
  return program.slice(start, end);
}

let helper: FakeHelper;

beforeEach(() => {
  helper = installFakeHelper();
  spawnMock.mockClear();
});

afterEach(() => {
  vi.clearAllMocks();
});

describe('read-only Windows directory ACL verification', () => {
  it('sends the directory over stdin to a fixed interpreter without mutating it', async () => {
    const { verifyWindowsDirectoryAcl } = await loadBoundary();

    const pending = verifyWindowsDirectoryAcl('C:\\workspace');
    await awaitRequest(helper.emitted);
    helper.stdout.write('{"v":1,"n":1,"ok":true}\n');

    await expect(pending).resolves.toBeUndefined();

    const [executable, arguments_] = spawnMock.mock.calls[0] as [
      string,
      readonly string[],
    ];
    // The interpreter is a fixed absolute path, never resolved from PATH or
    // from any caller-controlled environment value.
    expect(executable).toBe(POWERSHELL);
    const encodedIndex = arguments_.indexOf('-EncodedCommand');
    expect(encodedIndex).toBeGreaterThanOrEqual(0);
    const program = Buffer.from(
      arguments_[encodedIndex + 1] as string,
      'base64',
    ).toString('utf16le');
    expect(program).toContain("$administratorsSid = 'S-1-5-32-544'");
    expect(program).toContain('$hasWriteRights');
    // Reading a parent directory must never rewrite its ACL. The helper is one
    // shared program, so the guarantee is that the mutating calls exist only
    // inside the explicit `set` operation.
    const setBranch = program.indexOf("if ($op -eq 'set')");
    expect(setBranch).toBeGreaterThanOrEqual(0);
    for (const mutation of [
      'SetAccessControl',
      'SetOwner',
      'SetAccessRuleProtection',
    ]) {
      expect(program.indexOf(mutation)).toBeGreaterThan(setBranch);
      expect(readOnlyVerifierBody(program)).not.toContain(mutation);
    }
    // The no-mutation branch is reached for a parent-directory request, and it
    // only ever asks the platform to read the descriptor.
    expect(readOnlyVerifierBody(program)).toContain('GetAccessRules');
    expect(readOnlyVerifierBody(program)).not.toContain('AddAccessRule');

    // The target is framed on stdin as base64, so it can never be read as
    // program text or smuggled through the argument vector.
    const request = readRequest(helper.emitted);
    expect(request['op']).toBe('verify-parent-dir');
    expect(Buffer.from(String(request['p']), 'base64').toString('utf8')).toBe(
      'C:\\workspace',
    );
    expect(JSON.stringify(request)).not.toContain('C:\\\\workspace');
  });

  it('fails closed when the helper reports an unsafe ACL', async () => {
    const { verifyWindowsDirectoryAcl } = await loadBoundary();

    const pending = verifyWindowsDirectoryAcl('C:\\workspace');
    await awaitRequest(helper.emitted);
    helper.stdout.write('{"v":1,"n":1,"ok":false,"r":"policy"}\n');

    await expect(pending).rejects.toEqual(new PortableKeyFileError('KEY_FILE_UNSAFE'));
  });

  it('fails closed and does not retry a refused verification', async () => {
    const { verifyWindowsDirectoryAcl } = await loadBoundary();

    const pending = verifyWindowsDirectoryAcl('C:\\workspace');
    await awaitRequest(helper.emitted);
    helper.stdout.write('{"v":1,"n":1,"ok":false,"r":"policy"}\n');

    await expect(pending).rejects.toMatchObject({ code: 'KEY_FILE_UNSAFE' });
    // A policy verdict is a statement about the filesystem, so re-reading it
    // cannot help. One interpreter start, one request.
    expect(spawnMock).toHaveBeenCalledTimes(1);
    expect(helper.emitted).toHaveLength(1);
  });

  it('fails closed when the helper answers with something that is not a verdict', async () => {
    const { verifyWindowsDirectoryAcl } = await loadBoundary();

    const pending = verifyWindowsDirectoryAcl('C:\\workspace');
    await awaitRequest(helper.emitted);
    helper.stdout.write('{"ok":true}\n');

    // A reply with no envelope and no matching nonce can never be accepted.
    expect(
      await Promise.race([
        pending,
        new Promise((resolve) => setTimeout(() => resolve('still-pending'), 50)),
      ]),
    ).toBe('still-pending');

    // Once the helper dies, the retry budget is spent against helpers that
    // cannot answer either, and the boundary still fails closed.
    installDyingHelper();
    helper.child.emit('exit', 1);
    await expect(pending).rejects.toMatchObject({ code: 'KEY_FILE_UNSAFE' });
  });

  it('never accepts a verdict addressed to another request', async () => {
    const { verifyWindowsDirectoryAcl } = await loadBoundary();

    const pending = verifyWindowsDirectoryAcl('C:\\workspace');
    await awaitRequest(helper.emitted);
    helper.stdout.write('{"v":1,"n":99,"ok":true}\n');

    expect(
      await Promise.race([
        pending,
        new Promise((resolve) => setTimeout(() => resolve('still-pending'), 50)),
      ]),
    ).toBe('still-pending');

    installDyingHelper();
    helper.child.emit('exit', 1);
    await expect(pending).rejects.toMatchObject({ code: 'KEY_FILE_UNSAFE' });
  });

  it('retries a helper that dies, then fails closed', async () => {
    installDyingHelper();
    const { verifyWindowsDirectoryAcl } = await loadBoundary();

    await expect(verifyWindowsDirectoryAcl('C:\\workspace')).rejects.toMatchObject({
      code: 'KEY_FILE_UNSAFE',
    });
    // An interpreter that keeps dying is retried within the retry budget
    // rather than accepted or reported as an unsafe ACL.
    expect(spawnMock.mock.calls.length).toBeGreaterThan(1);
  });

  it('refuses to send a target that could not be a Kavrix-owned path', async () => {
    const { verifyWindowsDirectoryAcl } = await loadBoundary();

    await expect(verifyWindowsDirectoryAcl('relative\\path')).rejects.toEqual(
      new PortableKeyFileError('KEY_FILE_UNSAFE'),
    );
    await expect(
      verifyWindowsDirectoryAcl('C:\\workspace\\a\nb'),
    ).rejects.toMatchObject({ code: 'KEY_FILE_UNSAFE' });
    expect(spawnMock).not.toHaveBeenCalled();
  });
});

describe('Kavrix-owned object hardening', () => {
  it('verifies first and only rewrites the ACL when verification shows it is needed', async () => {
    const { setWindowsUserOnlyAcl } = await loadBoundary();

    const pending = setWindowsUserOnlyAcl('C:\\workspace\\key.bin');
    await awaitRequest(helper.emitted);
    expect(readRequest(helper.emitted)['op']).toBe('verify-user-only');
    helper.stdout.write('{"v":1,"n":1,"ok":false,"r":"policy"}\n');
    await new Promise((resolve) => setTimeout(resolve, 20));

    expect(helper.emitted).toHaveLength(2);
    expect(readRequest(helper.emitted.slice(1))['op']).toBe('set');
    helper.stdout.write('{"v":1,"n":2,"ok":true}\n');
    await new Promise((resolve) => setTimeout(resolve, 20));

    expect(helper.emitted).toHaveLength(3);
    helper.stdout.write('{"v":1,"n":3,"ok":true}\n');
    await expect(pending).resolves.toBeUndefined();
  });

  it('leaves an already-protected object untouched', async () => {
    const { setWindowsUserOnlyAcl } = await loadBoundary();

    const pending = setWindowsUserOnlyAcl('C:\\workspace\\key.bin');
    await awaitRequest(helper.emitted);
    helper.stdout.write('{"v":1,"n":1,"ok":true}\n');

    await expect(pending).resolves.toBeUndefined();
    expect(helper.emitted).toHaveLength(1);
  });

  it('fails closed when hardening cannot be verified afterwards', async () => {
    const { setWindowsUserOnlyAcl } = await loadBoundary();

    const pending = setWindowsUserOnlyAcl('C:\\workspace\\key.bin');
    await awaitRequest(helper.emitted);
    helper.stdout.write('{"v":1,"n":1,"ok":false,"r":"policy"}\n');
    await new Promise((resolve) => setTimeout(resolve, 20));
    helper.stdout.write('{"v":1,"n":2,"ok":true}\n');
    await new Promise((resolve) => setTimeout(resolve, 20));
    helper.stdout.write('{"v":1,"n":3,"ok":false,"r":"policy"}\n');

    await expect(pending).rejects.toMatchObject({ code: 'KEY_FILE_UNSAFE' });
  });
});

describe('helper lifecycle', () => {
  it('starts one interpreter and reuses it across requests', async () => {
    const { verifyWindowsUserOnlyAcl, verifyWindowsDirectoryAcl } =
      await loadBoundary();

    const first = verifyWindowsUserOnlyAcl('C:\\workspace\\a.bin');
    await awaitRequest(helper.emitted);
    helper.stdout.write('{"v":1,"n":1,"ok":true}\n');
    await first;

    const second = verifyWindowsDirectoryAcl('C:\\workspace');
    await new Promise((resolve) => setTimeout(resolve, 20));
    helper.stdout.write('{"v":1,"n":2,"ok":true}\n');
    await second;

    expect(spawnMock).toHaveBeenCalledTimes(1);
    expect(helper.emitted).toHaveLength(2);
  });

  it('stops keeping the process alive while no request is outstanding', async () => {
    const { verifyWindowsUserOnlyAcl } = await loadBoundary();

    const pending = verifyWindowsUserOnlyAcl('C:\\workspace\\a.bin');
    await awaitRequest(helper.emitted);
    // The interpreter is unreferenced as soon as it is spawned, so an idle
    // helper can never be the reason a Kavrix process stays alive.
    expect(helper.child.unref).toHaveBeenCalled();

    // While a request is outstanding the handles are referenced again, so the
    // process waits for the verdict instead of exiting first.
    expect(helper.child.ref).toHaveBeenCalled();
    helper.stdout.write('{"v":1,"n":1,"ok":true}\n');
    await pending;
    expect(helper.child.unref).toHaveBeenCalledTimes(2);
  });
});
