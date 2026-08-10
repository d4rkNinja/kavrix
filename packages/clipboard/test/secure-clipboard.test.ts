import { describe, expect, it } from 'vitest';

import {
  MAX_CLEAR_TIMEOUT_MS,
  MIN_CLEAR_TIMEOUT_MS,
  SecureClipboard,
} from '../src/index.js';
import { bytes, testRuntime } from './helpers.js';

const windowsPowerShell =
  'C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe';

describe('SecureClipboard', () => {
  it('sends a Windows secret only through child stdin with a minimized environment', async () => {
    const fixture = testRuntime('win32', [windowsPowerShell], {
      SystemRoot: 'C:\\Windows',
      WINDIR: 'C:\\Windows',
      ComSpec: 'C:\\Windows\\System32\\cmd.exe',
      PATH: 'secret-path-canary',
      USERPROFILE: 'secret-profile-canary',
    });
    const clipboard = new SecureClipboard(fixture.runtime);
    const secret = bytes('clipboard-secret-canary');

    await expect(
      clipboard.copy(secret, { clearAfterMs: MIN_CLEAR_TIMEOUT_MS }),
    ).resolves.toMatchObject({ generation: 1 });
    expect(fixture.commands.clipboard).toEqual(secret);
    const serializedMetadata = JSON.stringify(
      fixture.commands.calls.map(({ executable, args, environment }) => ({
        executable,
        args,
        environment,
      })),
    );
    expect(serializedMetadata).not.toContain('clipboard-secret-canary');
    expect(serializedMetadata).not.toContain('secret-path-canary');
    expect(serializedMetadata).not.toContain('secret-profile-canary');
    expect(fixture.commands.calls[0]?.stdin).toEqual(secret);
    expect(fixture.commands.calls[0]?.args).toContain('-NonInteractive');
    expect(fixture.commands.calls[0]?.args).toContain('-Sta');
    expect(fixture.commands.rawWriteInput?.every((value) => value === 0)).toBe(true);
    expect(fixture.commands.rawReadOutput?.every((value) => value === 0)).toBe(true);
    secret.fill(0);
  });

  it('clears an unchanged generation when its timer expires', async () => {
    const fixture = testRuntime('darwin', ['/usr/bin/pbcopy', '/usr/bin/pbpaste']);
    const clipboard = new SecureClipboard(fixture.runtime);
    await clipboard.copy(bytes('short-lived'), { clearAfterMs: 1_000 });

    await fixture.scheduler.run(0);

    expect(fixture.commands.clipboard).toHaveLength(0);
    expect(clipboard.takeBackgroundError()).toBeNull();
  });

  it('never clears newer external clipboard contents', async () => {
    const fixture = testRuntime('darwin', ['/usr/bin/pbcopy', '/usr/bin/pbpaste']);
    const clipboard = new SecureClipboard(fixture.runtime);
    await clipboard.copy(bytes('kavrix-owned'), { clearAfterMs: 1_000 });
    fixture.commands.clipboard = bytes('new-user-content');

    await fixture.scheduler.run(0);

    expect(fixture.commands.clipboard).toEqual(bytes('new-user-content'));
    fixture.commands.clipboard = bytes('kavrix-owned');
    await expect(clipboard.lock()).resolves.toBe(false);
    expect(fixture.commands.clipboard).toEqual(bytes('kavrix-owned'));
  });

  it('uses generation checks so an older timer cannot clear a newer copy', async () => {
    const fixture = testRuntime('darwin', ['/usr/bin/pbcopy', '/usr/bin/pbpaste']);
    const clipboard = new SecureClipboard(fixture.runtime);
    await clipboard.copy(bytes('first'), { clearAfterMs: 1_000 });
    await clipboard.copy(bytes('second'), { clearAfterMs: 2_000 });

    await fixture.scheduler.run(0, true);
    expect(fixture.commands.clipboard).toEqual(bytes('second'));
    await fixture.scheduler.run(1);
    expect(fixture.commands.clipboard).toHaveLength(0);
  });

  it('guard-clears a completed write when cancellation interrupts verification', async () => {
    const fixture = testRuntime('darwin', ['/usr/bin/pbcopy', '/usr/bin/pbpaste']);
    const clipboard = new SecureClipboard(fixture.runtime);
    const controller = new AbortController();
    fixture.commands.afterWrite = () => {
      controller.abort();
    };

    await expect(
      clipboard.copy(bytes('cancelled-secret'), {
        clearAfterMs: 1_000,
        signal: controller.signal,
      }),
    ).rejects.toMatchObject({ code: 'CLIPBOARD_ABORTED' });
    expect(fixture.commands.clipboard).toHaveLength(0);
  });

  it('lock immediately clears matching content and preserves replacements', async () => {
    const fixture = testRuntime('darwin', ['/usr/bin/pbcopy', '/usr/bin/pbpaste']);
    const clipboard = new SecureClipboard(fixture.runtime);
    await clipboard.copy(bytes('lock-me'), { clearAfterMs: 5_000 });
    await expect(clipboard.lock()).resolves.toBe(true);
    expect(fixture.commands.clipboard).toHaveLength(0);

    await clipboard.copy(bytes('leave-replacement'), { clearAfterMs: 5_000 });
    fixture.commands.clipboard = bytes('external');
    await expect(clipboard.dispose()).resolves.toBe(false);
    expect(fixture.commands.clipboard).toEqual(bytes('external'));
  });

  it('retains ownership after an aborted lock so a later lock can retry', async () => {
    const fixture = testRuntime('darwin', ['/usr/bin/pbcopy', '/usr/bin/pbpaste']);
    const clipboard = new SecureClipboard(fixture.runtime);
    await clipboard.copy(bytes('retry-lock'), { clearAfterMs: 5_000 });
    const controller = new AbortController();
    controller.abort();

    await expect(clipboard.lock(controller.signal)).rejects.toMatchObject({
      code: 'CLIPBOARD_ABORTED',
    });
    expect(fixture.commands.clipboard).toEqual(bytes('retry-lock'));
    await expect(clipboard.lock()).resolves.toBe(true);
    expect(fixture.commands.clipboard).toHaveLength(0);
  });

  it('validates UTF-8 bytes, NUL exclusion, size, and clear-delay bounds', () => {
    const fixture = testRuntime('darwin', ['/usr/bin/pbcopy', '/usr/bin/pbpaste']);
    const clipboard = new SecureClipboard(fixture.runtime);
    for (const [secret, timeout] of [
      [new Uint8Array(), MIN_CLEAR_TIMEOUT_MS],
      [Uint8Array.of(0), MIN_CLEAR_TIMEOUT_MS],
      [Uint8Array.of(0xff), MIN_CLEAR_TIMEOUT_MS],
      [bytes('value'), MIN_CLEAR_TIMEOUT_MS - 1],
      [bytes('value'), MAX_CLEAR_TIMEOUT_MS + 1],
    ] as const) {
      expect(() => clipboard.copy(secret, { clearAfterMs: timeout })).toThrow(
        expect.objectContaining({ code: 'CLIPBOARD_VALIDATION_FAILED' }),
      );
    }
    expect(() => clipboard.copy(bytes('value'), undefined as never)).toThrow(
      expect.objectContaining({ code: 'CLIPBOARD_VALIDATION_FAILED' }),
    );
    expect(() =>
      clipboard.copy(bytes('value'), {
        clearAfterMs: MIN_CLEAR_TIMEOUT_MS,
        signal: {} as AbortSignal,
      }),
    ).toThrow(expect.objectContaining({ code: 'CLIPBOARD_VALIDATION_FAILED' }));
    expect(fixture.commands.calls).toHaveLength(0);
  });

  it('preserves external replacement if copy verification observes a race', async () => {
    const fixture = testRuntime('darwin', ['/usr/bin/pbcopy', '/usr/bin/pbpaste']);
    const clipboard = new SecureClipboard(fixture.runtime);
    fixture.commands.afterWrite = () => {
      fixture.commands.clipboard = bytes('external-during-copy');
    };

    await expect(
      clipboard.copy(bytes('attempted-secret'), { clearAfterMs: 1_000 }),
    ).rejects.toMatchObject({ code: 'CLIPBOARD_CHANGED' });
    expect(fixture.commands.clipboard).toEqual(bytes('external-during-copy'));
    await expect(clipboard.lock()).resolves.toBe(false);
  });

  it('reports background expiry failures without unhandled rejection', async () => {
    const fixture = testRuntime('darwin', ['/usr/bin/pbcopy', '/usr/bin/pbpaste']);
    const clipboard = new SecureClipboard(fixture.runtime);
    await clipboard.copy(bytes('background-failure'), { clearAfterMs: 1_000 });
    fixture.commands.failNext = true;

    await fixture.scheduler.run(0);

    expect(clipboard.takeBackgroundError()).toMatchObject({
      code: 'CLIPBOARD_OPERATION_FAILED',
    });
    expect(clipboard.takeBackgroundError()).toBeNull();
    await expect(clipboard.lock()).resolves.toBe(true);
  });

  it('clears the previous owned value when a replacement write fails', async () => {
    const fixture = testRuntime('darwin', ['/usr/bin/pbcopy', '/usr/bin/pbpaste']);
    const clipboard = new SecureClipboard(fixture.runtime);
    await clipboard.copy(bytes('previous-secret'), { clearAfterMs: 1_000 });
    fixture.commands.failNext = true;

    await expect(
      clipboard.copy(bytes('replacement-secret'), { clearAfterMs: 1_000 }),
    ).rejects.toMatchObject({ code: 'CLIPBOARD_OPERATION_FAILED' });
    expect(fixture.commands.clipboard).toHaveLength(0);
  });

  it('guard-clears a secret when the writer reports failure after changing clipboard', async () => {
    const fixture = testRuntime('darwin', ['/usr/bin/pbcopy', '/usr/bin/pbpaste']);
    const clipboard = new SecureClipboard(fixture.runtime);
    fixture.commands.failAfterWrite = true;

    await expect(
      clipboard.copy(bytes('uncertain-write'), { clearAfterMs: 1_000 }),
    ).rejects.toMatchObject({ code: 'CLIPBOARD_OPERATION_FAILED' });
    expect(fixture.commands.clipboard).toHaveLength(0);
  });

  it('retains guarded-clear ownership when verification and cleanup both fail', async () => {
    const fixture = testRuntime('darwin', ['/usr/bin/pbcopy', '/usr/bin/pbpaste']);
    const clipboard = new SecureClipboard(fixture.runtime);
    fixture.commands.afterWrite = () => {
      fixture.commands.afterWrite = undefined;
      fixture.commands.failuresRemaining = 2;
    };

    await expect(
      clipboard.copy(bytes('retry-cleanup'), { clearAfterMs: 1_000 }),
    ).rejects.toMatchObject({ code: 'CLIPBOARD_OPERATION_FAILED' });
    expect(fixture.commands.clipboard).toEqual(bytes('retry-cleanup'));
    await expect(clipboard.lock()).resolves.toBe(true);
    expect(fixture.commands.clipboard).toHaveLength(0);
  });
});
