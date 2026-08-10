import { describe, expect, it } from 'vitest';

import { detectClipboardBackend } from '../src/backends.js';
import { testRuntime } from './helpers.js';

const windowsPowerShell =
  'C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe';

describe('clipboard backend detection', () => {
  it('prefers a complete Wayland tool pair and passes only display-safe environment', async () => {
    const fixture = testRuntime(
      'linux',
      ['/usr/bin/wl-copy', '/usr/bin/wl-paste', '/usr/bin/xclip'],
      {
        WAYLAND_DISPLAY: 'wayland-0',
        XDG_RUNTIME_DIR: '/run/user/1000',
        DISPLAY: ':0',
        PATH: '/unsafe:/usr/bin',
        HOME: 'home-secret-canary',
      },
    );
    const backend = await detectClipboardBackend(fixture.runtime);

    expect(backend.name).toBe('wayland-wl-clipboard');
    await backend.write(new TextEncoder().encode('value'));
    expect(fixture.commands.calls[0]?.environment).toEqual({
      DISPLAY: ':0',
      WAYLAND_DISPLAY: 'wayland-0',
      XDG_RUNTIME_DIR: '/run/user/1000',
    });
    expect(JSON.stringify(fixture.commands.calls[0]?.environment)).not.toContain(
      'home-secret-canary',
    );
    expect(fixture.executables.requests[0]).toEqual({
      name: 'wl-copy',
      candidates: ['/usr/local/bin/wl-copy', '/usr/bin/wl-copy', '/bin/wl-copy'],
    });
  });

  it('falls back from unavailable Wayland to xclip and then xsel', async () => {
    const xclipFixture = testRuntime('linux', ['/usr/bin/xclip'], {
      WAYLAND_DISPLAY: 'wayland-0',
      XDG_RUNTIME_DIR: '/run/user/1000',
      DISPLAY: ':1',
    });
    const xselFixture = testRuntime('linux', ['/usr/local/bin/xsel'], {
      DISPLAY: ':1',
      PATH: '/usr/local/bin',
    });

    await expect(detectClipboardBackend(xclipFixture.runtime)).resolves.toMatchObject({
      name: 'x11-xclip',
    });
    await expect(detectClipboardBackend(xselFixture.runtime)).resolves.toMatchObject({
      name: 'x11-xsel',
    });
  });

  it('fails closed on headless, unsupported, and incomplete platforms', async () => {
    const headless = testRuntime('linux', ['/usr/bin/xclip']);
    const incompleteWayland = testRuntime('linux', ['/usr/bin/wl-copy'], {
      WAYLAND_DISPLAY: 'wayland-0',
      XDG_RUNTIME_DIR: '/run/user/1000',
    });
    const unsupported = testRuntime('freebsd', []);

    for (const fixture of [headless, incompleteWayland, unsupported]) {
      await expect(detectClipboardBackend(fixture.runtime)).rejects.toMatchObject({
        code: 'CLIPBOARD_UNAVAILABLE',
      });
    }
  });

  it('fails closed when required commands or display environment are unsafe', async () => {
    const macMissingPaste = testRuntime('darwin', ['/usr/bin/pbcopy']);
    const windowsMissing = testRuntime('win32', [], {
      SystemRoot: 'C:\\Windows',
    });
    const unsafeDisplay = testRuntime('linux', ['/usr/bin/xclip'], {
      DISPLAY: ':0\0unsafe',
    });

    await expect(detectClipboardBackend(macMissingPaste.runtime)).rejects.toMatchObject(
      { code: 'CLIPBOARD_UNAVAILABLE' },
    );
    await expect(detectClipboardBackend(windowsMissing.runtime)).rejects.toMatchObject({
      code: 'CLIPBOARD_UNAVAILABLE',
    });
    await expect(detectClipboardBackend(unsafeDisplay.runtime)).rejects.toMatchObject({
      code: 'CLIPBOARD_VALIDATION_FAILED',
    });
  });

  it('does not trust inherited Windows command roots or forward their values', async () => {
    const attackerPowerShell =
      'D:\\attacker\\System32\\WindowsPowerShell\\v1.0\\powershell.exe';
    const fixture = testRuntime('win32', [attackerPowerShell, windowsPowerShell], {
      SystemRoot: 'D:\\attacker',
      WINDIR: 'D:\\attacker',
      TEMP: 'environment-secret-canary',
    });

    const backend = await detectClipboardBackend(fixture.runtime);
    await backend.write(new TextEncoder().encode('value'));

    expect(fixture.executables.requests).toEqual([
      { name: 'powershell.exe', candidates: [windowsPowerShell] },
    ]);
    expect(fixture.commands.calls[0]?.executable).toBe(windowsPowerShell);
    expect(fixture.commands.calls[0]?.environment).toEqual({
      SystemRoot: 'C:\\Windows',
    });
    expect(JSON.stringify(fixture.commands.calls[0])).not.toContain(
      'environment-secret-canary',
    );
  });
});
