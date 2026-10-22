/* global process, setTimeout, clearTimeout, setInterval, clearInterval */
import { mkdir } from 'node:fs/promises';
import { join } from 'node:path';
import { spawn, spawnSync } from 'node:child_process';
import { setWindowsUserOnlyAcl } from '../../../packages/key-files/dist/windows-acl.js';

/** Exercises the installed split bundle through streams, not a physical TTY. */
export async function smokeTuiChildCommands(bin, installRoot) {
  const started = Date.now();
  const limit = 120_000;
  const home = join(installRoot, 'tui-child-home');
  const config = join(home, 'config');
  await mkdir(home, { mode: 0o700 });
  if (process.platform === 'win32') await setWindowsUserOnlyAcl(home);
  const passphrase = 'PackedTuiPublicTestPassphrase!';
  const env = {
    ...process.env,
    HOME: home,
    USERPROFILE: home,
    XDG_CONFIG_HOME: home,
    TERM: 'xterm-256color',
    INK_SCREEN_READER: '',
    NO_COLOR: '1',
    FORCE_COLOR: '1',
    KAVRIX_TUI_MOUSE: '0',
  };
  const invalidOutput = (text) =>
    text.includes(passphrase) ||
    /MODULE_NOT_FOUND|ERR_MODULE_NOT_FOUND|node:internal\/modules\/cjs\/loader|NO_COLOR.*FORCE_COLOR/u.test(
      text,
    );
  const initialized = spawnSync(
    process.execPath,
    [
      bin,
      'init',
      '--json',
      '--profile',
      'packed-tui',
      '--data-file',
      join(home, 'database.kavrix'),
      '--key-file',
      join(home, 'owner.key'),
      '--config-dir',
      config,
      '--passphrase-stdin',
    ],
    {
      cwd: installRoot,
      shell: false,
      windowsHide: true,
      env,
      input: `${passphrase}\n${passphrase}\n`,
      encoding: 'utf8',
      timeout: Math.max(1, limit - (Date.now() - started)),
    },
  );
  if (
    initialized.error ||
    initialized.status !== 0 ||
    invalidOutput(`${initialized.stdout ?? ''}${initialized.stderr ?? ''}`)
  )
    throw new Error(
      'Installed TUI child smoke initialization failed or exposed unsafe output.',
    );

  const child = spawn(
    process.execPath,
    [
      '--require',
      join(installRoot, 'onboarding-tty.cjs'),
      bin,
      'tui',
      '--no-splash',
      '--ascii',
      '--no-color',
      '--no-mouse',
      '--profile-config-dir',
      config,
    ],
    {
      cwd: installRoot,
      shell: false,
      windowsHide: true,
      env,
      stdio: ['pipe', 'pipe', 'pipe'],
    },
  );
  let output = '';
  let allOutput = '';
  let ended = false;
  let unsafe = false;
  let inputError = false;
  let expired = false;
  let resolveExit;
  const exited = new Promise((resolve) => {
    resolveExit = resolve;
  });
  child.once('error', () => {
    ended = true;
    resolveExit(null);
  });
  child.once('close', (code) => {
    ended = true;
    resolveExit(code);
  });
  child.stdin.on('error', () => {
    inputError = true;
  });
  for (const stream of [child.stdout, child.stderr]) {
    stream.on('data', (chunk) => {
      const text = chunk.toString('utf8');
      output = (output + text).slice(-512 * 1024);
      allOutput = (allOutput + text).slice(-512 * 1024);
      unsafe ||= invalidOutput(allOutput);
    });
  }
  const deadline = setTimeout(
    () => {
      expired = true;
      child.kill('SIGKILL');
    },
    Math.max(1, limit - (Date.now() - started)),
  );
  const waitFor = (predicate, label) =>
    new Promise((resolve, reject) => {
      const timer = setInterval(() => {
        if (unsafe || inputError || expired || ended) {
          clearInterval(timer);
          reject(
            new Error(`Installed TUI child smoke failed while awaiting ${label}.`),
          );
        } else if (predicate(output)) {
          clearInterval(timer);
          resolve();
        }
      }, 25);
    });
  const send = (text) => {
    output = '';
    child.stdin.write(text);
  };
  try {
    await waitFor((text) => text.includes('Loaded profile registry.'), 'Home');
    send('u');
    await waitFor((text) => text.includes('Passphrase:'), 'masked unlock');
    send(passphrase);
    await waitFor(
      (text) => text.includes('*'.repeat(passphrase.length)),
      'masked input',
    );
    send('\r');
    await waitFor((text) => text.includes('Unlocked ('), 'unlock success');
    send('5');
    await waitFor((text) => /DOCTOR \/ HEAL/iu.test(text), 'Doctor screen');
    send('d');
    await waitFor(
      (text) =>
        /Doctor: [1-9][0-9]* check\(s\)\./u.test(text) &&
        text.includes('database-container'),
      'authenticated Doctor result',
    );
    send('q');
    const code = await exited;
    if (code !== 0 || unsafe || expired || invalidOutput(allOutput))
      throw new Error(
        'Installed TUI child smoke did not exit cleanly with safe Doctor output.',
      );
  } finally {
    if (!ended) child.kill('SIGKILL');
    await exited;
    clearTimeout(deadline);
  }
}
