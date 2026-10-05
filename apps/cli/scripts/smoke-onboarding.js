/* global process, setTimeout, clearTimeout, setInterval, clearInterval */
import { mkdir, writeFile, readdir } from 'node:fs/promises';
import { join } from 'node:path';
import { spawn } from 'node:child_process';
import { setWindowsUserOnlyAcl } from '../../../packages/key-files/dist/windows-acl.js';

/** Stream harness for the actual installed CLI; this is not a physical TTY test. */
export async function smokeOnboarding(bin, installRoot) {
  const home = join(installRoot, 'onboarding-home');
  await mkdir(home, { mode: 0o700 });
  if (process.platform === 'win32') await setWindowsUserOnlyAcl(home);
  const preload = join(installRoot, 'onboarding-tty.cjs');
  await writeFile(
    preload,
    `
for (const stream of [process.stdin, process.stdout, process.stderr]) {
  Object.defineProperty(stream, 'isTTY', { value: true });
}
process.stdout.columns = 100; process.stdout.rows = 30;
process.stdin.setRawMode = () => process.stdin;
`,
  );
  const child = spawn(
    process.execPath,
    [
      '--require',
      preload,
      bin,
      'init',
      '--no-splash',
      '--no-mouse',
      '--ascii',
      '--no-color',
    ],
    {
      cwd: installRoot,
      shell: false,
      windowsHide: true,
      env: {
        ...process.env,
        HOME: home,
        USERPROFILE: home,
        XDG_CONFIG_HOME: home,
        TERM: 'xterm-256color',
        INK_SCREEN_READER: '',
        NO_COLOR: '1',
        KAVRIX_TUI_MOUSE: '0',
      },
      stdio: ['pipe', 'pipe', 'pipe'],
    },
  );
  let output = '';
  let ended = false;
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
  for (const stream of [child.stdout, child.stderr])
    stream.on('data', (chunk) => {
      output = (output + chunk.toString('utf8')).slice(-512 * 1024);
    });
  const deadline = setTimeout(() => child.kill(), 120000);
  const waitFor = (marker) =>
    new Promise((resolve, reject) => {
      const started = Date.now();
      const timer = setInterval(() => {
        if (output.includes(marker)) {
          clearInterval(timer);
          resolve();
        } else if (ended || Date.now() - started > 60000) {
          clearInterval(timer);
          reject(new Error(`Installed setup did not reach ${marker}.`));
        }
      }, 25);
    });
  const send = (input) => {
    output = '';
    child.stdin.write(input);
  };
  try {
    await waitFor('Welcome');
    send('\r');
    await waitFor('Local encrypted file');
    send('2');
    await waitFor('MongoDB selected.');
    send('\r');
    await waitFor('Profile id:');
    send('\r');
    await waitFor('Database name:');
    send('\r');
    await waitFor('Key file:');
    const beforeBrowse = (await readdir(home)).sort();
    send('\u0002');
    await waitFor('CHOOSE FOLDER');
    if (JSON.stringify((await readdir(home)).sort()) !== JSON.stringify(beforeBrowse))
      throw new Error('Installed folder browsing changed the filesystem.');
    send('\u001b');
    await waitFor('Key file:');
    send('\r');
    await waitFor('MongoDB URL:');
    send('mongodb://127.0.0.1:1/test');
    await waitFor('Paste works');
    const started = Date.now();
    send('\u0014');
    await waitFor('MongoDB could not be reached.');
    if (Date.now() - started < 4000)
      throw new Error(
        'Installed probe did not execute the driver server-selection timeout.',
      );
    if (output.includes('mongodb://127.0.0.1:1/test'))
      throw new Error('Installed setup exposed masked connection input.');
    send('\u0003');
    const code = await exited;
    if (code !== 1 || !output.includes('Setup cancelled. No vault was created.'))
      throw new Error(
        'Installed setup did not preserve its cancellation exit code and notice.',
      );
    if ((await readdir(join(home, '.kavrix'))).length !== 0)
      throw new Error('Connection checking created unexpected vault artifacts.');
  } finally {
    clearTimeout(deadline);
    if (!ended) child.kill();
    await exited;
  }
}
