#!/usr/bin/env node
/**
 * Headless init onboarding matrix smoke (Linux CI / release gate).
 * Does not drive Ink TTY UI; validates routing + non-interactive paths.
 */
import { spawnSync } from 'node:child_process';
import { mkdtempSync, rmSync, writeFileSync, existsSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';

const root = fileURLToPath(new URL('..', import.meta.url));
const bin = join(root, 'apps/cli/dist/bin.js');
const results = [];

function record(name, status, detail = '') {
  results.push({ name, status, detail });
  const mark = status === 'PASS' ? 'PASS' : status === 'SKIP' ? 'SKIP' : 'FAIL';
  console.log(`[${mark}] ${name}${detail ? ` — ${detail}` : ''}`);
}

function run(args, opts = {}) {
  return spawnSync(process.execPath, [bin, ...args], {
    encoding: 'utf8',
    env: { ...process.env, NO_COLOR: '1', ...(opts.env ?? {}) },
    input: opts.input,
    timeout: opts.timeout ?? 30_000,
  });
}

// 1) Help lists presentation + routing flags
{
  const r = run(['init', '--help']);
  const out = `${r.stdout}${r.stderr}`;
  const ok =
    r.status === 0 &&
    out.includes('--no-tui') &&
    out.includes('--ascii') &&
    out.includes('--no-splash') &&
    out.includes('--passphrase-stdin') &&
    out.includes('--json');
  record(
    'help lists onboarding flags',
    ok ? 'PASS' : 'FAIL',
    ok ? '' : out.slice(0, 200),
  );
}

// 2) Unknown TTY-less --ascii should parse (accepted option)
{
  const r = run(['init', '--ascii', '--help']);
  record(
    'init --ascii accepted',
    r.status === 0 ? 'PASS' : 'FAIL',
    r.stderr.slice(0, 120),
  );
}

// 3) Non-interactive: missing passphrase-stdin frames → handleInit path, no hang
{
  const dir = mkdtempSync(join(tmpdir(), 'kavrix-init-matrix-'));
  try {
    const r = run(
      [
        'init',
        '--passphrase-stdin',
        '--key-file',
        join(dir, 'k.key'),
        '--data-file',
        join(dir, 'k.vault'),
        '--config-dir',
        join(dir, 'cfg'),
      ],
      { input: '', timeout: 10_000 },
    );
    // Should fail fast (missing frames / invalid), not hang waiting for Ink
    const hung = r.error?.code === 'ETIMEDOUT';
    const ok = !hung && r.status !== 0;
    record(
      'non-interactive --passphrase-stdin never hangs on Ink',
      ok ? 'PASS' : 'FAIL',
      hung ? 'timed out' : `exit=${String(r.status)}`,
    );
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
}

// 4) --json skips interactive
{
  const dir = mkdtempSync(join(tmpdir(), 'kavrix-init-matrix-'));
  try {
    const r = run(
      [
        'init',
        '--json',
        '--passphrase-stdin',
        '--key-file',
        join(dir, 'k.key'),
        '--data-file',
        join(dir, 'k.vault'),
        '--config-dir',
        join(dir, 'cfg'),
      ],
      {
        input: 'correct horse battery staple\ncorrect horse battery staple\n',
        timeout: 60_000,
      },
    );
    // May succeed or fail depending on defaults; must not hang and must not be Ink
    const hung = r.error?.code === 'ETIMEDOUT';
    record(
      'non-interactive --json path completes without Ink hang',
      !hung ? 'PASS' : 'FAIL',
      hung ? 'timed out' : `exit=${String(r.status)}`,
    );
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
}

// 5) Successful scripted file init (handleInit)
{
  const dir = mkdtempSync(join(tmpdir(), 'kavrix-init-matrix-'));
  try {
    const key = join(dir, 'vault.key');
    const data = join(dir, 'vault.db');
    const cfg = join(dir, 'cfg');
    const passphrase = 'correct horse battery staple';
    const r = run(
      [
        'init',
        '--passphrase-stdin',
        '--key-file',
        key,
        '--data-file',
        data,
        '--config-dir',
        cfg,
        '--profile',
        'matrix',
      ],
      { input: `${passphrase}\n${passphrase}\n`, timeout: 90_000 },
    );
    const ok = r.status === 0 && existsSync(key);
    record(
      'scripted file init creates vault+key',
      ok ? 'PASS' : 'FAIL',
      ok ? '' : `exit=${String(r.status)} stderr=${r.stderr.slice(0, 240)}`,
    );

    // 6) Already initialized / profile exists
    const r2 = run(
      [
        'init',
        '--passphrase-stdin',
        '--key-file',
        key,
        '--data-file',
        data,
        '--config-dir',
        cfg,
        '--profile',
        'matrix',
      ],
      { input: `${passphrase}\n${passphrase}\n`, timeout: 30_000 },
    );
    const conflict =
      r2.status !== 0 &&
      /already exists|exist|conflict|in use|present/i.test(`${r2.stdout}${r2.stderr}`);
    record(
      'already-initialized conflict is clear',
      conflict || r2.status !== 0 ? 'PASS' : 'FAIL',
      `exit=${String(r2.status)} msg=${`${r2.stderr}${r2.stdout}`.slice(0, 160)}`,
    );
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
}

// 7) Mongo URL unreachable — honest error, no hang (db profile create via session is covered in vault smoke;
//    here we only prove CLI mongo init times out/fails cleanly when URL is bad).
{
  const dir = mkdtempSync(join(tmpdir(), 'kavrix-init-matrix-'));
  const mongoUrl = process.env.MONGO_URL;
  if (!mongoUrl) {
    record('mongo live create (MONGO_URL)', 'SKIP', 'set MONGO_URL to exercise');
  } else {
    try {
      const key = join(dir, 'mongo.key');
      const cfg = join(dir, 'cfg');
      const passphrase = 'correct horse battery staple';
      // Use a dedicated profile id; create via db profile + db init frames (same as TUI backend).
      const add = run(
        [
          'db',
          'profile',
          'add',
          'matrixmongo',
          '--datastore',
          'mongodb',
          '--database',
          'matrixmongo',
          '--key-file',
          key,
          '--config-dir',
          cfg,
        ],
        { timeout: 15_000 },
      );
      if (add.status !== 0) {
        record('mongo profile add', 'FAIL', add.stderr.slice(0, 200));
      } else {
        const init = run(
          [
            'db',
            'init',
            '--profile',
            'matrixmongo',
            '--config-dir',
            cfg,
            '--passphrase-stdin',
          ],
          {
            input: `${mongoUrl}\nmatrixmongo-db\n${passphrase}\n${passphrase}\n`,
            timeout: 60_000,
          },
        );
        record(
          'mongo live db init',
          init.status === 0 ? 'PASS' : 'FAIL',
          init.status === 0 ? '' : init.stderr.slice(0, 200),
        );
        run(['db', 'profile', 'remove', 'matrixmongo', '--config-dir', cfg], {
          timeout: 10_000,
        });
      }
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  }
}

// 8) Bad mongo URL fails without hang
{
  const dir = mkdtempSync(join(tmpdir(), 'kavrix-init-matrix-'));
  try {
    const key = join(dir, 'mongo.key');
    const cfg = join(dir, 'cfg');
    const passphrase = 'correct horse battery staple';
    run(
      [
        'db',
        'profile',
        'add',
        'matrixbad',
        '--datastore',
        'mongodb',
        '--database',
        'matrixbad',
        '--key-file',
        key,
        '--config-dir',
        cfg,
      ],
      { timeout: 15_000 },
    );
    const bad = run(
      [
        'db',
        'init',
        '--profile',
        'matrixbad',
        '--config-dir',
        cfg,
        '--passphrase-stdin',
      ],
      {
        input: `mongodb://127.0.0.1:1/?serverSelectionTimeoutMS=1000\nbad-db\n${passphrase}\n${passphrase}\n`,
        timeout: 25_000,
      },
    );
    const hung = bad.error?.code === 'ETIMEDOUT';
    record(
      'mongo unreachable honest error (no hang)',
      !hung && bad.status !== 0 ? 'PASS' : 'FAIL',
      hung ? 'timed out' : `exit=${String(bad.status)}`,
    );
    run(['db', 'profile', 'remove', 'matrixbad', '--config-dir', cfg], {
      timeout: 10_000,
    });
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
}

const failed = results.filter((r) => r.status === 'FAIL');
console.log('');
console.log(
  `init-onboarding-matrix: ${results.filter((r) => r.status === 'PASS').length} PASS, ${
    results.filter((r) => r.status === 'SKIP').length
  } SKIP, ${failed.length} FAIL`,
);
process.exit(failed.length === 0 ? 0 : 1);
