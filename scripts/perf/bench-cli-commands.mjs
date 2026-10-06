/**
 * Measures real end-to-end CLI command latency against a synthetic local vault.
 *
 * Every scenario spawns the built executable as a fresh process, so the sample
 * includes the full user-visible cost: process startup, module evaluation,
 * passphrase derivation, storage I/O, and output formatting. No command output
 * is persisted, and every run is checked for plaintext leakage of the fixture
 * value before it is discarded.
 *
 * Excluded by design: `tui` (interactive; covered by bench-tui-render.mjs),
 * `self-update` (network), and MongoDB scenarios (require a disposable replica
 * set, per docs/performance.md).
 */
import { spawn } from 'node:child_process';
import { randomUUID } from 'node:crypto';
import { mkdtemp, realpath, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';

import { parseArgs, summarize } from './harness.mjs';

const here = dirname(fileURLToPath(import.meta.url));
const binPath = resolve(here, '../../apps/cli/dist/bin.js');
const windowsAcl = await import(
  pathToFileURL(resolve(here, '../../packages/key-files/dist/windows-acl.js')).href
).catch(() => undefined);

const iterations = Number.parseInt(parseArgs(process.argv).iterations ?? '5', 10);
const warmup = 1;
const invocationTimeoutMs = 120_000;

const results = {
  environment: {
    node: process.version,
    platform: `${process.platform}-${process.arch}`,
  },
  scenarios: {},
};

const root = await realpath(await mkdtemp(join(tmpdir(), 'kavrix-perf-cli-')));
// Artifacts live directly in the ACL-hardened root: the CLI enforces owned
// permissions on every directory it touches, and a hermetic HOME keeps profile
// state out of the developer's real configuration.
const configHome = join(root, '.config');
const paths = {
  dataFile: join(root, 'vault.kavrix'),
  keyFile: join(root, 'primary.key'),
};
const credentialName = 'perf-credential';
const temporaryName = 'perf-temporary';
const renamePair = ['perf-rename-a', 'perf-rename-b'];
const passphrase = randomUUID() + randomUUID();
// Synthetic fixture value; never revealed by these scenarios and never printed.
const fixtureValue = randomUUID();

try {
  if (process.platform === 'win32' && windowsAcl !== undefined) {
    await windowsAcl.setWindowsUserOnlyAcl(root);
  }
  await primeVault();
  results.processOverhead = await summarizeOverhead();
  const scenarios = [
    {
      name: 'vaultList',
      args: ['vault', 'list', '--datastore', 'file', '--data-file', paths.dataFile],
      frames: [],
    },
    { name: 'vaultStatus', args: ['vault', 'status', ...fileArgs()], frames: [] },
    {
      name: 'keyStatus',
      args: ['key', 'status', ...keyArgs(), '--passphrase-stdin'],
      frames: [passphrase],
    },
    {
      name: 'keyVerify',
      args: ['key', 'verify', ...keyArgs(), '--passphrase-stdin'],
      frames: [passphrase],
    },
    {
      name: 'has',
      args: ['has', credentialName, ...fileArgs(), ...keyArgs(), '--passphrase-stdin'],
      frames: [passphrase],
    },
    {
      name: 'get',
      args: ['get', credentialName, ...fileArgs(), ...keyArgs(), '--passphrase-stdin'],
      frames: [passphrase],
    },
    {
      name: 'listUnlocked',
      args: ['list', ...fileArgs(), ...keyArgs(), '--passphrase-stdin'],
      frames: [passphrase],
    },
    {
      name: 'viewAllJson',
      args: ['view', ...fileArgs(), ...keyArgs(), '--passphrase-stdin', '--json'],
      frames: [passphrase],
    },
    {
      name: 'viewOneJson',
      args: [
        'view',
        credentialName,
        ...fileArgs(),
        ...keyArgs(),
        '--passphrase-stdin',
        '--json',
      ],
      frames: [passphrase],
    },
    {
      name: 'searchJson',
      args: [
        'search',
        'perf',
        ...fileArgs(),
        ...keyArgs(),
        '--passphrase-stdin',
        '--json',
        '--limit',
        '5',
      ],
      frames: [passphrase],
    },
    {
      name: 'statsJson',
      args: ['stats', ...fileArgs(), ...keyArgs(), '--passphrase-stdin', '--json'],
      frames: [passphrase],
    },
    {
      name: 'putAndRemove',
      runs: 2,
      steps: [
        {
          args: [
            'put',
            temporaryName,
            ...fileArgs(),
            ...keyArgs(),
            '--passphrase-stdin',
            '--value-stdin',
          ],
          frames: [passphrase, fixtureValue],
        },
        {
          args: [
            'remove',
            temporaryName,
            ...fileArgs(),
            ...keyArgs(),
            '--passphrase-stdin',
          ],
          frames: [passphrase],
        },
      ],
    },
    {
      name: 'renameAlternate',
      runs: 2,
      steps: [
        {
          args: [
            'rename',
            renamePair[0],
            renamePair[1],
            ...fileArgs(),
            ...keyArgs(),
            '--passphrase-stdin',
          ],
          frames: [passphrase],
        },
        {
          args: [
            'rename',
            renamePair[1],
            renamePair[0],
            ...fileArgs(),
            ...keyArgs(),
            '--passphrase-stdin',
          ],
          frames: [passphrase],
        },
      ],
    },
    {
      name: 'doctor',
      args: ['doctor', ...fileArgs(), ...keyArgs(), '--passphrase-stdin'],
      frames: [passphrase],
    },
    {
      name: 'doctorHealth',
      args: ['doctor', 'health', ...fileArgs(), ...keyArgs(), '--passphrase-stdin'],
      frames: [passphrase],
    },
    {
      name: 'recoveryStatus',
      args: ['recovery', 'status', ...fileArgs(), '--json'],
      frames: [],
    },
  ];
  for (const scenario of scenarios) {
    results.scenarios[scenario.name] = await timeScenario(scenario);
  }
} finally {
  console.log(JSON.stringify(results, null, 2));
  await removeTemporaryRoot(root);
}

/**
 * Windows briefly holds handles on freshly exited child processes and their
 * files (antivirus, indexer), so removal retries for a bounded period instead
 * of failing a benchmark that already produced its numbers.
 */
async function removeTemporaryRoot(target) {
  for (let attempt = 0; attempt < 10; attempt += 1) {
    try {
      await rm(target, { recursive: true, force: true, maxRetries: 3 });
      return;
    } catch {
      await new Promise((resolveSleep) => setTimeout(resolveSleep, 250));
    }
  }
  process.stderr.write(`[perf] cleanup of ${target} did not complete; ignoring\n`);
}

function fileArgs() {
  return [
    '--datastore',
    'file',
    '--data-file',
    paths.dataFile,
    '--vault',
    'perf-vault',
  ];
}

function keyArgs() {
  return ['--key-file', paths.keyFile];
}

function framesPayload(frames) {
  return frames.length === 0 ? undefined : `${frames.join('\n')}\n`;
}

/** Creates the vault, one credential, and the rename pair once (untimed). */
async function primeVault() {
  await runChecked(
    ['init', '--legacy', ...fileArgs(), ...keyArgs(), '--passphrase-stdin'],
    framesPayload([passphrase, passphrase]),
  );
  await runChecked(
    [
      'put',
      credentialName,
      ...fileArgs(),
      ...keyArgs(),
      '--passphrase-stdin',
      '--value-stdin',
    ],
    framesPayload([passphrase, fixtureValue]),
  );
  // Only the first rename target is primed; the scenario alternates
  // rename-a -> rename-b -> rename-a, so each iteration stays valid.
  await runChecked(
    [
      'put',
      renamePair[0],
      ...fileArgs(),
      ...keyArgs(),
      '--passphrase-stdin',
      '--value-stdin',
    ],
    framesPayload([passphrase, fixtureValue]),
  );
}

/** Reference number for subtracting bare process overhead from a scenario. */
async function summarizeOverhead() {
  const samples = [];
  for (let index = 0; index < iterations; index += 1) {
    samples.push(await timeInvocation(['--version'], undefined));
  }
  return summarize(samples);
}

async function timeScenario(scenario) {
  const steps = scenario.steps ?? [
    { args: scenario.args, frames: scenario.frames ?? [] },
  ];
  const samples = [];
  for (let index = 0; index < warmup + iterations; index += 1) {
    let combined = 0;
    for (let repeat = 0; repeat < (scenario.runs ?? 1); repeat += 1) {
      const step = steps[repeat] ?? steps[0];
      combined += await timeInvocation(step.args, framesPayload(step.frames));
    }
    if (index >= warmup) samples.push(combined);
  }
  return summarize(samples);
}

async function timeInvocation(args, input) {
  const started = process.hrtime.bigint();
  const result = await runChecked(args, input);
  const elapsed = Number(process.hrtime.bigint() - started) / 1e6;
  if (
    !args.includes('--reveal') &&
    (result.stdout.includes(fixtureValue) || result.stderr.includes(fixtureValue))
  ) {
    throw new Error(`kavrix ${args.join(' ')} exposed the fixture value`);
  }
  return elapsed;
}

async function runChecked(args, input) {
  return await new Promise((resolveRun, rejectRun) => {
    const child = spawn(process.execPath, [binPath, ...args], {
      cwd: root,
      // Only Kavrix's own configuration is hermetic. HOME/USERPROFILE stay
      // real because the Windows ACL helper intentionally reuses the user's
      // PowerShell module-analysis cache to keep interpreter start-up fast;
      // a synthetic profile would defeat that and skew every sample.
      env: { ...process.env, XDG_CONFIG_HOME: configHome },
      shell: false,
      stdio: ['pipe', 'pipe', 'pipe'],
      windowsHide: true,
    });
    const stdout = [];
    const stderr = [];
    let settled = false;
    const finish = (error, result) => {
      if (settled) return;
      settled = true;
      clearTimeout(timeout);
      if (error !== undefined) rejectRun(error);
      else resolveRun(result);
    };
    const capture = (chunk, target) => {
      target.push(Buffer.from(chunk));
    };
    child.stdout.on('data', (chunk) => capture(chunk, stdout));
    child.stderr.on('data', (chunk) => capture(chunk, stderr));
    child.stdin.on('error', () => undefined);
    child.stdin.end(input ?? '');
    const timeout = setTimeout(() => {
      child.kill();
      finish(new Error(`kavrix ${args.join(' ')} timed out`));
    }, invocationTimeoutMs);
    child.once('error', () => {
      finish(new Error(`kavrix ${args.join(' ')} could not start`));
    });
    child.once('close', (code) => {
      const result = {
        stdout: Buffer.concat(stdout).toString('utf8'),
        stderr: Buffer.concat(stderr).toString('utf8'),
      };
      if (code !== 0) {
        finish(
          new Error(
            `kavrix ${args.join(' ')} failed (code ${String(code)}): ${result.stderr
              .trim()
              .slice(0, 300)}`,
          ),
        );
      } else {
        finish(undefined, result);
      }
    });
  });
}
