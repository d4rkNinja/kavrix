/* global process */

import { spawn } from 'node:child_process';
import { platform } from 'node:process';
import { fileURLToPath } from 'node:url';

const root = fileURLToPath(new URL('..', import.meta.url));

const isWindows = platform === 'win32';
const pnpmBin = isWindows ? 'pnpm.cmd' : 'pnpm';

const useColor = Boolean(process.stdout.isTTY) && !process.env.NO_COLOR;
const paint = (code, text) => (useColor ? `\x1b[${code}m${text}\x1b[0m` : text);
const bold = (text) => paint(1, text);
const dim = (text) => paint(2, text);
const green = (text) => paint(32, text);
const red = (text) => paint(31, text);
const yellow = (text) => paint(33, text);

function parseArgs(argv) {
  const flags = new Set();
  for (const arg of argv) {
    if (arg !== '--quick' && arg !== '--acceptance-only') {
      throw new Error(`Unknown option: ${arg}`);
    }
    flags.add(arg);
  }
  if (flags.has('--quick') && flags.has('--acceptance-only')) {
    throw new Error('--quick and --acceptance-only are mutually exclusive');
  }
  return flags;
}

function formatDuration(ms) {
  const seconds = ms / 1000;
  if (seconds < 60) return `${seconds.toFixed(1)}s`;
  const minutes = Math.floor(seconds / 60);
  return `${minutes}m ${Math.round(seconds % 60)}s`;
}

function canRunDocker() {
  return new Promise((resolvePromise) => {
    const child = spawn(
      isWindows ? 'docker.cmd' : 'docker',
      ['info', '--format', '{{.ServerVersion}}'],
      {
        cwd: root,
        shell: isWindows,
        stdio: 'ignore',
      },
    );
    child.on('error', () => resolvePromise(false));
    child.on('close', (code) => resolvePromise(code === 0));
  });
}

function spawnStep(command, args) {
  return new Promise((resolvePromise) => {
    const startedAt = Date.now();
    const child = isWindows
      ? spawn([command, ...args].join(' '), {
          cwd: root,
          shell: true,
          env: { ...process.env, FORCE_COLOR: useColor ? '1' : '0' },
        })
      : spawn(command, args, {
          cwd: root,
          env: { ...process.env, FORCE_COLOR: useColor ? '1' : '0' },
        });

    let stdout = '';
    let stderr = '';
    child.stdout.setEncoding('utf8');
    child.stderr.setEncoding('utf8');
    child.stdout.on('data', (chunk) => {
      stdout += chunk;
      if (stdout.length > 8 * 1024 * 1024) stdout = stdout.slice(-4 * 1024 * 1024);
    });
    child.stderr.on('data', (chunk) => {
      stderr += chunk;
      if (stderr.length > 8 * 1024 * 1024) stderr = stderr.slice(-4 * 1024 * 1024);
    });
    child.on('error', (spawnError) => {
      resolvePromise({
        code: null,
        stdout,
        stderr,
        spawnError,
        durationMs: Date.now() - startedAt,
      });
    });
    child.on('close', (code) => {
      resolvePromise({ code, stdout, stderr, durationMs: Date.now() - startedAt });
    });
  });
}

function printFailure(result) {
  if (result.spawnError) console.error(red(`    ${result.spawnError.message}`));
  const tail = `${result.stdout}\n${result.stderr}`
    .split(/\r?\n/)
    .filter((line) => line.trim().length > 0)
    .slice(-40);
  for (const line of tail) console.error(dim(`    | ${line}`));
}

const stepLog = [];

async function runStep(step, { streamProgress = true } = {}) {
  if (streamProgress) {
    process.stdout.write(`  ${dim('[run]')} ${step.name.padEnd(32)} `);
  }
  const result = await spawnStep(pnpmBin, step.args);
  const passed = result.code === 0;
  console.log(
    passed
      ? green(`ok ${dim(formatDuration(result.durationMs))}`)
      : red(`FAILED ${dim(formatDuration(result.durationMs))}`),
  );
  stepLog.push({ name: step.name, failed: !passed, durationMs: result.durationMs });
  if (!passed) printFailure(result);
  return passed;
}

async function runSequential(stageName, steps) {
  console.log(bold(`\n==> ${stageName}`));
  for (const step of steps) {
    const passed = await runStep(step);
    if (!passed) return [step.name];
  }
  return [];
}

async function runParallel(stageName, steps) {
  console.log(bold(`\n==> ${stageName} ${dim('(parallel)')}`));
  await Promise.all(steps.map((step) => runStep(step, { streamProgress: false })));
  return stepLog.filter((entry) => entry.failed).map((entry) => entry.name);
}

async function buildPlan(flags) {
  const staticChecks = [
    { name: 'format:check', args: ['run', 'format:check'] },
    { name: 'lint', args: ['run', 'lint'] },
    { name: 'typecheck', args: ['run', 'typecheck'] },
  ];
  const buildAndTest = [
    { name: 'build', args: ['run', 'build'] },
    { name: 'test', args: ['run', 'test'] },
  ];
  const packedCliAcceptance = [
    { name: 'acceptance:pre-ci', args: ['run', 'acceptance:pre-ci'] },
    { name: 'package:smoke', args: ['--filter', 'kavrix', 'run', 'package:smoke'] },
  ];

  const stages = [];
  const skipped = [];

  if (!flags.has('--acceptance-only')) {
    stages.push({ name: 'Static checks', parallel: true, steps: staticChecks });
    stages.push({ name: 'Build and unit tests', steps: buildAndTest });
  }

  if (!flags.has('--quick')) {
    if (await canRunDocker()) {
      stages.push({
        name: 'Database container acceptance',
        steps: [
          {
            name: 'acceptance:database-container',
            args: ['run', 'acceptance:database-container'],
          },
        ],
      });
    } else {
      skipped.push({
        name: 'acceptance:database-container',
        reason: 'Docker not available here; CI runs it on Linux',
      });
    }
    stages.push({ name: 'Packed CLI acceptance', steps: packedCliAcceptance });
  }

  return { stages, skipped };
}

function summarize(skipped, failedSteps) {
  console.log(bold('\n=== Summary ==='));
  for (const entry of stepLog) {
    const status = entry.failed ? red('FAIL') : green('pass');
    console.log(
      `  ${status}  ${entry.name.padEnd(34)} ${formatDuration(entry.durationMs)}`,
    );
  }
  for (const item of skipped) {
    console.log(`  ${yellow('skip')}  ${item.name.padEnd(34)} ${dim(item.reason)}`);
  }
  if (failedSteps.length > 0) {
    console.log(bold(red(`\nVerification FAILED (${failedSteps.join(', ')})`)));
    return 1;
  }
  console.log(bold(green('\nAll gates passed.')));
  console.log(
    dim('Safe to push; CI re-runs everything across Linux, macOS, and Windows.'),
  );
  return 0;
}

async function main() {
  let flags;
  try {
    flags = parseArgs(process.argv.slice(2));
  } catch (error) {
    console.error(
      `${red('error')} ${error instanceof Error ? error.message : String(error)}`,
    );
    console.error('Usage: node scripts/verify-all.mjs [--quick | --acceptance-only]');
    process.exitCode = 2;
    return;
  }

  const mode = flags.has('--acceptance-only')
    ? 'acceptance-only'
    : flags.has('--quick')
      ? 'quick'
      : 'full';
  console.log(bold(`Kavrix verification (${mode})`));
  console.log(dim(`Root: ${root}`));

  const { stages, skipped } = await buildPlan(flags);
  let failedSteps = [];

  for (const stage of stages) {
    const failures = stage.parallel
      ? await runParallel(stage.name, stage.steps)
      : await runSequential(stage.name, stage.steps);
    if (failures.length > 0) {
      failedSteps = failures;
      break;
    }
  }

  process.exitCode = summarize(skipped, failedSteps);
}

main().catch((error) => {
  console.error(
    red(error instanceof Error ? (error.stack ?? error.message) : String(error)),
  );
  process.exitCode = 1;
});
