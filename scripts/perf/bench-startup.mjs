/**
 * Measures CLI process startup: end-to-end wall clock, peak RSS, and the
 * module-graph cost that dominates it.
 *
 * These are the numbers a user feels when they type `kavrix <anything>`.
 */
import { execFile } from 'node:child_process';
import { readdir, mkdtemp, readFile, rm, stat } from 'node:fs/promises';
import { createRequire } from 'node:module';
import { tmpdir } from 'node:os';
import { dirname, resolve } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { promisify } from 'node:util';

import { parseArgs, summarize } from './harness.mjs';

const execFileAsync = promisify(execFile);
const here = dirname(fileURLToPath(import.meta.url));
const require = createRequire(import.meta.url);
const binPath = resolve(here, '../../apps/cli/dist/bin.js');
const rssProbe = pathToFileURL(resolve(here, 'rss-probe.mjs')).href;
const iterations = Number.parseInt(parseArgs(process.argv).iterations ?? '12', 10);

const results = {
  nodeBaseline: await timeProcess(process.execPath, ['--version']),
  versionFlag: await timeKavrix(['--version']),
  helpFlag: await timeKavrix(['--help']),
  unknownCommand: await timeKavrix(['__kavrix_perf_unknown__']),
  eagerModuleLoad: await measureEagerModuleLoad(),
  bundleBytes: await measureBundleBytes(),
};

console.log(JSON.stringify(results, null, 2));

async function timeProcess(command, args) {
  const samples = [];
  for (let index = 0; index < iterations; index += 1) {
    const started = process.hrtime.bigint();
    await execFileAsync(command, args, { windowsHide: true, stdio: 'ignore' });
    samples.push(Number(process.hrtime.bigint() - started) / 1e6);
  }
  return summarize(samples);
}

async function timeKavrix(args) {
  const samples = [];
  for (let index = 0; index < iterations; index += 1) {
    const started = process.hrtime.bigint();
    await run(process.execPath, [binPath, ...args], {
      windowsHide: true,
      stdio: 'ignore',
    });
    samples.push(Number(process.hrtime.bigint() - started) / 1e6);
  }
  return {
    ...summarize(samples),
    peakRssMb: await measurePeakRssMb(args),
  };
}

/**
 * Peak RSS of a real CLI run, sampled by an exit hook in a preload. The probe
 * only reads `process.memoryUsage()` and writes the number to a temp file; it
 * cannot observe or alter vault state.
 */
async function measurePeakRssMb(args) {
  const directory = await mkdtemp(resolve(tmpdir(), 'kavrix-perf-rss-'));
  const target = resolve(directory, 'rss.txt');
  try {
    await run(process.execPath, ['--import', rssProbe, binPath, ...args], {
      windowsHide: true,
      stdio: 'ignore',
      env: { ...process.env, KAVRIX_PERF_RSS_FILE: target },
    });
    const recorded = Number.parseInt(await readFile(target, 'utf8'), 10);
    return Number.isFinite(recorded) ? Math.round(recorded / 1024) / 1024 : -1;
  } catch {
    return -1;
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
}

/**
 * Cost of evaluating the package graph the CLI imports at startup, isolated
 * from process-spawn overhead and measured with heap/RSS deltas.
 */
async function measureEagerModuleLoad() {
  const before = process.memoryUsage();
  const started = process.hrtime.bigint();
  await import('@kavrix/schemas');
  await import('@kavrix/crypto');
  await import('@kavrix/storage');
  const after = process.memoryUsage();
  return {
    loadMs: round(Number(process.hrtime.bigint() - started) / 1e6),
    heapDeltaMb: mb(after.heapUsed - before.heapUsed),
    rssDeltaMb: mb(after.rss - before.rss),
  };
}

async function measureBundleBytes() {
  const distDirectory = dirname(binPath);
  const chunkNames = await readdir(resolve(distDirectory, 'chunks')).catch(() => []);
  const names = [
    { relative: 'bin.js' },
    ...chunkNames
      .filter((name) => name.endsWith('.js'))
      .map((name) => ({ relative: `chunks/${name}` })),
  ];
  let total = 0;
  for (const { relative } of names) {
    const info = await stat(resolve(distDirectory, relative)).catch(() => undefined);
    if (info?.isFile() === true) total += info.size;
  }
  return { totalJsBytes: total, artifactCount: names.length };
}

/** Runs a child to completion; any exit code is a valid startup sample. */
async function run(command, args, options) {
  try {
    await execFileAsync(command, args, options);
  } catch {
    // Help, usage errors, and unknown commands exit non-zero by design, and
    // their startup cost is identical to a successful run.
  }
}

function mb(bytes) {
  return round(bytes / 1024 / 1024);
}

function round(value) {
  return Math.round(value * 1000) / 1000;
}
