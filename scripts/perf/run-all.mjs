/**
 * Runs the whole performance suite and writes one JSON report per label, so a
 * before/after comparison is a plain file diff rather than a judgement call.
 *
 * Usage: node scripts/perf/run-all.mjs --label=after [--only=startup,storage]
 */
import { spawn } from 'node:child_process';
import { mkdir, writeFile } from 'node:fs/promises';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const here = dirname(fileURLToPath(import.meta.url));
const reportDirectory = resolve(here, '../../.tmp/perf');

const args = parseArgs(process.argv);
const label = args.label ?? 'run';
const only = args.only === undefined ? undefined : new Set(args.only.split(','));

const suites = [
  { name: 'startup', script: 'bench-startup.mjs', extra: ['--iterations=10'] },
  { name: 'cli', script: 'bench-cli-commands.mjs', extra: ['--iterations=5'] },
  { name: 'acl', script: 'bench-acl.mjs', extra: ['--iterations=5'] },
  { name: 'storage', script: 'bench-storage-file.mjs', extra: ['--iterations=4'] },
  { name: 'tui', script: 'bench-tui-render.mjs', extra: ['--iterations=120'] },
  {
    name: 'serialization',
    script: 'bench-serialization.mjs',
    extra: ['--iterations=2000'],
  },
];

await mkdir(reportDirectory, { recursive: true });
const summary = {};

for (const suite of suites) {
  if (only !== undefined && !only.has(suite.name)) continue;
  process.stderr.write(`\n[perf] ${suite.name}\n`);
  const stdout = await runSuite(suite);
  await writeFile(
    resolve(reportDirectory, `${label}.${suite.name}.json`),
    stdout,
    'utf8',
  );
  summary[suite.name] = summarizeJson(stdout);
}

console.log(JSON.stringify({ label, suites: summary }, null, 2));

function runSuite(suite) {
  return new Promise((resolvePromise, rejectPromise) => {
    const child = spawn(
      process.execPath,
      ['--import', 'tsx', resolve(here, suite.script), ...suite.extra],
      {
        cwd: resolve(here, '../..'),
        stdio: ['ignore', 'pipe', 'inherit'],
        windowsHide: true,
      },
    );
    let stdout = '';
    child.stdout.setEncoding('utf8');
    child.stdout.on('data', (chunk) => {
      stdout += chunk;
    });
    child.once('error', rejectPromise);
    child.once('close', (code) => {
      if (code === 0) resolvePromise(stdout);
      else rejectPromise(new Error(`${suite.name} exited with code ${String(code)}`));
    });
  });
}

/** Pulls the median of every leaf measurement out of a suite report. */
function summarizeJson(text) {
  let parsed;
  try {
    parsed = JSON.parse(text);
  } catch {
    return { error: 'unparsable report' };
  }
  const leaves = {};
  walk(parsed, '', leaves);
  return leaves;
}

function walk(node, prefix, sink) {
  if (node === null || typeof node !== 'object') return;
  if (typeof node.medianMs === 'number') {
    sink[prefix] = node.medianMs;
    return;
  }
  for (const [key, value] of Object.entries(node))
    walk(value, `${prefix}.${key}`, sink);
}

function parseArgs(argv) {
  const values = {};
  for (const entry of argv) {
    const match = /^--([^=]+)=(.*)$/u.exec(entry);
    if (match !== null) values[match[1]] = match[2];
  }
  return values;
}
