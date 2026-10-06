/**
 * Builds the before/after performance report from two saved suite reports.
 *
 * Startup is additionally reported net of the bare Node baseline measured in the
 * same run, because that baseline drifts with machine load and would otherwise
 * hide or invent part of the change.
 */
import { readFile } from 'node:fs/promises';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const here = dirname(fileURLToPath(import.meta.url));
const reportDirectory = resolve(here, '../../.tmp/perf');

const suites = ['startup', 'acl', 'storage', 'tui', 'serialization'];
const before = await readReports('before');
const after = await readReports('after');

const rows = [];
for (const suite of suites) {
  for (const key of Object.keys(before[suite] ?? {}).sort()) {
    const from = before[suite][key];
    const to = after[suite]?.[key];
    if (typeof from !== 'number' || typeof to !== 'number') continue;
    rows.push({ suite, metric: key, before: from, after: to });
  }
}

// Startup is dominated by process launch that Kavrix does not control, so the
// same numbers are also reported net of the bare interpreter measured in the
// same run.
const baselineBefore = before.startup['nodeBaseline'] ?? 0;
const baselineAfter = after.startup['nodeBaseline'] ?? 0;
for (const row of [...rows]) {
  if (row.suite !== 'startup' || row.metric === 'nodeBaseline') continue;
  rows.push({
    suite: 'startup',
    metric: `${row.metric} (net of node)`,
    before: round(row.before - baselineBefore),
    after: round(row.after - baselineAfter),
  });
}

console.log('| Suite | Metric | Before | After | Speedup | Change |');
console.log('| --- | --- | ---: | ---: | ---: | ---: |');
for (const row of rows) {
  const speedup = row.before / row.after;
  const change = ((row.after - row.before) / row.before) * 100;
  console.log(
    `| ${row.suite} | ${row.metric} | ${format(row.before)} | ${format(row.after)} | ${speedup.toFixed(2)}x | ${signed(change)} |`,
  );
}

const startupNet = rows.filter((row) => row.metric === 'versionFlag (net of node)');
if (startupNet.length > 0) {
  console.log(
    `\nCLI startup overhead (excluding interpreter launch): ${startupNet[0].before}ms -> ${startupNet[0].after}ms`,
  );
}

async function readReports(label) {
  const reports = {};
  for (const suite of suites) {
    try {
      const parsed = JSON.parse(
        await readFile(resolve(reportDirectory, `${label}.${suite}.json`), 'utf8'),
      );
      reports[suite] = flatten(parsed);
    } catch {
      reports[suite] = {};
    }
  }
  return reports;
}

function flatten(node) {
  const sink = {};
  for (const [key, value] of Object.entries(node)) {
    if (value !== null && typeof value === 'object') {
      Object.assign(sink, flatten(value));
    } else if (typeof value === 'number') {
      sink[key] = value;
    }
  }
  return sink;
}

function round(value) {
  return Math.round(value * 1000) / 1000;
}

function format(value) {
  return value >= 100 ? value.toFixed(1) : value.toFixed(3);
}

function signed(percent) {
  const rounded = Math.round(percent * 10) / 10;
  return `${rounded > 0 ? '+' : ''}${String(rounded)}%`;
}
