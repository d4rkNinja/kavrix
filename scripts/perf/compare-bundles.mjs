/**
 * Interleaved A/B comparison of two built CLI bundles.
 *
 * Startup measurements drift with machine load, so comparing two runs taken
 * minutes apart can invent or hide a difference. This alternates between the
 * two artifacts sample by sample, so any drift affects both equally, and
 * reports the paired difference rather than two independent medians.
 */
import { execFile } from 'node:child_process';
import { cp, rm } from 'node:fs/promises';
import { createRequire } from 'node:module';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { promisify } from 'node:util';

import { parseArgs, percentile, summarize } from './harness.mjs';

const execFileAsync = promisify(execFile);
const here = dirname(fileURLToPath(import.meta.url));
const require = createRequire(import.meta.url);
void require;

const args = parseArgs(process.argv);
const labelA = args.a ?? 'a';
const labelB = args.b ?? 'b';
const dirA = resolve(here, `../../.tmp/ab-${labelA}`);
const dirB = resolve(here, `../../.tmp/ab-${labelB}`);
const source = resolve(here, '../../apps/cli/dist');
const iterations = Number.parseInt(args.iterations ?? '40', 10);
const commandArgs = (args.command ?? '--version').split(' ').filter(Boolean);

await rm(dirA, { recursive: true, force: true });
await rm(dirB, { recursive: true, force: true });
await cp(source, dirA, { recursive: true });
await cp(source, dirB, { recursive: true });

const binA = resolve(dirA, 'bin.js');
const binB = resolve(dirB, 'bin.js');

for (let index = 0; index < 4; index += 1) {
  await run(binA);
  await run(binB);
}

const samplesA = [];
const samplesB = [];
for (let index = 0; index < iterations; index += 1) {
  samplesA.push(await run(binA));
  samplesB.push(await run(binB));
  samplesB.push(await run(binB));
  samplesA.push(await run(binA));
}

const summaryA = summarize(samplesA);
const summaryB = summarize(samplesB);
const difference = ((summaryB.medianMs - summaryA.medianMs) / summaryA.medianMs) * 100;

console.log(
  JSON.stringify(
    {
      command: commandArgs.join(' '),
      samples: samplesA.length,
      [labelA]: summaryA,
      [labelB]: summaryB,
      [`${labelB}_vs_${labelA}_medianDeltaPercent`]: Math.round(difference * 100) / 100,
      [`${labelB}_vs_${labelA}_speedup`]:
        Math.round((summaryA.medianMs / summaryB.medianMs) * 100) / 100,
      aTail: [
        percentile(
          [...samplesA].sort((x, y) => x - y),
          0.95,
        ),
      ],
    },
    null,
    2,
  ),
);

async function run(bin) {
  const started = process.hrtime.bigint();
  try {
    await execFileAsync(process.execPath, [bin, ...commandArgs], {
      windowsHide: true,
      stdio: 'ignore',
    });
  } catch {
    // Any exit code is a valid startup sample.
  }
  return Number(process.hrtime.bigint() - started) / 1e6;
}
