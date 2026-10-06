/**
 * Isolates the Windows protected-path boundary cost.
 *
 * `kavrix` treats every ACL assertion as a hostile platform boundary, which on
 * Windows means spawning a fixed interpreter with a fixed encoded script. This
 * benchmark measures the three primitives the storage layer actually calls so
 * the cost of a single store operation can be attributed precisely.
 *
 * On non-Windows platforms every helper is a documented no-op and this reports
 * zeros rather than pretending to measure a boundary that does not exist.
 */
import { mkdtemp, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import {
  setWindowsUserOnlyAcl,
  verifyWindowsDirectoryAcl,
  verifyWindowsUserOnlyAcl,
} from '../../packages/key-files/src/windows-acl.ts';

import { parseArgs, timeRepeatedly } from './harness.mjs';

const iterations = Number.parseInt(parseArgs(process.argv).iterations ?? '5', 10);

if (process.platform !== 'win32') {
  console.log(
    JSON.stringify(
      { platform: process.platform, note: 'ACL boundary is a POSIX no-op' },
      null,
      2,
    ),
  );
} else {
  console.log(JSON.stringify(await measure(), null, 2));
}

async function measure() {
  const directory = await mkdtemp(join(tmpdir(), 'kavrix-perf-acl-'));
  try {
    const file = join(directory, 'protected.bin');
    await writeFile(file, 'synthetic non-secret benchmark payload');
    await setWindowsUserOnlyAcl(file);
    await setWindowsUserOnlyAcl(directory);
    const freshFile = join(directory, 'fresh.bin');
    return {
      platform: process.platform,
      iterations,
      setUserOnlyAclOnFreshFile: await timeRepeatedly(
        async () => {
          await rm(freshFile, { force: true });
          await writeFile(freshFile, 'synthetic');
          await setWindowsUserOnlyAcl(freshFile);
        },
        { iterations, warmup: 0 },
      ),
      verifyUserOnlyAcl: await timeRepeatedly(() => verifyWindowsUserOnlyAcl(file), {
        iterations,
        warmup: 1,
      }),
      verifyDirectoryAcl: await timeRepeatedly(
        () => verifyWindowsDirectoryAcl(directory),
        {
          iterations,
          warmup: 1,
        },
      ),
    };
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
}
