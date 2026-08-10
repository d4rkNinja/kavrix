import process from 'node:process';

const versionParts = process.versions.node.split('.').map(Number);
const [major, minor, patch] = versionParts;

if (
  major !== 24 ||
  minor === undefined ||
  patch === undefined ||
  !Number.isSafeInteger(minor) ||
  minor < 19 ||
  !Number.isSafeInteger(patch) ||
  patch < 0
) {
  process.stderr.write('Unsupported Node runtime. Use Node >=24.19.0 and <25.\n');
  process.exitCode = 1;
} else {
  await import('./performance.ts');
}
