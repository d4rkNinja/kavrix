import process from 'node:process';

// Mirrors apps/cli/src/runtime-preflight.ts. The check has to run before the
// dynamic import below, because performance.ts pulls in built packages that
// would fail with a bare TypeError on a runtime missing crypto.argon2.
const SUPPORTED_NODE_RANGE = '>=24.12.0 <25 || >=25.1.0';

function isSupportedNodeVersion(value) {
  const match = /^(\d+)\.(\d+)\.(\d+)(?:[-+].*)?$/u.exec(value);
  if (match === null) return false;
  const [major, minor] = match.slice(1, 3).map(Number);
  if (!Number.isSafeInteger(major) || !Number.isSafeInteger(minor)) return false;
  if (major === 24) return minor >= 12;
  if (major === 25) return minor >= 1;
  return major > 25;
}

if (isSupportedNodeVersion(process.versions.node)) {
  await import('./performance.ts');
} else {
  process.stderr.write(
    `Unsupported Node runtime v${process.versions.node}. Use Node ${SUPPORTED_NODE_RANGE}.\n`,
  );
  process.exitCode = 1;
}
