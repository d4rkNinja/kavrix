import * as nodeCrypto from 'node:crypto';

/**
 * The Node range this build supports, mirroring `engines.node`.
 *
 * The floor is an API floor, not a preference. `crypto.argon2` — the primitive
 * behind every passphrase key slot — was added in v24.7.0 and does not exist in
 * any 22.x release. `DatabaseSync.enableDefensive`, which the local store relies
 * on to refuse SQL that can corrupt the on-disk schema, landed on main in
 * v25.1.0 and was backported to v24.12.0. Node 25.0.x therefore falls in a real
 * gap: it is newer than the 24.x backport yet older than the release that
 * carries the change forward, so it is excluded rather than approximated.
 *
 * There is deliberately no upper bound. Both `crypto.argon2` and `node:sqlite`
 * are release-candidate APIs, so the honest guard against a future breaking
 * change is the capability probe below, which fails closed on the specific
 * primitive that went missing. An engine ceiling cannot express that; all it
 * would do is block installation on every Node released after this package.
 */
export const SUPPORTED_NODE_RANGE = '>=24.12.0 <25 || >=25.1.0';

export class CliUnsupportedRuntimeError extends Error {
  readonly code = 'CLI_UNSUPPORTED_RUNTIME' as const;
  readonly safe = true;

  constructor(reason: string) {
    super(`${reason} CredVault requires Node ${SUPPORTED_NODE_RANGE}.`);
    this.name = 'CliUnsupportedRuntimeError';
  }
}

type NodeVersion = Readonly<{ major: number; minor: number; patch: number }>;

/**
 * Parses the numeric core of a Node version, ignoring any pre-release or build
 * suffix. A nightly such as `26.0.0-pre` is judged on `26.0.0`.
 */
function parseNodeVersion(value: string): NodeVersion | null {
  const match = /^(\d+)\.(\d+)\.(\d+)(?:[-+].*)?$/u.exec(value);
  if (match === null) return null;
  const [major, minor, patch] = match.slice(1, 4).map(Number);
  if (
    major === undefined ||
    minor === undefined ||
    patch === undefined ||
    !Number.isSafeInteger(major) ||
    !Number.isSafeInteger(minor) ||
    !Number.isSafeInteger(patch)
  ) {
    return null;
  }
  return { major, minor, patch };
}

export function isSupportedNodeVersion(value: string): boolean {
  const version = parseNodeVersion(value);
  if (version === null) return false;
  // >=24.12.0 <25
  if (version.major === 24) return version.minor >= 12;
  // >=25.1.0, and every later major
  if (version.major === 25) return version.minor >= 1;
  return version.major > 25;
}

/**
 * Rejects a runtime this build cannot honor, before any command touches key
 * material.
 *
 * The version range and the capability probe are both required and neither
 * subsumes the other: a version check alone trusts a self-reported string, and
 * a capability check alone would accept a runtime whose Argon2 exists but
 * predates a fix this code depends on. The probe reads a property rather than
 * computing a hash so that metadata-only commands stay fast, and touches only
 * `node:crypto` — importing `node:sqlite` here would print an experimental
 * warning to stderr on every invocation.
 */
export function assertSupportedRuntime(
  nodeVersion: string = process.versions.node,
  capabilities: Readonly<Record<string, unknown>> = nodeCrypto,
): void {
  if (!isSupportedNodeVersion(nodeVersion)) {
    throw new CliUnsupportedRuntimeError(`Unsupported Node runtime v${nodeVersion}.`);
  }
  for (const primitive of ['argon2', 'argon2Sync'] as const) {
    if (typeof capabilities[primitive] !== 'function') {
      throw new CliUnsupportedRuntimeError(
        `This Node build is missing crypto.${primitive}, so passphrase key slots cannot be derived.`,
      );
    }
  }
}
