import { PortableKeyFileError } from './errors.js';
import {
  prewarmWindowsAclHelper as prewarmWindowsAclHelperProcess,
  runWindowsAclRequest,
  type WindowsAclOperation,
  type WindowsAclReply,
} from './windows-acl-process.js';

const ACL_RETRY_ATTEMPTS = 3;
const ACL_RETRY_BASE_DELAY_MS = 75;

/**
 * Serializes ACL mutations and their verification so concurrent callers cannot
 * interleave a hardening step with somebody else's check. The helper itself
 * serves one request at a time, so this queue is what makes each
 * verify-then-act sequence atomic with respect to other callers.
 */
let windowsAclQueue: Promise<void> = Promise.resolve();

/**
 * Applies the caller's retry policy to one protected-path request.
 *
 * Only transport failures are retried: an interpreter that could not start, a
 * helper that died, a timeout, or a malformed reply. A refused verification is
 * a statement about the filesystem that no retry can change, so re-reading the
 * security descriptor the same way only multiplied the cost of already-failing
 * operations by three. Verdicts are therefore terminal and transport failures
 * keep the historical retry budget.
 */
async function requestAcl(
  operation: WindowsAclOperation,
  targetPath: string,
): Promise<WindowsAclReply> {
  let lastError: unknown;
  for (let attempt = 0; attempt < ACL_RETRY_ATTEMPTS; attempt += 1) {
    try {
      return await runWindowsAclRequest(operation, targetPath);
    } catch (error) {
      lastError = error;
      if (attempt + 1 < ACL_RETRY_ATTEMPTS) {
        await delay(ACL_RETRY_BASE_DELAY_MS * (attempt + 1));
      }
    }
  }
  throw lastError instanceof Error
    ? lastError
    : new PortableKeyFileError('KEY_FILE_UNSAFE');
}

function withWindowsAclLock<T>(operation: () => Promise<T>): Promise<T> {
  const run = windowsAclQueue.then(operation, operation);
  windowsAclQueue = run.then(
    () => undefined,
    () => undefined,
  );
  return run;
}

/** Turns any non-acceptance into the single generic unsafe-file error. */
function requireAccepted(reply: WindowsAclReply): void {
  if (!reply.ok) throw new PortableKeyFileError('KEY_FILE_UNSAFE');
}

async function delay(ms: number): Promise<void> {
  await new Promise<void>((resolve) => {
    setTimeout(resolve, ms);
  });
}

/**
 * Hardens one Kavrix-owned file or directory so only the current user can read
 * or write it. An already-hardened object is left alone, because a second
 * owner-setting operation can be rejected on Windows.
 */
export async function setWindowsUserOnlyAcl(targetPath: string): Promise<void> {
  await withWindowsAclLock(async () => {
    try {
      requireAccepted(await requestAcl('verify-user-only', targetPath));
      return;
    } catch {
      // Only rewrite the ACL when verification shows that it is needed.
    }
    requireAccepted(await requestAcl('set', targetPath));
    requireAccepted(await requestAcl('verify-user-only', targetPath));
  });
}

/**
 * Verifies that one Kavrix-owned file or directory is protected: inheritance
 * disabled, owned by the current user, and free of any grant to another
 * principal. Directories may additionally rely on inheritable rights so their
 * children inherit equivalent protection.
 */
export async function verifyWindowsUserOnlyAcl(targetPath: string): Promise<void> {
  await withWindowsAclLock(async () => {
    requireAccepted(await requestAcl('verify-user-only', targetPath));
  });
}

/**
 * Verifies an existing directory's effective writable principals without
 * mutating its ACL. Inherited read grants are allowed, but write or control
 * grants are restricted to the current user, SYSTEM, and built-in
 * Administrators.
 */
export async function verifyWindowsDirectoryAcl(targetPath: string): Promise<void> {
  await withWindowsAclLock(async () => {
    requireAccepted(await requestAcl('verify-parent-dir', targetPath));
  });
}

/**
 * Starts the helper interpreter before any path needs verification, so its
 * start-up cost overlaps argument handling and key derivation instead of
 * sitting on the critical path of the first protected-file operation.
 *
 * This is a pure warm-up: it never verifies anything, never reports success,
 * and cannot turn a later failure into success. If the helper cannot start
 * here, the first real request starts it again and surfaces the failure
 * through the normal fail-closed path.
 */
export function prewarmWindowsAclHelper(): void {
  if (process.platform !== 'win32') return;
  // Documented runner opt-out: warm-up is a pure latency optimization, so
  // test suites may suppress the concurrent interpreter boot without any
  // effect on verification outcomes, which still fail closed on request.
  if (process.env['KAVRIX_SKIP_ACL_PREWARM'] === '1') return;
  prewarmWindowsAclHelperProcess();
}
