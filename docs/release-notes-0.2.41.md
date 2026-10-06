# Release notes — 0.2.41 bounded TUI sessions and concurrent agent requests

Browse now loads one authenticated hierarchy snapshot instead of launching up to
421 context/service/item listing processes. Scripts can use
`kavrix context list --tree --json`; truncated previews are reported explicitly.
The splash dismisses as soon as the backend is ready, with no minimum animation
wait. Agent dry-run no longer forwards passphrases or connection input it does
not consume.

`kavrix policy snapshot --json` reads policies, grants, and audit from one
authenticated, read-only sidecar snapshot. The TUI renders all three together;
failures do not become a successful empty audit view.

For bound database profiles, common TUI operations reuse authenticated keys.
Storage opens per action and closes afterward, releasing local writer locks
between actions. Each reuse checks protected key-file content and permissions,
profile binding, database/vault authentication, and the rollback anchor. Keys and
retained unlock buffers expire after two minutes without backend actions or
fifteen minutes since unlock. Navigation alone does not renew the idle deadline.
Profile changes, failures, and exit dispose the session. Administrative child
commands invalidate reusable keys; legacy standalone profiles keep their existing
command route. In-progress operations settle before cleanup. Copy and reveal
still enforce reveal policy and explicit UI confirmation.

The agent broker admits up to four concurrent requests, each with isolated socket
framing and child I/O. A 32-request queue and ten-second admission deadline bound
overload. Confirmation prompts and sealed audit writes remain serialized. Stdout
and stderr are drained concurrently to avoid full-pipe stalls. Denials, pins,
working-directory restrictions, and execution windows remain checked per request.

No encrypted vault, key-file, recovery-kit, profile, or authorization envelope
format changed. Argon2id parameters are unchanged. JavaScript cannot guarantee
erasure of string copies, and an unlocked host remains outside the protection
boundary. Operation-count improvements are verified by tests; no end-to-end
latency promises are made. See [performance](performance.md), [TUI behavior](tui-guide.md),
and the [release procedure](release.md). Publication is claimed only after the
exact-commit CI/CodeQL, trusted npm workflow, registry integrity, and GitHub
release gates succeed.

The development-only Vitest and coverage packages are updated to 4.1.11 to
address the mocker path-traversal advisory. Published runtime dependencies are
unchanged.

Legacy local-file replacement now tolerates transient Windows `EPERM` sharing
denials with at most sixteen attempts and three seconds of backoff. Both target
and staged file identities and permissions are checked on every attempt;
the target's read-time metadata snapshot must also remain unchanged, so inode
reuse and in-place writes fail closed alongside substitution and permanent
denial. This follows the existing
protected key-file replacement behavior. Tests cover retry, substitution,
exhaustion, cleanup, and preservation of committed ciphertext.
