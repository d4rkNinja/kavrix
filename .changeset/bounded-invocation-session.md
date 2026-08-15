---
'kavrix': minor
---

Bound every unlocked invocation to a session that guarantees secrets are cleared.

One `InvocationSession` owns the deadlines, the abort signal that cancellable work
is threaded onto, and the ordered release stack. Release steps run exactly once in
reverse acquisition order for every ending — normal completion, thrown error,
invocation timeout, inactivity timeout, and `SIGINT`/`SIGTERM`/`SIGHUP` — so a
decrypted root key, an open SQLite store, a protected backend, and a clipboard
entry can no longer outlive the command that acquired them. Interrupting an
unlocked command previously killed the process without running any of that
teardown.

Expiry is measured on an injectable monotonic clock rather than wall-clock time,
so changing the system clock cannot extend a session, and a backward reading fails
closed. Work that stops making progress is abandoned rather than waited on, so a
command blocked on a socket, a pipe, or a prompt cannot hold a session open past
its deadline; its resources are still released because they live on the session's
stack. A result that arrives after a deadline lapsed is refused instead of being
rendered as an unlocked outcome.

Deadlines default to a 15-minute invocation limit, a 2-minute inactivity limit,
and a 2-minute reauthentication window, and operators may override them with
`CREDS_SESSION_TIMEOUT_MS`, `CREDS_SESSION_IDLE_TIMEOUT_MS`, and
`CREDS_REAUTH_WINDOW_MS`. These are policy, not secrets. A malformed,
out-of-bounds, or internally inconsistent value fails closed with a usage error
before any vault is opened, and the rejected value is never echoed back.

A session that ends before its command finishes exits `1` and names why —
`SESSION_TIMEOUT`, `SESSION_IDLE_TIMEOUT`, `SESSION_INTERRUPTED`,
`SESSION_TERMINATED`, or `SESSION_CLOCK_UNUSABLE` — so an interrupted run is
distinguishable from a failed one without widening the documented exit-code
taxonomy.

Cleanup is cooperative and in-process: `SIGKILL` and host power loss bypass it,
and a handle held open outside the session can delay process exit after the
session has released its own resources.
