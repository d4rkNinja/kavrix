# Native platform acceptance gate design (#53)

## Goal

Provide one explicit, opt-in command for real operating-system acceptance of
the native keychain, protected key-file filesystem policy, and secure clipboard
boundary. The command must run the real adapters on the current OS, reject
unexpected skips, and never replay child output.

## Current gaps

- `packages/keychain/test/native-keychain.integration.test.ts` already guards
  four real Credential Manager/Keychain/Secret Service tests with
  `KAVRIX_KEYCHAIN_INTEGRATION=1`.
- `packages/clipboard/integration/system-clipboard.integration.ts` already
  guards a snapshot/copy/compare-clear/restore test with two explicit flags,
  but the default Vitest include does not discover its `.integration.ts` file.
- `packages/key-files` has strong platform-specific unit coverage, but no
  opt-in real-platform integration file or package command that records a
  production filesystem acceptance run.
- There is no single gate that requires all opt-in flags and proves that every
  selected file ran without skips or pending tests.

## Chosen approach

Add a root `platform:acceptance` command backed by a small TypeScript gate and
an explicit `vitest.platform.config.ts`. The gate requires these non-secret
opt-in values before it can spawn Vitest:

```text
KAVRIX_KEYCHAIN_INTEGRATION=1
KAVRIX_KEY_FILE_INTEGRATION=1
KAVRIX_CLIPBOARD_INTEGRATION=1
KAVRIX_CLIPBOARD_EXCLUSIVE_SESSION=1
```

It passes the values only through the child environment, invokes the pinned
workspace Vitest entry with `shell: false`, explicit integration files, JSON
reporting, bounded output, and a finite timeout, then validates exact file
coverage and all-passed/no-skip counts. Failure output is one generic line.
The gate is intentionally not part of the ordinary unit suite because it
temporarily writes to the user's clipboard and touches real OS credential
stores.

The new key-file integration test writes a generated unprotected portable key
inside a temporary protected directory, reads it back, and then proves that a
second hard link and a broadened platform permission/ACL are rejected. It wipes
owned key buffers and removes its temporary path. Existing keychain and
clipboard integration tests remain the source of truth for native API
round-trips, compare-before-clear, clipboard restoration, and cleanup.

## Alternatives rejected

1. Rename the clipboard file so the ordinary unit glob picks it up. This would
   make a clipboard-mutating test run without the explicit exclusive-session
   consent and could overwrite a user's clipboard during `pnpm test`.
2. Add only another shell snippet to CI. That would not validate report
   completeness and would duplicate secret-sensitive child-process policy.
3. Treat the existing platform-specific unit tests as acceptance. They prove
   adapter behavior with test doubles and local OS helpers, but cannot prove a
   real Credential Manager/Keychain/Secret Service or desktop clipboard.

## Failure and security behavior

- Missing or blank opt-in flags fail before file discovery or child spawn.
- Missing files, malformed JSON, zero tests, pending/todo/failed tests, skipped
  tests, and report/file drift all fail closed.
- Child output is bounded and never printed; command arguments contain no
  secret-bearing values, and `shell: false` is asserted by tests.
- Clipboard acceptance requires an exclusive session because it snapshots and
  temporarily replaces user clipboard content; it restores only content still
  attributable to the test.
- A failed native gate is recorded as an unavailable platform prerequisite, not
  as a passing support claim.

## Scope boundary

This issue adds the opt-in gate and key-file acceptance coverage. It does not
claim that the current managed Windows desktop/credential store is usable, add
platform emulators, enable an OS matrix in ordinary CI, or change cryptography,
keychain fallback policy, ACL policy, or clipboard semantics.
