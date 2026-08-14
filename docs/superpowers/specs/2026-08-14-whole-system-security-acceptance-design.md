# Whole-system plaintext canary and hostile terminal acceptance design (#49)

## Goal

Prove that a runtime-generated sensitive canary stays out of every durable or
observable surface exercised by the packed CLI acceptance journey, and that
hostile terminal control content cannot execute or corrupt rendered output.
The gate must cover the real local vault, encrypted HTTP fixture, encrypted
backup, command arguments/environment, stdout/stderr, completion, logs, and
clipboard cleanup without weakening the zero-knowledge boundary.

## Architecture

The existing command-only acceptance harness is the right integration seam: it
uses the production CLI composition, protected test-owned native keychain,
real SQLite local stores and journals, the encrypted opaque HTTP control-plane
fixture, and the guarded clipboard port. Issue #49 strengthens that flow with
a per-run high-entropy canary and one scanner that checks raw bytes plus the
documented encoded representations. The scanner reports only a surface,
encoding, and a non-reversible fingerprint when it fails.

The live MongoDB canary scan remains owned by the real source/archive/isolated
restore gate added for #48. This issue does not add a CLI MongoDB adapter or
move raw MongoDB credentials across the CLI boundary; the status document will
map that separate live gate explicitly.

Terminal hardening is implemented in both the CLI boundary sanitizer and the
shared TUI text sanitizer. They consume 8-bit C1 CSI/string commands, including
OSC/DCS/SOS/PM/APC, and make Unicode line-separator controls visible or safe.
The tests exercise 7-bit and 8-bit forms, terminated and unterminated payloads,
bidi controls, and line controls.

## Acceptance flow

1. Generate a unique canary at test runtime and initialize the real CLI flow.
2. Create, mutate, sync, show, copy, lock, reopen, update, archive, restore,
   and read a credential through the existing encrypted control plane.
3. Create and verify a local encrypted backup, run shell completion, and
   collect command arguments/environment/output, captured logs, HTTP bodies,
   clipboard state after lock/disposal, all home-directory bytes, and archive
   bytes.
4. Scan each surface for the canary in UTF-8, UTF-16LE, Base64, Base64url,
   JSON-escaped, and direct substring forms. Assert that redacted output,
   transport payloads, SQLite/journal/key-file/temp/backup artifacts, and
   completion are canary-free.
5. Run the focused CLI/TUI terminal tests and affected package gates. If the
   configured Mongo replica set is unavailable, retain #48's explicit
   environment blocker instead of claiming a live database result.

## Security and failure coverage

- The scanner never includes the canary value in assertion messages.
- The canary is generated after the test module loads and is not committed as
  a fixture or written to a file intentionally.
- Clipboard bytes are copied only into the test-owned guarded adapter and are
  wiped on lock/disposal; the post-flow scan checks that no copy remains.
- Existing initialization output for explicitly acknowledged portable and
  recovery material remains an intentional guarded allowlist; the credential
  canary is never allowlisted.
- Sanitizers replace or remove hostile terminal controls before rendering and
  preserve only escaped line delimiters where the CLI contract requires them.

## Out of scope

The TUI remains out of the packed CLI acceptance journey, and this issue does
not expose new commands, alter cryptographic envelopes, change Mongo schemas,
or publish/close GitHub work.

## Verification

Run the focused CLI boundary, TUI sanitizer, and basic acceptance suites, then
run affected typecheck/build/lint/format/diff gates. Record the exact Mongo
environment prerequisite and any package-smoke ACL limitation in the final
status when those external prerequisites are absent.
