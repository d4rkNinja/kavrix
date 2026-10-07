# Release notes — 0.2.43 precise agent denials

Agent and live permission lookups now require an explicitly declared map entry.
Inherited names such as `constructor`, `toString`, and `valueOf` do not count as
configured agents or permissions. Undeclared agent names return the stable
invalid-configuration error and exit code 14 instead of an internal TypeError.
Explicitly declared names remain supported; no new identifier is reserved.

Unknown and `deny: true` permissions are denied before executable resolution or
hashing. A missing executable therefore cannot turn a policy denial into a spawn
failure or prevent the denial audit record. The broker keeps its existing deny
frame, exit code, counter, and sealed audit contract. Rejected requests avoid
filesystem work; no measured latency improvement is claimed.

Regression tests exercise inherited agent names, explicitly declared names,
unknown live permissions, explicit deny with an unresolved executable, and
persisted denial audit events. The existing full-path command audit assertion
remains intact. No cryptographic or encrypted storage format changes.

Publication requires the complete [release gates](release.md). This version
retains the responsive TUI, bounded sessions, batched snapshots, consistent
project discovery, and concurrent agent requests described in the
[0.2.42 notes](release-notes-0.2.42.md),
[TUI guide](tui-guide.md), and [agent guide](agent-guide.md).

Local preflight passed formatting, linting, type checking, build, package smoke
and content inspection, both packed CLI acceptance flows, and dependency audit.
The coverage run passed 2,100 tests across 166 test files, with 21
environment-dependent tests skipped. Coverage was 86.66% statements, 80.25%
branches, 91.04% functions, and 88.21% lines; existing thresholds were preserved.
