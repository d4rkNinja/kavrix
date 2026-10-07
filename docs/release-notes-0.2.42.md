# Release notes — 0.2.42 terminal animation lifecycle

Finished entrance and list-stagger animations now unsubscribe from the shared
32 ms clock. If nothing continuous remains, the timer stops while the screen
stays mounted. Splash wordmark reveal also stops at its final frame; loading
elapsed seconds derive from the spinner's existing cadence rather than a second
per-frame state update. Keyboard selection, reveal deadlines, and authentication
requirements are unchanged.

Regression tests check exact final frames, automatic timer cleanup, simultaneous
finite and continuous animations, zero-duration settlement, and removal during
tick delivery. A mounted Ink test checks that an entrance releases its timer
without unmounting. These prove timer behavior, not measured terminal latency.

The [TUI guide](tui-guide.md) now provides an existing-vault walkthrough and
PowerShell/POSIX reduced-motion troubleshooting. Getting started identifies
which tasks require CLI commands; it no longer claims every workflow exists
inside the TUI. Agent is configuration dry-run, not a live broker dashboard.

No encrypted storage formats or cryptographic parameters change. Publication
requires the complete gates in the [release procedure](release.md).

The Windows local preflight passed 2,074 tests with 21 environment-gated skips;
coverage was 86.68% statements, 80.25% branches, 91.04% functions, and 88.23%
lines, with unchanged thresholds. Build, formatting, lint, type checks, packed
smoke, both packed acceptance suites, package inspection, and audit passed.
Skipped tests do not establish live transactional MongoDB behavior. Exact-commit
CI/CodeQL and trusted publication remain release gates.
