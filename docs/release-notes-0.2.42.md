# Release notes — 0.2.42 responsive TUI and consistent agent discovery

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

Loading indicators now honor reduced motion. Resize bursts coalesce over 32 ms
using the latest dimensions; pending work cancels on unmount, and onboarding
ignores unchanged sizes. Input readiness waits for the resized frame, and pointer
reports are discarded while layout work is pending instead of acting on old
coordinates. Tests cover actual mounted pointer streams, resize bursts, and
hold cleanup, including an update that schedules another resize.

Agent run now discovers a project file when its optional config path is omitted,
matching the TUI workflow. Agent run, agent exec dry-run, and project-aware run
share discovery of one `kavrix.yaml`, `kavrix.yml`, or `kavrix.json` in the working
directory. Multiple defaults require `--config <path>`. Invalid or unreadable
files fail closed; they do not fall back to another configuration. Tests cover
all default formats, absence, malformed files, ambiguity, explicit selection,
and consistent agent run/exec validation without unlock.

The [agent guide](agent-guide.md) separates configuration validation from runtime
authorization, explains permission names and injection mapping, and documents
broker limits and the TUI's scope. Getting started requests the same permission
key it declares in YAML, and CLI help describes discovery.

Windows packed acceptance has a 75-minute CI budget because hosted native
protected-file checks and packed command journeys exhausted the old 45-minute
job allowance. Every check, runtime CLI deadline, security assertion, and coverage
threshold remains mandatory. Earlier candidates were never tagged or published.

No encrypted storage formats or cryptographic parameters change. Publication
requires the complete gates in the [release procedure](release.md).

The Windows local preflight passed 2,092 tests with 21 environment-gated skips;
coverage was 86.67% statements, 80.24% branches, 91.04% functions, and 88.22%
lines, with unchanged thresholds. Build, formatting, lint, type checks, packed
smoke, both packed acceptance suites, package inspection, and audit passed.
Skipped tests do not establish live transactional MongoDB behavior. Exact-commit
CI/CodeQL and trusted publication remain release gates.
