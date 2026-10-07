# Release notes — 0.2.43 agent discovery and responsive resize

Agent run now discovers a project file when the optional config path is omitted,
matching the TUI's documented workflow. Agent run, agent exec dry-run, and
project-aware run share discovery of one `kavrix.yaml`, `kavrix.yml`, or
`kavrix.json` in the working directory. Multiple defaults require an explicit
`--config` path. Invalid or unreadable files fail closed; discovery no longer
swallows validation failures or treats all read failures as absence.

Loading indicators now honor reduced motion. Terminal resize bursts coalesce
over 32 ms using the latest dimensions, pending work cancels on unmount, and
onboarding no longer remounts chrome for unchanged sizes. Existing first-paint,
keyboard, protected-input, and mouse readiness behavior remains required.
Readiness waits for the resized frame; pending-layout pointer reports are
discarded, and resize input holds release on delivery or unmount.

The new [agent guide](agent-guide.md) separates configuration validation from
runtime authorization, explains the exact permission names and injection mapping,
and documents broker limits and the TUI's scope. Getting started now requests
the same permission key it declares in YAML. CLI help describes discovery.

Tests cover default formats, absence, malformed files, ambiguous defaults,
explicit selection, agent run/exec consistency without unlock, reduced-motion
loading, mounted list clock cleanup, resize bursts, and cancellation on unmount.
No encrypted formats or cryptographic parameters change. Multiple-default
projects must now select explicitly instead of relying on precedence.

These changes establish behavior, not measured end-to-end latency. Publication
requires the complete [release gates](release.md).

After correcting the resize/readiness regression, the clean Windows preflight
passed 2,092 tests with 21 environment-gated skips. Coverage passed unchanged
thresholds: 86.67% statements, 80.24% branches, 91.04% functions, and 88.22%
lines. Build, formatting, lint, type checks, packed smoke, both acceptance suites,
package inspection, and audit passed. Skipped integration tests do not establish
live transactional MongoDB behavior. Exact-commit CI/CodeQL and trusted
publication remain release gates.
