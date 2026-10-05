# Release notes — 0.2.38 responsive TUI and list shortcuts

The main Ink TUI now supports Home/End for first/last row selection and Page
Up/Page Down for faster list navigation. Credential page size follows terminal
height and the space occupied by a revealed field. Selection stays within the
current search results, including an empty result. Home supports these shortcuts
for destination selection. Input and confirmation overlays retain control of
keyboard actions.

The app skips state updates and mouse-frame invalidation when the router returns an
unchanged state without an effect. Duplicate terminal sizes preserve that state.
Reveal countdown frames update once per displayed second instead of four times
per second. Expiry still checks every 250ms and clears the displayed value at the
first tick at or after the deadline. A new reveal initializes its display clock
immediately, avoiding an incorrect initial countdown. Completed or failed initial
loads release their eight-second timeout immediately.

First-paint watchdogs, navigation/resize chrome remounts, masked input, explicit
reveal confirmation, encryption, and protected-file checks remain in place.
This release adds no runtime dependency or OS-specific executable.

Mounted app input readiness also waits for Ink to flush pending output before
reporting registered pointer regions. This keeps terminal resize and setup
automation coordinates aligned with the displayed frame without fixed delays.

CI also exposed an agent-broker pipe-close race on macOS x64. The relay now owns
child stdin errors before flushing queued input. A closed input pipe stops
forwarding and releases backpressure while output and the actual child exit
continue to be observed. Unexpected input failures terminate the connection with
a generic error; underlying diagnostics are never forwarded. Regression coverage
uses a real broker, client, and child, plus deterministic stream-error injection
to cover both outcomes and a diagnostic canary.

Regression tests cover terminal key-sequence decoding in a mounted Ink session,
large and filtered lists, terminal height, empty results, overlay isolation,
duplicate resize reports, countdown frame suppression, and expiry clearing.
The existing terminal-restoration, mouse, first-paint, and layout suites remain
release gates. Native Windows, macOS, and Linux CI on the exact commit is required
before tagging; local Windows checks alone do not establish other OS behavior.
See the [canonical release procedure](release.md).

Responsiveness still depends on the terminal and datastore. Timers can be delayed
by a blocked event loop, and JavaScript cannot guarantee erasure of string copies.
No claim is made that every OS or terminal supports an interactive TUI.
