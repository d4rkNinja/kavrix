# Terminal output and Ink showcase

The public `kavrix` CLI uses Commander for command parsing and sanitized
terminal rendering. Values are masked by default; plaintext display requires an
explicit guard such as `get --reveal`. Non-interactive output is ANSI-free.

The active `@kavrix/tui` workspace provides the Ink 7.1.1 / React 19.2.8
storage-selection showcase used by the interactive onboarding helper. It is a
presentational boundary only: its strings are static and it has no persistence,
cryptographic, or secret-input authority. The CLI loads it lazily, and the
non-TTY path retains the numbered storage-selection fallback.

The 0.2.3 no-argument TTY `kavrix init` path now creates the non-secret
`~/.kavrix/config.toml` onboarding reference and does not initialize a vault,
invoke the showcase, or load edited settings automatically. The showcase
remains part of the active build/test boundary for the
interactive storage-selection path; it is not a replacement for the canonical
profile → `db init` → `db vault create` setup.

Terminal-rendered content is treated as hostile. Control, ANSI, and OSC
sequences are sanitized before display, and secret values are never rendered by
the showcase.
