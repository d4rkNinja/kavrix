# Terminal output and Ink showcase

The public `kavrix` CLI uses Commander for command parsing and sanitized
terminal rendering. Values are masked by default; plaintext display requires an
explicit guard such as `get --reveal`. Non-interactive output is ANSI-free.

The active `@kavrix/tui` workspace provides the Ink 7.1.1 / React 19.2.8
storage-selection showcase used by the interactive onboarding helper. It is a
presentational boundary only: its strings are static and it has no persistence,
cryptographic, or secret-input authority. The CLI loads it lazily, and the
non-TTY path retains the numbered storage-selection fallback.

The current no-argument TTY `kavrix init` path uses a plain terminal helper,
not the Ink showcase. It creates a local encrypted database, default vault, and
recovery kit, verifies recovery, and only then selects the profile. The
non-secret `~/.kavrix/config.toml` reference is not loaded automatically.
The showcase remains part of the active build/test boundary for explicit
storage-selection presentation. The final selection stores only an
authenticated opaque default vault ID for that profile; an explicit
`--vault` continues to override it.

Masked interactive prompts render textual requirement, success, and error
markers and retry a locally invalid field without discarding unrelated answers.
A passphrase-confirmation mismatch retries the pair. Color is supplemental,
appears only on a capable TTY, and is disabled by `NO_COLOR` or `TERM=dumb`;
protected stdin remains silent and ANSI-free.

Terminal-rendered content is treated as hostile. Control, ANSI, and OSC
sequences are sanitized before display, and secret values are never rendered by
the showcase.
