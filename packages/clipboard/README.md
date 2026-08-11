# `@kavrix/clipboard`

Internal secure clipboard adapter for already-authorized UTF-8 secret bytes.

The adapter selects only supported native command paths: Windows PowerShell and
Windows Forms clipboard APIs, macOS `pbcopy`/`pbpaste`, Wayland
`wl-copy`/`wl-paste`, or X11 `xclip`/`xsel`. Secret bytes are written only to a
child's piped stdin. They are never placed in argv, environment variables,
URLs, persistence, logs, or error messages.

Timed and lock-triggered clears first read and fingerprint the current clipboard
and clear only the still-matching Kavrix generation. A newer Kavrix copy is
protected by serialized operations and generation tokens. New external content
observed during the comparison is preserved.

`clearAfterMs` is the requested time of the first guarded clear attempt, not a
guaranteed completion time. A transient native failure is retried at 100, 200,
and 400 ms, with no more than four total attempts and no retry started after the
700 ms monotonic cleanup deadline. Every retry re-reads and compares the
clipboard; replacement content ends cleanup without being cleared. An in-flight
native attempt may finish after the deadline, subject to its own command timeout.
The copy receipt reports the requested delay, retry deadline, and attempt bound
separately. If all attempts fail, retry state and fingerprints are wiped and a
generic background error is available through `takeBackgroundError()`.

## Limitations

- Clipboard managers, accessibility tools, remote-desktop software, malware,
  screenshots, and other processes may retain copied plaintext independently.
- Process and JavaScript buffer clearing is best effort; OS and native copies
  cannot be guaranteed zeroized.
- External applications can change the clipboard between the final comparison
  and the OS clear command because the supported command-line APIs provide no
  portable atomic compare-and-clear operation. The window is minimized, but a
  formal no-race guarantee against unrelated processes is impossible.
- Linux requires an active Wayland or X11 session and one supported tool pair
  installed under `/usr/local/bin`, `/usr/bin`, or `/bin`. `PATH` is deliberately
  ignored; nonstandard install locations and headless sessions fail closed.
- Windows requires the inbox Windows PowerShell executable at the fixed trusted
  `C:\Windows` installation, an STA-capable interactive session, and the Windows
  Forms clipboard assembly. Non-default Windows installation roots fail closed.
- The real-clipboard integration test is opt-in because it temporarily replaces
  user clipboard content. It requires both
  `KAVRIX_CLIPBOARD_INTEGRATION=1` and
  `KAVRIX_CLIPBOARD_EXCLUSIVE_SESSION=1`. It restores the in-memory snapshot
  only while the test still owns the clipboard; newer user content is preserved
  instead.
