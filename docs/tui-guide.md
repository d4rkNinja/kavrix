# Terminal output

Kavrix currently uses Commander output and sanitized terminal rendering rather
than an interactive Ink TUI. Values are masked by default; plaintext display
requires an explicit command guard such as \`get --reveal\`.

Terminal-rendered content is treated as hostile. Control, ANSI, and OSC
sequences are sanitized before display, and non-interactive flows remain
ANSI-free.

The historical TUI package is not included in the public npm artifact.
