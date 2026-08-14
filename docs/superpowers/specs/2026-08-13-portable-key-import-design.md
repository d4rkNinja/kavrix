# Protected portable-key import design

## Scope

Issue #33 composes the existing canonical portable-key file parser into the
production initialization path. A fresh `creds init --key-file <path>` accepts
either an unprotected or passphrase-protected v1 file, but requires the file's
binding to be `unbound`; a bound file belongs to a later recovery flow and must
not be silently repurposed as a new-vault credential.

## Input and lifecycle

1. Validate the path and source combination before reading the file.
2. Try the guarded unprotected reader with expected binding `{ kind: 'unbound' }`.
3. If the safe file is structurally a protected/otherwise cryptographically
   unreadable document, acquire one masked passphrase or one explicit stdin
   frame and retry through the protected reader with the same binding.
4. Format the parsed key only long enough to pass it to the existing
   initialization coordinator; wipe parsed key bytes and passphrase bytes in
   `finally` blocks. Filesystem safety errors never trigger a passphrase retry.
5. If the passphrase is read as a stdin frame, the later portable/recovery
   confirmation frames are read from the same bounded incremental frame reader,
   requiring EOF after the final frame.

The protected reader never returns file bytes, plaintext key bytes, or the
passphrase to the renderer or durable stores. The coordinator remains the owner
of locally parsing and authenticating the formatted key against the newly
created vault's encrypted envelope.

## CLI contract

`creds init --key-file <path>` keeps the existing masked passphrase behavior.
`--key-file-passphrase-stdin` opts into one leading passphrase frame when the
file is protected; with `--confirmation-stdin`, the portable and recovery
confirmation frames follow it. The flag is rejected for other initialization
sources and never accepts a passphrase as a normal option value.

## Verification

Focused tests cover unbound binding enforcement, protected/unprotected reader
selection, wrong passphrase and filesystem-error handling, byte wiping, staged
stdin framing, and the production initialization composition. Existing
key-files adversarial tests remain the source of truth for links/reparse points,
permissions, size bounds, malformed headers, and authenticated file contents.
