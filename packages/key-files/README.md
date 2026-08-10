# `@kavrix/key-files`

This internal adapter applies filesystem safety to the canonical portable-key
formats from `@kavrix/crypto`. Callers choose the protected or unprotected codec
explicitly and provide passphrases as mutable bytes, never normal command
arguments.

Reads are bounded to 16 KiB and verify the opened file's identity, type, link
count, ownership, and permissions before returning codec output. Unix requires
the current UID and a permission subset of `0600`, with no execution or special
bits. Windows requires a protected DACL containing only the current user and, if
present, Local System; inherited, group, and world grants fail closed.

Writes stage a user-only same-directory file, flush its contents, and publish it
atomically. Create-new uses an atomic hard link because Node does not expose a
portable no-replace rename; it never falls back to a racy copy. Explicit
replacement uses a cooperative cross-process lock, revalidates the old file,
and atomically renames the staged file. Directory metadata is flushed where the
platform supports directory handles.

On Windows, writes also require a protected containing-directory DACL with an
inheritable current-user-only rule. The adapter validates this before creating
the empty staging file, so no other account can retain a read handle before the
file receives its final direct DACL and secret content. It fails closed rather
than copying into another directory or briefly relying on a broad inherited ACL.

Replacement locks are deliberately not expired or removed automatically: age
cannot prove that another writer is dead. A stale lock returns
`KEY_FILE_BUSY` and leaves both the target and lock unchanged. An operator may
remove the empty `.kavrix-<digest>.lock` only after independently establishing
that no Kavrix process is writing that target.

The Windows ACL implementation uses the operating system's PowerShell/.NET ACL
APIs with a fixed encoded script, `shell: false`, bounded output, and no secret
data in arguments, output, or errors. The child receives only `SystemRoot`,
`WINDIR`, and a dedicated non-secret target-path environment variable; it does
not inherit the parent environment. Paths are never included in public error
messages. The executable and child system-root values are pinned to the supported
`C:\Windows` installation and never resolved from caller-controlled environment
variables or `PATH`; non-default Windows installation roots fail closed until a
trusted native system-directory resolver is implemented.
