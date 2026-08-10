# CLI reference

Kavrix is not published. The public-package build produces a `creds` executable,
but its installed command surface is intentionally limited to production-backed
local operations. Vault operations exist in a separately tested,
dependency-injected catalog in the repository; the packed executable does not
compose or expose them.

This distinction is security-relevant: a command listed as "catalog only" below
is not usable from the current public executable.

## Public-package executable

The packed executable reads no vault, keychain, network, clipboard, or MongoDB
state. Local generation uses the production cryptographic RNG, TOTP consumes a
locally supplied seed, and `key create` writes one protected or unprotected
portable-key file. Its current surface is:

| Command                                    | Status                         | Behavior                                                                                          |
| ------------------------------------------ | ------------------------------ | ------------------------------------------------------------------------------------------------- |
| `creds`                                    | Available in the built package | Prints help.                                                                                      |
| `creds --help`                             | Available in the built package | Prints static help.                                                                               |
| `creds --version`                          | Available in the built package | Prints package version `0.1.0`.                                                                   |
| `creds version`                            | Available in the built package | Prints package version `0.1.0`.                                                                   |
| `creds completion <shell>`                 | Available in the built package | Prints static top-level completion for `bash`, `zsh`, `fish`, or `powershell`.                    |
| `creds generate password [options]`        | Available in the built package | Generates one policy-validated password with production randomness.                               |
| `creds generate passphrase [options]`      | Available in the built package | Generates one passphrase from the attributed EFF short word list.                                 |
| `creds totp [options]`                     | Available in the built package | Reads a masked or explicit-stdin Base32 seed and emits one canonical TOTP code.                   |
| `creds key create --file <path> [options]` | Available in the built package | Creates one unbound v1 portable-key file, refuses overwrite, and never displays the portable key. |

The generated completion is derived from the static public catalog. It never
loads runtime vault names, aliases, fields, IDs, or secrets. Inspect output
before installing it into a shell profile:

```text
creds completion bash
creds completion zsh
creds completion fish
creds completion powershell
```

Password policy options cover length 8-1024, per-character-class minima, visible
ASCII exclusions, and `--stdout`. Passphrase options cover 6-24 words, one
supported separator, optional random capitalization/digit, exact word
exclusions, and `--stdout`. TOTP supports `--secret-stdin`, SHA-1/SHA-256/SHA-512,
6-8 digits, periods from 5 through 3600 seconds, an optional bounded Unix time,
and `--stdout`. Secret output requires an interactive stdout unless `--stdout`
is explicit.

`key create` is unprotected by default. `--protect-with-passphrase` acquires two
matching masked entries of at least 12 UTF-8 bytes; `--passphrase-stdin` requires
exactly two bounded frames followed by EOF. Success emits only `Portable key file
created.` Existing targets are never replaced.

The deterministic package build emits one ESM executable entry and
content-hashed lazy chunks. Version and completion do not evaluate the
cryptography/key-file chunk. The public JavaScript module contains only a
`CLI_VERSION` export; repository-only CLI factories and adapters are not
exported. The CycloneDX SBOM records an aggregate artifact-set hash, one hash for
every emitted JavaScript file, four bundled npm libraries, and the attributed
EFF word list as a separate CC-BY-4.0 data component. See the
[release process](./release.md) for the remaining publication gates.

## Additional dependency-injected catalog

[`CLI_COMMAND_CATALOG`](../apps/cli/src/catalog.ts) and
[`runCli`](../apps/cli/src/cli.ts) implement and test the following parser,
validation, rendering, and use-case boundaries. They require real
`CliUseCasePorts` and, where applicable, a `SecretInputPort`. No production
composition currently supplies those ports to the executable.

| Syntax                                                                                                 | Status       | Implemented boundary behavior                                                                                                               |
| ------------------------------------------------------------------------------------------------------ | ------------ | ------------------------------------------------------------------------------------------------------------------------------------------- |
| `creds init [options]`                                                                                 | Catalog only | Drives the injected crash-safe initialization coordinator and dedicated sensitive-display boundary.                                         |
| `creds init resume <operation-id>`                                                                     | Catalog only | Resumes one durable initialization journal operation without redisplaying creation material.                                                |
| `creds init cancel <operation-id>`                                                                     | Catalog only | Requests safe cancellation; unsafe states fail generically.                                                                                 |
| `creds status [--json]`                                                                                | Catalog only | Validates and renders redacted local vault/sync status.                                                                                     |
| `creds lock`                                                                                           | Catalog only | Calls the injected lock use case and prints `Vault locked.` after success.                                                                  |
| `creds show <group-query> <credential-query> [--json]`                                                 | Catalog only | Calls one redacted, schema-validated show use case. See [Direct access CLI](./direct-access-cli.md).                                        |
| `creds copy <group-query> <credential-query> <field-query> [--index <number>]`                         | Catalog only | Delegates authorized clipboard copy and returns only a safe label/deadline receipt, never the copied value.                                 |
| `creds device invite list --vault <vault-id> [--json]`                                                 | Catalog only | Lists canonical public invite metadata, never invite tokens or hashes.                                                                      |
| `creds device invite revoke <invite-id> --vault <vault-id>`                                            | Catalog only | Revokes one opaque invite ID.                                                                                                               |
| `creds device invite join --device <device-id> [--schema-version <version>] [--invite-stdin] [--json]` | Catalog only | Acquires the invite through a masked prompt or explicit stdin and calls an injected enrollment use case. The default schema version is `1`. |

The invite-join catalog entry is a low-level tested composition contract. It is
not the complete planned second-device workflow: server selection, portable-key
unlock, key-file input, durable enrollment replay state, and executable wiring
remain outside this catalog. Read
[Portable Key and Device Enrollment](./portable-key-and-device-enrollment.md)
for the protocol status.

The lower-level protocol now returns the canonical wrapped/encrypted vault record
with a successful invite redemption. The client validates its vault binding and
can locally authenticate an active current portable-key slot before it completes
device enrollment. `unlockRedeemedVaultWithPortableKey` returns an owned VRK that
the caller must clear. The portable key and VRK are never sent back to the API.
The catalog `joinInvite` adapter is responsible for preserving that ordering and
for durable, idempotent successor-token handling; the packed executable still
does not supply such an adapter.

If a catalog command is constructed without its required injected adapter, it
fails with `CLI_UNAVAILABLE` and exit code `5`; it never falls back to fake data.
In the public executable the same unregistered command is invalid usage and
returns exit code `2`.

## Unavailable public command families

The following surfaces are not available from the packed executable and must not
be treated as released behavior, even where a tested injected descriptor or
lower-level use case exists:

- initialization, resume/cancel, connect, and unlock;
- direct `copy` and `reveal`;
- group, item, dynamic-field, and note CRUD;
- portable-key import, rotation, recovery, and device lifecycle beyond the
  catalog contracts above;
- backup, verify, restore, history, and attachment commands;
- `get`, `set`, `update`, `run`, and the TUI entrypoint.

Lower-level implementations exist for several of these concerns, but no
uncomposed operation is advertised as a working command. The factual feature
ledger is [Implementation Status](./implementation-status.md).

## Exit codes and errors

The CLI runtime defines stable numeric categories in
[`CLI_EXIT_CODES`](../apps/cli/src/errors.ts):

| Exit | Meaning                                                                    |
| ---: | -------------------------------------------------------------------------- |
|  `0` | Success, including help and version display.                               |
|  `1` | An unexpected failure or a domain failure without a more specific mapping. |
|  `2` | Invalid command usage or domain validation failure.                        |
|  `3` | No matching record.                                                        |
|  `4` | Ambiguous name or alias.                                                   |
|  `5` | Required production adapter or network service unavailable.                |

Usage errors produced by Commander are deliberately generic:

```text
Error [CLI_USAGE]: Invalid command usage. Run 'creds --help'.
```

Other errors use one sanitized line on standard error:

```text
Error [CODE]: Safe message.
```

Unexpected exceptions become `UNEXPECTED_FAILURE` without exception text.
Ambiguity errors do not print candidate IDs, and invalid usage does not reflect
hostile arguments. ANSI/OSC/C1 controls, terminal string commands, bidi controls,
and embedded line controls are neutralized by the terminal boundary. Errors are
text even when a command has `--json`.

## Secret input

[`NodeSecretInput`](../apps/cli/src/secret-input.ts) implements the current input
boundary. The public executable uses it for TOTP seeds and protected key-file
passphrases; the injected catalog also uses it for initialization and invite
enrollment.

- Interactive input requires a real TTY, enters raw mode, does not echo the
  value, supports backspace, treats Ctrl+C as cancellation, and restores the
  prior raw-mode state.
- Redirected input is never consumed implicitly. The matching explicit stdin
  switch is required.
- `creds totp --secret-stdin` accepts exactly one bounded UTF-8 Base32 frame.
  `creds key create --protect-with-passphrase --passphrase-stdin` accepts exactly
  two matching bounded UTF-8 frames followed by EOF. Missing, extra, empty,
  malformed, control-bearing, or oversized input fails closed.
- Injectable initialization has separately staged `--key-stdin` and
  `--confirmation-stdin` protocols; invite enrollment uses `--invite-stdin`.
  Those flags do not make the corresponding commands public.
- No secret-valued positional or normal option is defined. In particular, there
  is no `--invite <value>`, `--passphrase <value>`, `--portable-key <value>`, or
  TOTP seed option that carries the secret itself.

Do not put a portable key, recovery key, passphrase, invite, token, or credential
value in argv, a URL, an environment variable, a shell history entry, or a
command-substitution expression. Explicit stdin is an automation boundary, not
permission to source plaintext from an unprotected file or another logged
command.

## Text and structured output

Non-interactive output is normalized to LF and contains no intentional ANSI.
Every string crossing the renderer is sanitized for terminal control sequences.

The catalog `--json` outputs are canonical redacted projections, formatted with
two-space indentation and one trailing newline. They are not plaintext export:

- status contains only vault/device IDs and sync state metadata;
- show masks sensitive fields, secret scalar variants, secret environment
  entries, and every note body;
- invite list contains only the public invite schema;
- invite join returns only vault and device IDs.

There is no current flag that emits secret JSON or bypasses redaction. JSON
schemas are command-specific, and stderr remains the sanitized text error
channel.

Password/passphrase generation and TOTP are deliberate non-JSON secret-output
commands. They emit exactly one generated value or code plus a newline, only to
an interactive stdout or when `--stdout` explicitly authorizes redirection.
`key create` emits only its generic success line and never the portable key or
passphrase.

## Shell quoting

Group and credential names are not secrets, but quote them so whitespace,
wildcards, variables, and punctuation reach Commander as one argument. Never use
these patterns to pass an actual secret.

| Shell      | Literal-name example                       |
| ---------- | ------------------------------------------ |
| Bash       | `creds show 'Email Accounts' 'Gmail Work'` |
| Zsh        | `creds show 'Email Accounts' 'Gmail Work'` |
| Fish       | `creds show 'Email Accounts' 'Gmail Work'` |
| PowerShell | `creds show 'Email Accounts' 'Gmail Work'` |

Those `show` examples describe the catalog syntax; they currently fail as invalid
usage in the packed executable. For Bash and Zsh, an embedded apostrophe can be
represented by closing the literal, adding an escaped apostrophe, and reopening
it: `'Operations'\'' Mail'`. In PowerShell, double an apostrophe inside a
single-quoted string: `'Operations'' Mail'`. Fish users should use a quoted form
appropriate to the exact name or select by opaque ID when punctuation would be
unclear.

Use `--` before positional queries that begin with a hyphen, once the operational
catalog is composed. Do not rely on shell aliases, glob expansion, locale-specific
case conversion, or unquoted command substitution for record selection.

## Current verification limits

Parser, renderer, terminal sanitizer, masked/stdin input, local generators, RFC
TOTP behavior, key-file creation/ACLs, static completion, package contents, lazy
chunk loading, and packed-bin behavior have automated tests. They do not prove
that a vault operation works end to end, because the public executable does not
yet compose vault unlock, sync, read-session, keychain, clipboard, TUI, or backup
use cases. Cross-platform shell completion packaging is prepared, but a
published package and final target-platform release evidence do not exist.
