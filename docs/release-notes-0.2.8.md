# Kavrix 0.2.8 — Safer protected input and profile routing

Kavrix 0.2.8 improves the public CLI contract around first-run routing,
protected interactive input, and command help. The zero-knowledge boundary is
unchanged: secret material remains local to the CLI and never enters datastore
profiles or the storage layer as plaintext.

## Authenticated per-profile default vaults

`kavrix db vault use <vault-id>` authenticates the selected datastore profile,
verifies that the requested vault exists, and stores its opaque ID as that
profile's default. Each profile keeps an independent selection. Vault-scoped
commands use the stored default when `--vault` is omitted, while an explicit
`--vault <id>` overrides it for only that invocation.

If neither selection is available, Kavrix fails before requesting secret input
rather than guessing. The protected profile registry contains only non-secret
routing data. It does not store MongoDB credentials, passphrases, private
database or vault labels, database root keys, vault root keys, or credential
values.

## Protected prompt feedback and retry behavior

Interactive masked prompts now state the non-secret input requirement before
entry and report progress with textual `[i]`, `[OK]`, and `[X]` markers. Locally
invalid input retries only the affected field. When a passphrase confirmation
does not match, Kavrix retries both entries without revealing either value or
requiring unrelated earlier fields to be entered again.

Color remains optional and redundant. ANSI styling is emitted only to an
eligible TTY and is disabled by `NO_COLOR` or `TERM=dumb`; the textual markers
remain. Protected stdin framing stays silent and ANSI-free, and cancellation or
terminal preparation and cleanup failures continue to fail closed.

## Help and usage contracts

Root help and every public canonical or alias `--help` route now render without
executing command actions or reading secret input and exit successfully. Their
non-interactive output is ANSI-free and contains no internal stack detail.
Unknown root commands retain the documented usage exit `2` and produce one
sanitized error with command usage.

`kavrix grant create --help` now lists all effective creation options inherited
from the parent `grant` command and explains that they may appear before or
after `create <secret>`. `policy check` and `policy explain` now show and enforce
the literal executable pass-through contract:

```text
kavrix policy <check|explain> [options] <id> -- <executable> [args...]
```

A missing separator or executable is rejected as usage error `2` before secret
input is read.

## Compatibility and rollback

Kavrix 0.2.8 reads strict version 1 datastore-profile registries without
rewriting them during read-only operations. The next protected profile mutation
publishes the version 2 registry required to store an optional default vault.
Kavrix 0.2.7 cannot read that newer registry, so an in-place downgrade after a
0.2.8 profile mutation is unsupported. Restore a separately preserved version 1
registry or roll forward to 0.2.8; do not hand-edit the protected registry.

## Release verification

Publication is gated by the complete local release suite, package smoke and
content inspection, database-container acceptance, dependency audit,
exact-commit CI and CodeQL, npm trusted publishing with provenance, registry
SHA-512 integrity reconciliation, and GitHub release creation only after npm
confirms `kavrix@0.2.8`.
