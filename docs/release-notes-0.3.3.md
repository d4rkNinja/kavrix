# Release notes — 0.3.3

0.3.3 is a security and correctness release across the whole firewall: the
TUI no longer opens unencrypted MongoDB transport on its own, agent-broker
frames are sealed, hostile terminal content can no longer crash the renderer,
and large-but-legitimate backups become restorable again. Two operator-visible
behavior changes require attention when scripting; everything else is
transparent hardening. Publication follows the
[trusted-publishing procedure](release.md).

## Operator-visible changes (read before scripting)

- `kavrix tui` no longer enables non-TLS MongoDB transport for remote hosts.
  The TUI previously connected to any non-loopback MongoDB URI without TLS
  without asking. Remote non-loopback databases now fail closed exactly like
  the numbered CLI commands; pass the explicit
  `kavrix tui --allow-insecure-transport` flag for networks you have
  determined are isolated.
- `db vault remove` now requires an explicit confirmation. Interactive runs
  ask for it on the terminal; `--secrets-stdin` runs append the exact frame
  `REMOVE <vaultId>` after the unlock frames. `kavrix frames "db vault remove"`
  prints the current order, and a wrong or missing confirmation cancels the
  removal.

## Security

- Agent-broker frames are sealed in both directions with the reviewed
  chacha20-poly1305 under a key derived from the one-session broker token, so
  passive same-user observation of the named pipe or socket sees only
  ciphertext. Policy decisions and child output no longer ride the pipe
  as readable JSON.
- macOS `session enable` stores the wrapping key through `security -i`
  command-over-stdin instead of process arguments, matching the invariant the
  Linux port already kept. The duplicate keychain write that could fail
  `session enable` on Windows after the sealed file was written is removed.
- Imported archive entry names are control-character-sanitized before they
  can appear in error messages, so a crafted `kavrix import archive` cannot
  inject terminal escape sequences.
- The TUI terminal sanitizer replaces lone surrogates — which hostile vault
  records can carry — instead of throwing, closing a renderer crash loop that
  re-triggered every time the affected group was opened.
- Derived authorization-state keys are zeroized on success paths in
  `kavrix run` and `kavrix agent run`, and every raced grant denial (expired,
  exhausted, revoked, lost race under the lock) now commits its audit event
  before the typed error is thrown. A concurrent denial can no longer escape
  the audit trail.

## Data integrity

- Database backups and vault exports honor their advertised 128 MB / 64 MB
  archive bounds. The previous shared record ciphertext ceiling silently
  capped archives near 16.8 MB, so a legitimate 17–32 MB backup could be
  created but never restored, and large exports failed at creation.
- `get --reveal --json` and `field get --reveal` return multiline secrets
  exactly; display-oriented control-character replacement no longer corrupts
  newlines on the guarded machine-readable reveal paths.
- A protected file transition interrupted by a crash no longer bricks the
  target: replacement locks record their owning process and provably stale
  locks (dead owner, ancient age, or legacy empty locks past a grace window)
  are recovered automatically instead of failing `KEY_FILE_BUSY` forever.
- `doctor health --heal` refuses to treat a non-current Windows drive root as
  a filesystem root, so healing a key file at `D:\` can no longer tighten the
  ACL of the whole drive.

## Reliability and exit-code contract

- Coded errors wrapped in an aggregate cleanup failure keep their stable exit
  codes and carry the underlying message instead of degrading to a generic
  exit 1; an uncaught store-close failure in a cleanup path no longer masks
  the original operation error or exit code.
- Corrupt or unsafe datastore-profile registries fail the command with the
  reviewed error instead of silently falling back to legacy standalone
  routing; invalid profile and vault identifiers produce the reviewed
  messages and exit codes rather than a generic parser failure.
- The runner terminates a timed-out or aborted child's process tree (POSIX
  process group, Windows `taskkill /T /F`), accepts inherited environments
  with values up to the Windows per-variable limit, and keeps secret
  mappings at the tighter cap.
- The Windows agent-broker pipe is part of the sealed-frame change above;
  `agent exec` clients negotiate the same encrypted protocol.

## TUI

- Shift+Up/Down reorder works in the repeatable field editor as advertised;
  onboarding folder-browser clicks select the row they highlight.
- OSC 52 clipboard copies clear the previous payload before each new copy
  (at most one secret resident), refuse oversized payloads honestly instead
  of silently dropping, and no longer claim verified delivery.
- The mock backend is no longer part of the package's public API; `kavrix tui`
  consumes a narrow host entry instead of the fused barrel.

## Architecture

- The persistence ports (`EncryptedVaultStore`, `EncryptedDatabaseStore`,
  `CollaborativeVaultStore`) are owned by `packages/core`, with storage as
  the adapter package — the layering described in the architecture
  documentation is now enforced by the dependency graph and a boundary test,
  and `docs/architecture.md` matches `AGENTS.md`.
- Full lockfile, formatting, lint, typecheck, unit, packed-CLI acceptance,
  audit, and SBOM gates pass locally; release publication is additionally
  gated on main CI and CodeQL for this exact commit before tagging.

## Verification and limits

Local verification covered the full `verify:all` gate set on Windows x64
(Node 26.10.0): static checks, build, 2,300+ unit/integration tests, packed
CLI acceptance, and package-content checks. Service-dependent MongoDB
integration suites skip when no container is available. The release version
is separately gated by main CI and CodeQL on its exact commit before
tagging; trusted publishing performs archive integrity, SBOM, and
registry-integrity reconciliation before the npm publication.
