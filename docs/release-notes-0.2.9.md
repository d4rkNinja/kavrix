# Kavrix 0.2.9 — Recovery-verified local onboarding

Kavrix 0.2.9 turns the bare interactive `kavrix init` path into a complete
local-file setup. It creates an encrypted database and owner key, creates one
default vault, creates a separately protected recovery kit, verifies that kit
locally, and selects the new profile only after every authenticated step
succeeds.

The zero-knowledge boundary is unchanged: protected labels and passphrases stay
inside the local CLI. They are never accepted through argv or environment
variables and never appear in the generated config reference, terminal output,
profile registry, or encrypted artifact plaintext.

## Guided local first run

Run a bare no-option command in a TTY:

```sh
kavrix init
```

The visible wizard collects a public profile ID plus destinations for the
encrypted database, owner key, and recovery kit. Blank destinations use the
private `~/.kavrix` directory. Only after all destinations pass preflight
does Kavrix collect the private database/vault labels and the confirmed owner
and recovery passphrases through masked prompts.

The existing protected `config.toml` is still generated as a non-secret
command reference. It is not loaded automatically and contains no unlock
material.

## Fail-closed publication

The route is initially published without selecting it. Database initialization
binds that exact route, default-vault publication verifies the same database
binding, and final selection atomically checks the complete expected file
route, database ID, and default vault ID.

If another process replaces the profile during setup, Kavrix refuses to bind,
default, or select the replacement. Failures after a durable publication retain
recovery-capable artifacts and return phase-specific inspection guidance rather
than attempting destructive rollback or claiming success.

Final selection is itself a protected publication. If the filesystem reports an
ambiguous outcome after that write begins, Kavrix does not claim completion;
the profile may already be selected, so the error directs the user to reconcile
with `kavrix db profile status` before retrying or changing selection.

## Destination and secret hardening

Preflight canonicalizes parent directories and rejects collisions across:

- database, owner-key, recovery-kit, and revision-anchor targets;
- database and protected-file lock paths;
- the datastore profile registry and generated config reference;
- symbolic-link aliases where supported and case-only aliases on every platform.

Artifact destinations are checked again after publishing the unselected route.
The owning storage and key-file primitives retain their create-only, no-follow,
identity, permissions, and authenticated-publication checks. Owned passphrase
byte copies are wiped on every exit.

## Compatibility

Explicitly routed or non-TTY root `init` remains the stable version 2
single-vault compatibility path. MongoDB and advanced routing continue through
the explicit `db profile`, `db init`, `db vault`, and
`db recovery` commands.

## Release verification

Publication is gated by the complete local release suite, focused real-storage
and race/collision regressions, package smoke and content inspection, packed
command and database-container acceptance, dependency audit, exact-commit CI
and CodeQL, npm trusted publishing with provenance, registry SHA-512 integrity
reconciliation, and GitHub release creation only after npm confirms
`kavrix@0.2.9`.
