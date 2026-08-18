# Threat model

## Assets

- credential values and their authenticated encrypted payloads;
- portable-key and recovery-kit protected files;
- vault root keys, key-slot metadata, and recovery state;
- MongoDB connection credentials supplied at runtime.

## Intended protections

Kavrix derives and unwraps keys locally, authenticates every persisted envelope,
and sends MongoDB only opaque vault documents. The database adapter rejects
remote connections without explicit TLS and rejects invalid-certificate,
invalid-hostname, and explicit TLS-disablement options.

Protected files are passphrase-bound and permission checked. Secret input is
masked or framed through stdin; secrets are not accepted as positional command
arguments, logged, or written to settings files.

## Out of scope

A fully trusted local process running after unlock can inspect process memory or
intercept terminal output. MongoDB metadata remains observable. Losing every
authorized key file and recovery kit is intentionally unrecoverable.

## Rollback protection

The local payload authenticates the complete document metadata and revision in
its associated data. After a successful unlock, Kavrix also maintains a
restrictive local revision anchor authenticated by the vault root key. A
database-only administrator who replaces the document with a lower revision or
a same-revision metadata fork is rejected before credentials are exposed.
Recovery-only operations require the same anchor. If the anchor is missing,
\`kavrix doctor health --accept-current\` is an explicit migration action and
must only be used after independently verifying the current database snapshot.
A lost key file and lost anchor remain an intentional manual-recovery
condition; root rotation cannot erase old ciphertext snapshots.

## Release evidence

The release gate includes schema/crypto tamper tests, protected-file tests,
Mongo URI policy tests, packed-artifact checks, and a real MongoDB integration
test when \`KAVRIX_MONGODB_URI\` is available. Cross-platform ACL behavior
requires a supported Windows runner.
