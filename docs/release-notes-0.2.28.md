# Release notes — 0.2.28 protected database backup (`kavrix backup`)

New command family answering the product's hardest rule: losing every valid
key file and recovery kit is unrecoverable by design, so a verified,
independently passphrase-protected backup is the operator's safety net.

## What ships

- `kavrix backup create --file <path>` seals the selected local-file
  database-container profile's database file into a single JSON archive
  document. The archive is sealed with XChaCha20-Poly1305 under an
  Argon2id key derived from a new backup passphrase (minimum 16 bytes,
  confirmed pair). The canonical archive header — format, version, creation
  time, datastore kind, opaque database identity, exact plaintext length,
  and the derivation parameters — is the envelope's associated data, so an
  archive cannot be relabeled to another database, truncated, or spliced
  without failing authentication. The archive is written through the
  protected-file writer (owner-only permissions, atomic create, refusal to
  clobber without `--overwrite`).
- `kavrix backup verify --file <path>` authenticates an archive and reports
  its database ID, sealed byte length, and creation time without writing any
  database file. A wrong passphrase and a modified archive are deliberately
  indistinguishable: both fail with the generic authentication message and
  exit 10. Malformed or unknown documents fail with exit 16 before any key
  derivation.
- `kavrix backup restore --file <path> --data-file <path>` authenticates an
  archive and publishes the plaintext database file to a new destination
  through the protected-file writer (same create/`--overwrite` rules). The
  restored file is the same database: bind a profile to it with
  `kavrix db profile add` and the original owner key authenticates, or use
  `kavrix db recovery use` with a database recovery kit.
- `kavrix frames "backup create"` (and verify/restore) document the stdin
  frame contracts. Passphrases are accepted only through masked prompts or
  stdin frames; no secret travels through argv. Plaintext database bytes
  exist only in memory during create/restore and are cleared best effort.
- Scope: local-file datastore profiles only. MongoDB database backup is not
  part of this release and fails closed with a configuration message.
  Archive bound: 128 MiB plaintext (the protected-stream file ceiling).

## Implementation

- `packages/schemas/src/database-backup-archive.ts` — strict versioned
  archive schema with canonical base64url bounds.
- `packages/crypto/src/backup-envelope.ts` — `sealDatabaseBackupArchive`,
  `parseDatabaseBackupArchive`, `openDatabaseBackupArchive`,
  `discardBackupPlaintext`; the AAD construction mirrors the sealed
  state-envelope pattern (domain string, length prefix, canonical JSON).
- `apps/cli/src/backup-command.ts` — command composition; profile routing
  through the protected registry (`openIfPresent`/`open`, current profile
  fallback, explicit `--profile`), consistent with the rest of the CLI.
- `packages/crypto/test/backup-envelope.test.ts` — round-trip, wrong
  passphrase, tampered ciphertext/tag, transplanted database identity
  (AAD), declared-length mismatch, malformed/unknown documents, and
  plaintext-bound rejection.
- `apps/cli/test/backup-command.test.ts` — end-to-end against the real CLI
  composition: unbound-profile refusal (exit 14), create → verify →
  restore with a restored file that authenticates under the original owner
  key, clobber refusal without `--overwrite`, wrong-passphrase
  `AUTHENTICATION_FAILED` JSON envelope (exit 10, no human stderr
  duplicate), tampered-ciphertext human-path failure, and non-backup
  content rejected as an integrity failure (exit 16) before any key work.
