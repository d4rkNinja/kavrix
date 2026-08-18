# CLI reference

Kavrix is a direct-MongoDB local CLI. Run \`kavrix --help\` or
\`kavrix <command> --help\` for the authoritative option list.

## Vault and database

- \`kavrix init\`: create a vault and a protected portable key file.
- \`kavrix db ping\`: verify the configured MongoDB connection without unlocking a vault.
- \`kavrix vault list\`: list vault identifiers without revealing values.
- \`kavrix vault status\`: show non-secret vault metadata and key-slot state.

## Encrypted credentials

- \`kavrix put <name>\`: encrypt and store a value; existing names require \`--overwrite\`.
- \`kavrix get <name>\`: read a value; plaintext output requires the explicit \`--reveal\` guard.
- \`kavrix list\`: list names and metadata without values.
- \`kavrix view <name>\`: render one guarded credential view.
- \`kavrix search <query>\`: search names and safe metadata without printing values.
- \`kavrix stats\`: show counts and non-secret size/revision statistics.
- \`kavrix remove <name>\`: delete a credential; use the command's confirmation guard.
- \`kavrix has <name>\`: check existence without revealing its value.
- \`kavrix rename <from> <to>\`: rename an encrypted record without reprinting it.
- \`kavrix doctor\`: decrypt and validate the local vault without printing values.
- \`kavrix doctor health\`: run fail-closed checks for the Mongo connection, vault schema/AAD,
  protected portable key, encrypted payload, and recovery slots. It retries a transient Mongo
  connection once and reports that retry as \`autoHealed\`; it never regenerates keys, rewrites
  ciphertext, bypasses rollback protection, or guesses how to repair cryptographic corruption.
  Missing keys, metadata tampering, replay/rollback, invalid ciphertext, and unavailable MongoDB
  are reported under \`manualRecoveryRequired\`. A missing trusted local revision anchor is
  never initialized implicitly; use \`--accept-current\` only after independently verifying the
  current database snapshot.

## Key files

- \`kavrix key status\`: show protected key-file metadata.
- \`kavrix key verify\`: cryptographically verify a key file.
- \`kavrix key copy\`, \`key replicate\`, \`key assign\`: create another protected key file with the same binding.
- \`kavrix key rewrap\`: replace a key-file passphrase without changing its vault binding.

Key-file copies are not independently revocable. Keep copies protected and
separate from the database.

## Recovery kits

- \`kavrix recovery create\`: create a passphrase-protected recovery kit for an active vault slot.
- \`kavrix recovery verify\`: validate a recovery kit and the trusted local anchor without changing the vault.
- \`kavrix recovery status\`: list non-secret recovery-slot state.
- \`kavrix recovery revoke\`: revoke a slot in the current local document.
- \`kavrix recovery use\`: unlock with a recovery kit and trusted local anchor, then rotate the root key.

Recovery kits contain wrapped key material, not plaintext backup codes. Payload
AAD rejects partial metadata tampering, and the trusted local revision anchor
rejects lower-revision or same-revision forked snapshots. Recovery-only commands
fail closed when that anchor is missing.

## Input and output rules

Secrets are accepted through masked prompts, protected files, or explicit stdin
frames. They are not accepted as positional arguments, environment variables,
settings files, or unguarded output. Terminal output is sanitized and masks
values by default.
