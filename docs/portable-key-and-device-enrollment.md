# Portable keys and legacy compatibility

This filename is retained for historical links. The supported product has no
device-enrollment or hosted-server lifecycle. It uses protected key files for
the local-file and direct-MongoDB database-container paths, plus a separate
version 2 compatibility format.

Database-container initialization (`kavrix db init`) creates a protected
database-owner key file containing wrapped key material bound to the database.
The legacy root `kavrix init` path creates a protected portable-key file bound to
one version 2 vault when invoked with explicit routing and secret input. A bare
no-argument TTY `kavrix init` only creates the non-secret `config.toml` template
and does not create a key or vault. Current commands do not load the file
automatically.

## Lifecycle

- `kavrix db key status` inspects a database-owner key without revealing key
  bytes; `kavrix db key create` creates a whole-database share key for an exact
  local snapshot.
- `kavrix key status` and `kavrix key verify` inspect a legacy version 2 key
  without revealing key bytes.
- `kavrix key copy`, `key replicate`, and `key assign` create another protected
  legacy file with the same binding.
- `kavrix key rewrap` changes a legacy file's passphrase without changing its
  vault binding.

Copies are not independently revocable. For local database sharing, possession
of the exact encrypted snapshot and matching share key grants access to every
vault in that snapshot. Losing every owner key and recovery kit is permanent by
design.

The old server enrollment, device join, SQLite journal, and native keychain
workflow is not part of the supported local product.
