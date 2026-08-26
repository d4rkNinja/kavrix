# Datastore modes

Kavrix stores one encrypted database container in a protected local file or as
one database document plus per-vault documents in MongoDB. Storage receives
opaque IDs, versions, revisions, timestamps, wrapped-key metadata, and encrypted
envelopes. It does not receive plaintext labels, credential data, portable keys,
passphrases, recovery secrets, DRKs, or VRKs.

## Non-secret profiles

Profiles prevent repeated routing flags without becoming a secret store:

```sh
kavrix db profile add local-work --datastore file \
  --data-file ./work.kavrix --key-file ./work.kavrix.key
kavrix db profile use local-work
kavrix db profile status
```

A file profile stores only its alias, datastore type, data path, key path, and—
after initialization—the expected opaque database ID. A MongoDB profile stores
the alias, type, database name, database/vault collection names, key path, and
expected opaque database ID. It never stores a URI, username, password, token,
passphrase, label, or decrypted key. The protected registry is still permission
checked because redirecting a route is security-sensitive.

## Local encrypted database

```sh
kavrix db init --profile local-work
kavrix db vault create --profile local-work
kavrix put service/token --profile local-work --vault <vault-id>
```

The adapter stores a bounded database document and up to the schema's bounded
number of opaque vault documents in one canonical file. It enforces owner-only
POSIX permissions or Windows user-only ACLs, link rejection, an exclusive sibling
lock, exact expected revisions, restrictive temporary files, atomic publication,
and directory synchronization. Labels, credential names, and values remain in
authenticated encrypted envelopes.

Local sharing is all-or-nothing. Create a fresh share key with
`kavrix db key create`, then transfer exactly that key and its matching encrypted
database snapshot. Deliver the share-key passphrase through a separate secure
channel. The one-use authenticated bootstrap creates the recipient's local anchor
on first open; subsequent opens require that anchor and fail closed if it is
missing. Possession of the two shared artifacts grants access to every vault. Do
not copy the primary owner key, describe copied files as a reader/editor grant, or
assume Kavrix can revoke a copied key or snapshot.

## MongoDB topology and connection policy

MongoDB stores database/catalog state in `kavrix_databases` and vault state in
`kavrix_vaults` by default. A catalog-plus-vault update is transactional, so a
replica set or sharded cluster with transaction support is required. A standalone
server may answer `db ping` but cannot provide the required publication contract.

- `mongodb://localhost`, `mongodb://127.0.0.1`, and `mongodb://[::1]` may use a
  local development connection without an explicit TLS query parameter.
- Every non-local host, including `mongodb+srv://`, must explicitly set
  `tls=true` or `ssl=true`.
- `tls=false`, `ssl=false`, `sslValidate=false`, and insecure certificate or
  hostname options are rejected. `--allow-insecure-transport` relaxes exactly
  one rule — it permits a plaintext (non-TLS) connection to a non-local host
  for isolated networks; it never re-enables `tls=false`/`sslValidate=false`
  URI parameters, which are refused regardless of the flag.
- Supply the URI only through the masked prompt or the command's exact protected
  stdin frame. It is never a profile field, normal argument, or environment setting.

The adapter uses bounded connection/server/socket timeouts and maps validation,
conflict, existence, and dependency failures to generic fail-closed errors.

## Locks, crash recovery, and bounded repair

Every local database container is guarded by an exclusive sibling lock file
(`<data>.kavrix.lock`) that records its owning process ID. A hard kill
(Ctrl+C, terminal close, OOM) can leave that lock behind. The next invocation
detects the recorded owner: a live process yields a clear "locked by another
Kavrix process" error, while a provably dead owner's lock is removed
automatically before the command proceeds. Malformed or foreign lock files are
not removed automatically and require an operator to identify and remove the
stale artifact after confirming no Kavrix process owns it. Manual deletion is
also required if the filesystem prevents safe automatic removal.

If a process died mid-write in the era before owner-ID locks, or a datastore
was restored from an older snapshot, the trusted local rollback anchor may
reject the stored state as stale or forked. Kavrix refuses such snapshots;
the bounded remedy is:

```sh
kavrix db doctor health                    # diagnose: binding, documents, anchor
kavrix db doctor health --accept-current   # after human verification only
```

`--accept-current` fully authenticates every encrypted document with the
database root key first; if that succeeds it rewrites the local rollback
anchor to the observed state. Datastore content is never modified, and the
flag consciously trades rollback protection for recoverability — verify the
datastore contents independently before using it.

## Sharing caveats

A share key authorizes the exact snapshot that existed when `db key create`
ran. Database writes after that moment are invisible to recipients who open
with earlier copies; create a fresh share key after meaningful updates.
On Windows, plain `Copy-Item` inherits ACEs (for example `SYSTEM:(F)`) that
fail Kavrix's user-only ACL policy. Strip inherited ACEs before transfer:

```powershell
icacls <file> /inheritance:r
```

## Vault labels

Labels live inside the encrypted catalog. Owner commands redact them by
default (`[REDACTED]`); pass `--show-labels` to `db vault list` or
`db vault status` to display decrypted labels after authenticating.

## Switching and binding

`kavrix db profile use <id>` changes only the current non-secret route. Every
database session verifies the database ID in the protected owner key, observed
database document, and bound profile before asking storage to decrypt. A key from
another database therefore fails even when filenames, collection names, or vault
IDs look similar. Explicit routing overrides cannot silently change the expected
database ID.

## Migration

Legacy version 2 files are not silently rewritten. Register the legacy source
and destination as separate profiles, then run `kavrix migrate database`. Use
`--initialize` only for an unbound local destination. Migration authenticates the
source key and anchor, copies the complete payload, verifies the new destination,
and leaves the source intact.

No Kavrix server, HTTP endpoint, migration daemon, or plaintext settings file is
required by either mode.
