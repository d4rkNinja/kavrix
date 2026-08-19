# Recovery kits

A recovery kit is a passphrase-protected file that can replace a lost protected
key file. It is not a plaintext backup code and is never uploaded by Kavrix.

Database recovery kits and legacy version 2 vault recovery kits are distinct,
strict formats. Each reader rejects the other format.

## Database recovery

```sh
kavrix db recovery create --profile work --recovery-file ./work.database.recovery
kavrix db recovery verify --profile work --recovery-file ./work.database.recovery
kavrix db recovery status --profile work
kavrix db recovery revoke <slot-id> --profile work
kavrix db recovery use --profile work \
  --recovery-file ./work.database.recovery \
  --output-key-file ./work.recovered.key
```

Database recovery slots wrap the database root key. A verified kit can recreate
owner access to every vault in that database, subject to the matching datastore
and trusted database anchor. It does not recover a forgotten recovery
passphrase, regenerate missing ciphertext, rotate every vault key, or erase old
snapshots.

## Legacy version 2 recovery

## Lifecycle

```sh
kavrix recovery create
kavrix recovery verify
kavrix recovery status
kavrix recovery revoke <slot-id>
kavrix recovery use
```

Use `kavrix recovery <command> --help` for legacy vault, key-file, and recovery-file
options. Sensitive values are collected through masked prompts or explicit
protected input flows.

Creation adds an authenticated recovery slot to the encrypted vault document and
writes the matching passphrase-protected recovery file. Verification authenticates
the file without changing MongoDB. Revocation changes the authenticated slot
state and refuses to remove the last active recovery path. Use authenticates the
kit, requires the trusted revision anchor, creates a replacement protected key
file, rotates the vault root key, and persists a new document revision.

Keep recovery kits on media separate from active key files and database backups.
Anyone with a database recovery file, its passphrase, and the matching database
snapshot can recover every vault in that database. If every valid owner key and
database recovery kit is lost, Kavrix cannot decrypt its vaults.

Recovery rotation protects the current document; it cannot erase copies of old
encrypted snapshots. Protect MongoDB backups and define an appropriate retention
policy.
