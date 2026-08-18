# Recovery kits

A recovery kit is a passphrase-protected file that can replace a lost portable
key. It is not a plaintext backup code and is never uploaded by Kavrix.

## Lifecycle

```sh
kavrix recovery create
kavrix recovery verify
kavrix recovery status
kavrix recovery revoke <slot-id>
kavrix recovery use
```

Use `kavrix recovery <command> --help` for vault, key-file, and recovery-file
options. Sensitive values are collected through masked prompts or explicit
protected input flows.

Creation adds an authenticated recovery slot to the encrypted vault document and
writes the matching passphrase-protected recovery file. Verification authenticates
the file without changing MongoDB. Revocation changes the authenticated slot
state and refuses to remove the last active recovery path. Use authenticates the
kit, requires the trusted revision anchor, creates a replacement protected key
file, rotates the vault root key, and persists a new document revision.

Keep recovery kits on media separate from the active key file and database
backups. Anyone with the recovery file and its passphrase can recover the vault.
If every valid key file and recovery kit is lost, Kavrix cannot decrypt the
credentials.

Recovery rotation protects the current document; it cannot erase copies of old
encrypted snapshots. Protect MongoDB backups and define an appropriate retention
policy.
