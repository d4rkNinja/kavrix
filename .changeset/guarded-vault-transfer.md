---
'kavrix': minor
'@kavrix/core': minor
'@kavrix/import-export': minor
'@kavrix/schemas': minor
---

Add the guarded `creds transfer export` and `creds transfer import` commands for
moving groups between vaults.

A transfer is deliberately not a backup. It is sealed under its own passphrase —
never the vault's unlock material — so a transfer file that leaks cannot be
opened with vault credentials, and vault credentials are never written into a
portable file. The passphrase is derived with Argon2id and split by HKDF-SHA-256
into a payload-sealing key and a transcript-authentication key, so the two roles
cannot be confused; the sealed payloads reuse the existing group/item AAD
purposes because domain separation here comes from key separation rather than a
wire-visible enum change. Export confirms the passphrase twice, since a mistyped
one would produce a file nobody can ever open, and `--transfer-passphrase-stdin`
reads it from bounded stdin frames. It is never accepted in argv.

A new `projectItemForTransfer` in `@kavrix/core` decides what a transfer may
carry. A value whose field declares `exportPolicy: never` is omitted entirely —
not masked, not re-encrypted — and every omission is declared in a per-item
withholding manifest carrying only a stable key, a scope, and a reason.
Attachment content and attachment identifiers are never carried, and
item-to-item references are withheld because the destination mints new
identities. The projection fails closed rather than emitting a document that
could never be imported: a _required_ field whose value must be withheld aborts
the export, and the projection is re-validated against its own template before
it is written.

`readEncryptedTransfer` authenticates the complete file — framing, every sealed
entry, and the transcript tag over the whole stream — before it returns a single
document, so a truncated, reordered, oversized, or tampered transfer never
reaches a mutation path. The importer then plans the entire application before
creating the first group: group-name collisions are resolved up front, and every
item is checked against the template it travels with. `--on-collision` selects
how an existing group name is treated — `fail` (the default) refuses the
transfer, `skip` drops the colliding group and its credentials, and `rename`
creates it under the first free suffixed name. Names chosen for earlier groups
count as taken, so two identically named groups inside one transfer cannot
collapse into one.

Both receipts report counts only. Neither prints the transfer path, a group name,
a credential title, or any field value, in text or `--json`.
