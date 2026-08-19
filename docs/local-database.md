# Datastore modes

Kavrix stores one canonical encrypted local-vault document in a protected file
or in the `kavrix_vaults` MongoDB collection by default. The datastore receives the document
format, identifiers, revisions, timestamps, key-slot metadata, and encrypted
payload. It does not receive plaintext credential values, portable keys,
passphrases, recovery passphrases, or decrypted root keys.

## Local encrypted file

Select the file adapter explicitly on every applicable command:

```sh
kavrix init --datastore file --data-file ./kavrix.vault
kavrix put service/token --datastore file --data-file ./kavrix.vault
```

The adapter stores one vault per file and enforces a canonical bounded document,
owner-only file permissions or Windows ACLs, link rejection, an exclusive sibling
lock, expected-revision updates, restrictive temporary files, atomic publication,
and directory synchronization. Credential names and values remain inside the
authenticated encrypted payload. Vault ID, versions, revision, timestamps,
envelope sizes, and key-slot metadata remain visible to a process that can read
the file.

Kavrix does not persist the datastore choice. Repeat `--datastore file` and
`--data-file` so every command names its target explicitly. MongoDB remains the
default for backward compatibility.

## MongoDB connection policy

- \`mongodb://localhost\`, \`mongodb://127.0.0.1\`, and \`mongodb://[::1]\` may use the local development connection without an explicit TLS query parameter.
- Every non-local host, including \`mongodb+srv://\`, must explicitly set \`tls=true\` or \`ssl=true\`.
- \`tls=false\`, \`ssl=false\`, \`sslValidate=false\`, and insecure certificate/hostname options are rejected.
- Credentials belong in the MongoDB URI supplied through the masked prompt or protected environment integration, never in command arguments or committed files.

The adapter uses bounded connection, server-selection, and socket timeouts and
maps connection, validation, conflict, existence, and operation failures to
generic fail-closed errors.

## Operational commands

Use \`kavrix db ping --database <name>\` to test reachability. \`kavrix init\`
creates the first document and protected portable-key file. Subsequent commands
unlock the local document, decrypt in memory, and persist an optimistic revision
update.

No Kavrix server process, HTTP endpoint, migration daemon, or plaintext settings
file is required by either mode.
