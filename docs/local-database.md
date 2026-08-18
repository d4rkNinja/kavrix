# Local MongoDB mode

Kavrix stores one encrypted local-vault document per vault in the
\`kavrix_vaults\` collection by default. The database receives the document
format, identifiers, revisions, timestamps, key-slot metadata, and encrypted
payload. It does not receive plaintext credential values, portable keys,
passphrases, recovery passphrases, or decrypted root keys.

## Connection policy

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

No server process, HTTP endpoint, migration daemon, or local settings file is
required by Kavrix.
