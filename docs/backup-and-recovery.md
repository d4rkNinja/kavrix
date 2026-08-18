# Recovery kits

Kavrix recovery is a protected-file flow for replacing a lost portable key. It
does not upload a backup archive or expose a plaintext backup code.

## Lifecycle

\`\`\`sh
kavrix recovery create --vault <id> --key-file <path> --recovery-file <path>
kavrix recovery verify --recovery-file <path> --key-file <path>
kavrix recovery status --vault <id>
kavrix recovery revoke --vault <id> --slot <slot-id>
kavrix recovery use --vault <id> --key-file <path> --recovery-file <path>
\`\`\`

Creation wraps recovery material for one vault and slot in a passphrase-protected
kit. Verification authenticates the kit without changing MongoDB. Use unwraps
the root key locally, rotates the vault root key, and persists the updated
document. Revoked slots are rejected by the current decrypt path.

Keep recovery kits on a separate protected medium from portable-key files. Kavrix
stores a restrictive sidecar revision anchor next to the active key file and
authenticates it with the vault root key. A lower revision or same-revision
metadata fork is rejected before credentials are returned. Recovery-only
operations require that same anchor, so losing both the key file and its anchor
is an intentional manual-recovery condition. Payload AAD still authenticates
the complete document metadata and revision; root rotation cannot erase old
ciphertext snapshots.
