# Self-hosting

Kavrix does not require or ship a self-hosted server. The supported CLI is a
local-first secrets firewall: it authorizes scoped execution locally, and opens
a local encrypted database file or connects directly to MongoDB for ciphertext
storage. Encryption and decryption stay in the CLI process. This page is kept
only as a migration note for older repository layouts; the historical API,
sync, and server commands are not part of the npm package.

## 0.3.4 structured firewall workflows

Local-file backups can include the sealed authorization sidecar with --include-firewall. Apply it only after authenticating the restored database, using backup restore-firewall; archived grants are discarded. MongoDB still stores only encrypted records. Structured-field execution, snapshots and required-policy mode remain client-side operations.

See the [workflow guide](firewall-workflows.md) for commands and limitations.
