# Self-hosting

Kavrix does not require or ship a self-hosted server. The supported CLI is a
local-first secrets firewall: it authorizes scoped execution locally, and opens
a local encrypted database file or connects directly to MongoDB for ciphertext
storage. Encryption and decryption stay in the CLI process. This page is kept
only as a migration note for older repository layouts; the historical API,
sync, and server commands are not part of the npm package.
