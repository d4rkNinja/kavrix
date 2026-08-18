# Portable keys

Kavrix uses a protected portable-key file as the normal unlock capability. The
file contains wrapped key material bound to one vault and key version; it never
stores a plaintext credential value or passphrase.

## Lifecycle

- \`kavrix init\` creates the first protected key file and vault document.
- \`kavrix key status\` and \`kavrix key verify\` inspect it without revealing key bytes.
- \`kavrix key copy\`, \`key replicate\`, and \`key assign\` create another protected file with the same binding.
- \`kavrix key rewrap\` changes the file passphrase without changing the vault binding.

Copies are not independently revocable. Keep every copy protected and separate
from MongoDB. Losing every copy and recovery kit is permanent by design.

The old server enrollment, device join, SQLite journal, and native keychain
workflow is not part of the supported local product.
