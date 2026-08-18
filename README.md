# Kavrix

Kavrix is a local encrypted credential vault backed directly by MongoDB. The
CLI encrypts credential values before storage; no Kavrix server, HTTP API, sync
daemon, or self-hosting process is required.

## Install

\`\`\`sh
npm install --global kavrix
\`\`\`

Kavrix supports Node.js \`>=24.12.0 <25 || >=25.1.0\`.

## Quick start

\`\`\`sh
kavrix db ping --database kavrix_local
kavrix init --database kavrix_local --key-file ./kavrix.key
kavrix put production --database kavrix_local --key-file ./kavrix.key
kavrix list --database kavrix_local --key-file ./kavrix.key
kavrix get production --database kavrix_local --key-file ./kavrix.key
\`\`\`

Use \`kavrix --help\` and the command-specific \`--help\` output for the complete
surface:

- \`init\`, \`db ping\`
- \`put\`, \`get\`, \`list\`, \`view\`, \`search\`, \`stats\`
- \`remove\`, \`has\`, \`rename\`, \`doctor\`, \`doctor health\`
- \`recovery create\`, \`recovery verify\`, \`recovery revoke\`, \`recovery status\`, \`recovery use\`
- \`vault list\`, \`vault status\`
- \`key status\`, \`key verify\`, \`key copy\`, \`key replicate\`, \`key assign\`, \`key rewrap\`

Database URLs, passphrases, and credential values are read through masked
prompts or explicit stdin frames. They are not accepted as command-line
arguments or stored in a settings file. Protected-file passphrases must contain
at least 16 UTF-8 bytes.

## Security model

- Credential payloads are authenticated-encrypted locally before MongoDB writes.
- MongoDB stores opaque envelopes and wrapped key-slot metadata, not plaintext credentials or unlock material.
- Protected portable-key and recovery-kit files are required to unlock the vault.
- Losing every authorized protected key copy is permanent by design.
- A process already trusted by the unlocked local user can observe plaintext in memory.
- Recovery-kit use rotates the vault root key. Payload AAD and a root-key-authenticated local revision anchor reject metadata tampering, lower-revision replay, and same-revision forks.

Recovery kits are protected files, not plaintext backup codes. Store them separately
from portable key files and test recovery before relying on it. Recovery commands
reject overwrite mode and require new output paths.

## Development and release checks

\`\`\`sh
pnpm install --frozen-lockfile
pnpm verify
pnpm --filter kavrix package:smoke
pnpm --filter kavrix pack:check
pnpm audit --audit-level high
\`\`\`

The package is prepared for npm publication but is not published by this
repository state. Publication additionally requires the repository's reviewed
OIDC/trusted-publishing configuration and an authorized release tag.

The package includes attribution for the
[EFF Short Wordlist for Passphrases #1](https://www.eff.org/files/2016/09/08/eff_short_wordlist_1.txt)
under [CC-BY-4.0](https://creativecommons.org/licenses/by/4.0/).
