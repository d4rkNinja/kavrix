# Kavrix

## Keep credentials private without running another service

Kavrix is a local, zero-knowledge credential vault that stores encrypted records
in MongoDB. The CLI connects directly to MongoDB; there is no Kavrix server,
HTTP API, sync daemon, or self-hosting process to deploy.

Kavrix is designed for people who want:

| Need                           | Kavrix provides                                                                                 |
| ------------------------------ | ----------------------------------------------------------------------------------------------- |
| Store credentials in MongoDB   | Values are encrypted locally before they leave the CLI                                          |
| Work on more than one computer | Protected portable key files can be copied deliberately                                         |
| Recover from a lost key file   | Passphrase-protected recovery kits can create replacement keys                                  |
| Avoid accidental disclosure    | Values are masked by default and plaintext requires an explicit guard                           |
| Operate safely                 | `doctor health` checks the database, key, ciphertext, recovery state, and local rollback anchor |
| Keep operations simple         | One Node.js CLI package for Windows, macOS, and Linux                                           |

## Install

Kavrix requires Node.js `>=24.12.0 <25 || >=25.1.0`.

```sh
npm install --global kavrix
```

Verify the installation:

```sh
kavrix --version
kavrix --help
```

## Start in five minutes

The first command asks for the MongoDB connection string through a protected
prompt. The connection string, passphrase, and credential value are not placed
in the command line.

```sh
# Check that Kavrix can reach MongoDB.
kavrix db ping --database kavrix_local

# Create the vault and a protected local key file.
kavrix init --database kavrix_local --key-file ./kavrix.key

# Add a credential. Kavrix prompts for the value without echoing it.
kavrix put production/api-token --database kavrix_local --key-file ./kavrix.key

# List names and safe metadata only.
kavrix list --database kavrix_local --key-file ./kavrix.key

# Read the value. Output stays masked unless --reveal is supplied.
kavrix get production/api-token --database kavrix_local --key-file ./kavrix.key
```

Protect `kavrix.key` like a physical key. It is not a backup by itself:
create and separately store a recovery kit before you need one.

## Everyday work

| Goal                                       | Command                         |
| ------------------------------------------ | ------------------------------- |
| See a readable dashboard                   | `kavrix view`                   |
| See one credential card                    | `kavrix view <name>`            |
| Find names without opening values          | `kavrix search <pattern>`       |
| Show counts and non-secret statistics      | `kavrix stats`                  |
| Test existence without revealing a value   | `kavrix has <name>`             |
| Replace an existing value                  | `kavrix put <name> --overwrite` |
| Rename an encrypted record                 | `kavrix rename <from> <to>`     |
| Delete a record                            | `kavrix remove <name>`          |
| Validate the vault without printing values | `kavrix doctor`                 |
| Run safe health checks                     | `kavrix doctor health`          |

`get` and `view` do not reveal plaintext by default. Use
`--reveal` only in a terminal you trust, and avoid redirecting revealed
output into files, logs, shell history, or shared clipboard tools.

## Key files and recovery

### Portable key files

Use the key commands to manage protected copies:

| Goal                                | Command                                                                  |
| ----------------------------------- | ------------------------------------------------------------------------ |
| Inspect non-secret metadata         | `kavrix key status --key-file ./kavrix.key`                              |
| Cryptographically verify a key file | `kavrix key verify --key-file ./kavrix.key`                              |
| Create another protected copy       | `kavrix key copy --key-file ./kavrix.key --output-key-file ./second.key` |
| Use the same copy operation by name | `kavrix key replicate` or `kavrix key assign`                            |
| Change a key-file passphrase        | `kavrix key rewrap --key-file ./kavrix.key`                              |

Copies use the same vault binding and are not independently revocable. Store
copies in separate protected locations and do not keep every copy beside the
database or on the same laptop.

### Recovery kits

Recovery kits are encrypted protected files, not plaintext backup codes.

```sh
kavrix recovery create \
  --vault default \
  --key-file ./kavrix.key \
  --recovery-file ./kavrix.recovery.kit

kavrix recovery verify \
  --vault default \
  --key-file ./kavrix.key \
  --recovery-file ./kavrix.recovery.kit

kavrix recovery status --vault default
```

If the original key file is lost, `kavrix recovery use` verifies the
recovery kit and the trusted local revision anchor before creating a new
protected key file. Recovery commands refuse unsafe overwrites by default. Use
a new destination path and choose `--overwrite` only when you
intentionally replace that exact file.

`kavrix recovery revoke <slotId>` revokes a recovery slot in the
current vault document. Keep at least one independently verified unlock method
available. If every authorized key and recovery kit is lost, the encrypted data
is unrecoverable by design; Kavrix has no service-side backdoor.

## Database and vault selection

Kavrix uses MongoDB as an opaque storage layer. It does not create a settings
file containing a database URI or unlock secret.

Shared options include:

| Option                 | Purpose                                                        |
| ---------------------- | -------------------------------------------------------------- |
| `--database-url-stdin` | Read the MongoDB URI from stdin instead of a command argument  |
| `--database <name>`    | Select the MongoDB database when it is not embedded in the URI |
| `--collection <name>`  | Select the vault collection                                    |
| `--vault <id>`         | Select an opaque vault identifier                              |
| `--key-file <path>`    | Select a protected portable key file                           |
| `--passphrase-stdin`   | Read a key-file passphrase from protected stdin                |

For automation, use the stdin flags with a process that protects its input.
Never put a MongoDB URI, passphrase, key, or credential value in a shell
argument, a checked-in `.env` file, or a normal settings file.

Use `kavrix vault list` to see vault identifiers and
`kavrix vault status` to inspect non-secret metadata. Use
`kavrix db ping` when you only need to test connectivity and do not
want to unlock a vault.

For remote MongoDB, use TLS with normal certificate and hostname verification.
Client-side encryption protects credential contents, but it does not replace
transport security for connection metadata or database credentials.

## Security model

### What is protected

- Credential values, notes, and sensitive record payloads are authenticated-encrypted before MongoDB writes.
- Unlock material stays local: portable keys, passphrases, recovery keys, and decrypted values are not sent to MongoDB.
- Versioned envelopes authenticate ciphertext and its vault, record, schema, and key context.
- The key hierarchy uses independent wrapping keys so changing an unlock method does not require re-encrypting every credential.
- Protected key files and recovery kits are validated for format, binding, integrity, and safe filesystem permissions.
- Tampering, malformed envelopes, unavailable keys, invalid recovery state, and unsafe rollback conditions fail closed.

The version 1 implementation uses operating-system randomness, libsodium
XChaCha20-Poly1305 authenticated encryption, and Argon2id-based passphrase
derivation. These are implementation details, not a promise that cryptography
can overcome a compromised device or an exposed passphrase.

### What MongoDB can still see

Encryption does not hide every piece of metadata. MongoDB may observe opaque
identifiers, encrypted record sizes, versions, timestamps, relationships,
tombstone state, request timing, and traffic volume. It cannot decrypt the
credential payloads from those records alone.

### Important limits

- A process already trusted as the unlocked local user can observe plaintext in memory.
- Terminal applications, clipboard managers, crash dumps, swap, and backups can retain data outside Kavrix's control.
- Losing every authorized key file and recovery kit is permanent.
- `doctor health` detects and reports cryptographic corruption; it does not invent keys, rewrite ciphertext, or silently bypass rollback protection.
- No password manager can make a weak passphrase, compromised host, or leaked key safe.

## Input and output safety

- Secret values are accepted through masked prompts, protected files, or explicit stdin flows.
- Passphrases must contain at least 16 UTF-8 bytes.
- Plaintext is masked by default.
- `--reveal` is an explicit unsafe-output guard, not the default behavior.
- Terminal output is sanitized to prevent control-sequence injection.
- Key files are created without overwrite by default and are restricted to the current user.
- Recovery-kit commands require a new output path unless `--overwrite` is explicitly selected.

## Health checks and troubleshooting

Start with:

```sh
kavrix doctor health --database kavrix_local --key-file ./kavrix.key
```

The health command checks the MongoDB connection, vault schema, associated data,
protected key file, encrypted payload, recovery slots, and trusted local
revision anchor. It may retry a transient database connection. It never
regenerates a missing key or treats an untrusted database snapshot as safe.

If the command reports `manualRecoveryRequired`:

1. Stop writes to the affected vault.
2. Confirm that the database URI and selected vault are correct.
3. Verify the key file with `kavrix key verify`.
4. Compare the database snapshot with a known-good backup.
5. Use a verified recovery kit only when the local revision anchor and snapshot are trustworthy.

Do not use `--accept-current` merely to make a health check green.
That option initializes a missing local anchor only after you independently
verify the current database snapshot.

## Supported platforms

Kavrix is a portable Node.js CLI package. There is no separate self-hosted
server build or OS-specific encryption service. Install the same npm package on
Windows, macOS, or Linux with a supported Node.js runtime and a reachable
MongoDB deployment.

## Full command reference

```sh
kavrix --help
kavrix <command> --help
kavrix recovery --help
kavrix key --help
```

The practical reference is [docs/cli-reference.md](docs/cli-reference.md).
The security and data model notes are [docs/cryptography.md](docs/cryptography.md)
and [docs/data-model.md](docs/data-model.md).

## Maintainer checks

```sh
pnpm install --frozen-lockfile
pnpm verify
pnpm --filter kavrix package:smoke
pnpm --filter kavrix pack:check
pnpm audit --audit-level high
```

The npm package publishes only compiled JavaScript, declarations, the SBOM,
documentation, the license, and required runtime metadata. Never publish
portable keys, recovery kits, database URIs, local state, fixtures containing
secrets, or environment files.

## License and attribution

Kavrix is released under the MIT license. The package includes attribution for
the [EFF Short Wordlist for Passphrases #1](https://www.eff.org/files/2016/09/08/eff_short_wordlist_1.txt)
under [CC-BY-4.0](https://creativecommons.org/licenses/by/4.0/).
