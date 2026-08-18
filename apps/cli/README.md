# Kavrix

Kavrix is a local zero-knowledge encrypted credential vault for MongoDB. The executable talks
to MongoDB directly; no Kavrix server, API, sync daemon, or self-hosting process
is required.

## Install

```sh
npm install --global kavrix
```

Kavrix requires Node.js `>=24.12.0 <25 || >=25.1.0`.

## Quick start

```sh
kavrix db ping --database kavrix_local
kavrix init --database kavrix_local --key-file ./kavrix.key
kavrix put production --database kavrix_local --key-file ./kavrix.key
kavrix list --database kavrix_local --key-file ./kavrix.key
kavrix get production --database kavrix_local --key-file ./kavrix.key
```

Database URLs, passphrases, and credential values are read through masked
prompts or explicit stdin frames. They are never accepted as command-line
arguments or stored in a settings file. Protected-file passphrases must contain
at least 16 UTF-8 bytes. MongoDB receives only the authenticated encrypted vault
envelope and wrapped key-slot metadata.

Create an encrypted recovery kit after initialization:

```sh
kavrix recovery create --vault default --key-file ./kavrix.key \
  --recovery-file ./kavrix.recovery.kit
```

Use `kavrix --help` and `kavrix recovery --help` for the complete command
surface. Recovery kits are protected files, not plaintext backup codes, and
must be stored separately from the portable key file. Recovery commands reject
overwrite mode and require new output paths.

Run `kavrix doctor health` for fail-closed database, key, payload, recovery,
and rollback-anchor checks. A missing anchor is never silently recreated; use
`--accept-current` only after independently verifying the current MongoDB
snapshot.

## Security boundary

Without an authorized protected key file or recovery kit and its passphrase,
MongoDB ciphertext cannot be decrypted. A compromised process running as the
already-unlocked local user can still observe plaintext in memory. Losing every
protected key copy is permanent by design.

The package bundles and documents the EFF Short Wordlist for Passphrases #1,
available from <https://www.eff.org/files/2016/09/08/eff_short_wordlist_1.txt>,
under CC-BY-4.0. Attribution details are available from the EFF copyright page:
<https://www.eff.org/copyright> and the Creative Commons license:
<https://creativecommons.org/licenses/by/4.0/>.
