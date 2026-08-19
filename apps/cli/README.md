# kavrix

A local, zero-knowledge credential vault that stores multiple independently
encrypted vaults in a protected local database file or MongoDB. Kavrix encrypts
private labels and values before storage; it does not require a Kavrix server.

## Install

Requires Node.js `>=24.12.0 <25` or `>=25.1.0`. MongoDB is optional; database
writes require a transaction-capable replica set or sharded topology.

```sh
npm install --global kavrix
kavrix --version
kavrix --help
```

## Quick start

```sh
kavrix db profile add work --datastore file \
  --data-file ./work.kavrix --key-file ./work.kavrix.key
kavrix db profile use work
kavrix db init --profile work
kavrix db vault create --profile work
kavrix put github/token --profile work --vault <vault-id>
kavrix get github/token --profile work --vault <vault-id>
```

Commands prompt for sensitive input. Do not place secrets or MongoDB credentials
in normal command arguments or shell history. Use `kavrix <command> --help` for
the exact protected-input options available in this version.

## Main command groups

- `db profile`: manage protected non-secret datastore routes.
- `db init`, `db status`: initialize or authenticate a multi-vault database.
- `db vault`: create, list, inspect, or rename independently encrypted vaults.
- `db recovery`: manage database-root recovery kits.
- `migrate database`: explicitly copy a legacy version 2 vault into a database.
- `db ping`: test direct MongoDB connectivity.
- `init`, `vault`, `key`, `recovery`, `doctor`: version 2 compatibility commands.
- `put`, `get`, `list`, `view`, `search`, `stats`: manage encrypted values.
- `has`, `rename`, `remove`: inspect or change records without accidental reveal.
- `vault list`, `vault status`: select and inspect vaults.
- `key status|verify|copy|replicate|assign|rewrap`: manage protected key files.
- `recovery create|verify|revoke|status|use`: manage protected recovery kits.
- `doctor`, `doctor health`: authenticate, diagnose, and perform bounded safe repair.

Plaintext output is opt-in. `get` requires `--reveal`; listing and dashboard
commands never display credential values.

## Security boundary

Vault payloads and the private database catalog use XChaCha20-Poly1305
authenticated encryption. Protected key and recovery files use Argon2id-derived
keys and XChaCha20-Poly1305; HKDF-SHA-256 separates database, catalog, anchor,
and vault wrapping purposes. Ciphertext is bound to exact database/vault identity,
purpose, versions, revision, and metadata digest. Kavrix does not claim
permanently unbreakable encryption.

A DRK-authenticated local revision anchor detects database rollback,
same-revision forks, and inconsistent catalog/vault heads. Normal database
unlock fails closed if that anchor is missing or inconsistent.

MongoDB stores two collections of ciphertext plus visible opaque routing
metadata; it never receives passphrases, DRKs, VRKs, labels, or decrypted values.
Remote URIs must explicitly enable validated TLS. Kavrix cannot protect an unlocked machine from local
administrators, same-user malware, keyloggers, terminal capture, or process-memory
inspection. Local sharing of the database file and matching owner key grants full
access to all vaults. User identities, grants, roles, revocation, ownership
transfer, environments, groups, structured items, and typed fields are not yet
implemented. Losing all valid owner keys and database recovery kits makes the
database unrecoverable by design.

## Documentation and support

- [Full README](https://github.com/d4rkNinja/kavrix#readme)
- [Command guide](https://github.com/d4rkNinja/kavrix/blob/main/docs/cli-reference.md)
- [Threat model](https://github.com/d4rkNinja/kavrix/blob/main/docs/threat-model.md)
- [Security reports](https://github.com/d4rkNinja/kavrix/blob/main/SECURITY.md)
- [Issue tracker](https://github.com/d4rkNinja/kavrix/issues)

## Word-list attribution

Generated passphrases use **EFF Short Wordlist for Passphrases #1**, from
https://www.eff.org/files/2016/09/08/eff_short_wordlist_1.txt, licensed under
CC BY 4.0: https://creativecommons.org/licenses/by/4.0/.

## License

MIT
