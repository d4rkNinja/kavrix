# kavrix

A local, zero-knowledge credential vault backed directly by MongoDB. Kavrix
encrypts values before storage; it does not require or start a Kavrix server.

## Install

Requires Node.js `>=24.12.0 <25` or `>=25.1.0` and a reachable MongoDB deployment.

```sh
npm install --global kavrix
kavrix --version
kavrix --help
```

## Quick start

```sh
kavrix db ping
kavrix init
kavrix put github/token
kavrix list
kavrix view
kavrix get github/token --reveal
```

Commands prompt for sensitive input. Do not place secrets or MongoDB credentials
in normal command arguments or shell history. Use `kavrix <command> --help` for
the exact protected-input options available in this version.

## Main command groups

- `db ping`: test direct MongoDB connectivity.
- `init`: create a vault and passphrase-protected portable key file.
- `put`, `get`, `list`, `view`, `search`, `stats`: manage encrypted values.
- `has`, `rename`, `remove`: inspect or change records without accidental reveal.
- `vault list`, `vault status`: select and inspect vaults.
- `key status|verify|copy|replicate|assign|rewrap`: manage protected key files.
- `recovery create|verify|revoke|status|use`: manage protected recovery kits.
- `doctor`, `doctor health`: authenticate, diagnose, and perform bounded safe repair.

Plaintext output is opt-in. `get` requires `--reveal`; listing and dashboard
commands never display credential values.

## Security boundary

Vault payloads use XChaCha20-Poly1305 authenticated encryption. Protected key and
recovery files use Argon2id-derived keys and XChaCha20-Poly1305. Ciphertext is
bound to vault identity, schema/key version, revision, and security metadata.
MongoDB stores ciphertext plus visible operational metadata; it never receives
the portable key, recovery key, passphrase, root key, or decrypted value.

A protected local revision anchor detects older database snapshots and
same-revision metadata forks. Normal unlock fails closed if the anchor is
missing or inconsistent. `doctor health --accept-current` is an explicit trust
decision, not an automatic recovery shortcut.

Remote MongoDB URIs must explicitly enable validated TLS. Kavrix rejects insecure
TLS options. It cannot protect an already-unlocked machine from local
administrators, same-user malware, keyloggers, terminal capture, or process-memory
inspection. Losing all valid key files and recovery kits makes the vault
unrecoverable by design.

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
