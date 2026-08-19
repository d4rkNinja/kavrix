# Documentation

This documentation describes the supported Kavrix product: one local CLI that
encrypts credential values and stores authenticated ciphertext in a hardened
local file or directly in MongoDB. Historical API, sync-daemon, SQLite, and TUI
designs are not supported runtime paths.

## Start here

- [Command guide](cli-reference.md): setup, everyday commands, keys, recovery, and health checks.
- [Datastore policy](local-database.md): local-file safety plus MongoDB URI and TLS behavior.
- [Recovery kits](backup-and-recovery.md): create, verify, revoke, and use protected recovery material.
- [Direct CLI model](direct-access-cli.md): why no Kavrix server is required.

## Security model

- [Architecture](architecture.md): active components and trust boundaries.
- [Threat model](threat-model.md): intended protections, exclusions, and rollback handling.
- [Cryptography](cryptography.md): active algorithms, key hierarchy, authenticated metadata, and limits.
- [Data model](data-model.md): what MongoDB can see and what remains encrypted.
- [Security testing](security-testing.md): release gates and environment-specific evidence.
- [Dependency policy](dependency-policy.md): shipped dependency and SBOM rules.

## Maintainers

- [Implementation status](implementation-status.md): factual supported surface and known limits.
- [Release procedure](release.md): local preflight, trusted publication, and recovery reruns.
- [Performance notes](performance.md): current direct-MongoDB behavior.

Run `kavrix <command> --help` for the command options installed with a specific
version. Documentation must not override the executable's safety checks.
