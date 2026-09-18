# Documentation

Kavrix is a local-first secrets firewall for developers, applications, and AI
agents. The supported product is one local CLI that authorizes scoped secret
execution, policies, grants, and agent brokers, and that stores multiple
independently encrypted vaults inside an encrypted local-file or MongoDB
database container. Legacy version 2 single-vault documents remain supported
through their stable compatibility commands and explicit migration. Historical
API, sync-daemon, and SQLite designs are not runtime paths.

The active `packages/tui` workspace powers interactive management for the
secrets firewall (`kavrix tui` / onboarding); it has no persistence or
cryptographic authority of its own. The current bare no-option TTY `init` path
creates a local encrypted database, default vault, and verified recovery kit
before selecting its profile. The generated protected, non-secret `config.toml`
remains a command reference and is not loaded automatically.

## Getting Started

- [Command guide](cli-reference.md): profiles, `run`, policies, grants, agents, credentials, and recovery.
- [Direct CLI model](direct-access-cli.md): why no Kavrix server is required.
- [Terminal output and Ink TUI](tui-guide.md): sanitized output and interactive firewall management.
- [Self-hosting note](self-hosting.md): no Kavrix server to deploy — local CLI only.

## Secrets Firewall

- [Command guide — run / policy / grant / audit](cli-reference.md): scoped secret execution and authorization surface.
- [Implementation status](implementation-status.md): factual supported surface and known limits.

## Authorization

- Policies, temporary grants, confirmation, TTL, executable pins, and audit —
  see the [command guide](cli-reference.md) sections on policies, grants, and
  audit.
- [Architecture](architecture.md): active components and trust boundaries.

## AI Agents

- [Command guide — AI agent credential firewall](cli-reference.md): `kavrix agent run` / `agent exec` broker model.
- [Implementation status](implementation-status.md): agent firewall verification notes.

## Vaults & Storage

- [Datastore policy](local-database.md): local two-file sharing and MongoDB transaction/TLS requirements.
- [Data model](data-model.md): what MongoDB can see and what remains encrypted.
- [Performance notes](performance.md): current direct-MongoDB behavior.

## Security

- [Threat model](threat-model.md): intended protections, exclusions, and rollback handling.
- [Cryptography](cryptography.md): active algorithms, key hierarchy, authenticated metadata, and limits.
- [Security testing](security-testing.md): release gates and environment-specific evidence.
- [Dependency policy](dependency-policy.md): shipped dependency and SBOM rules.

## Recovery

- [Recovery kits](backup-and-recovery.md): create, verify, revoke, and use protected recovery material.

## Reference

- [Architecture](architecture.md)
- [Implementation status](implementation-status.md)
- [Release procedure](release.md): local preflight, trusted publication, and recovery reruns.
- [Active release boundary](active-release-boundary.md)

Run `kavrix <command> --help` for the command options installed with a specific
version. Documentation must not override the executable's safety checks.
