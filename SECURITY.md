# Security Policy

Kavrix (`CredVault` by default, with the `creds` executable) is intended to be a
zero-knowledge credentials vault. Security claims are limited to behavior that
has implementation and test evidence in
[docs/implementation-status.md](./docs/implementation-status.md).

## Supported versions

There is currently no supported public release.

| Version                              | Security support                  |
| ------------------------------------ | --------------------------------- |
| Unreleased development code          | Not supported for production data |
| Any copied, preview, or ad-hoc build | Not supported                     |

Do not store real credentials in this repository or an unreleased build. Before
a release, this table must name the maintained release lines and their security-
update window. End-of-life versions will not receive fixes and must not be used
for sensitive data.

The repository can build a self-contained `kavrix` npm archive, but “packs
successfully” is not a supported release state. npm ownership, trusted-publisher
configuration, private vulnerability reporting, secret scanning with push
protection, a successful CodeQL run, a named private contact, signed release
authorization, and post-publication verification remain mandatory. See
the [Public Release Process](./docs/release.md).

## Reporting a vulnerability

Do not open a public issue, discussion, pull request, or chat containing an
unfixed vulnerability, exploit, key, credential, token, private vault record, or
database dump.

The preferred reporting route is the repository host's private vulnerability-
reporting feature (for GitHub, use **Security → Report a vulnerability**) once it
is enabled. Include:

- affected version, commit, package, platform, and installation method;
- a concise impact statement and the trust boundary crossed;
- minimal reproducible steps or a small clearly fake proof of concept;
- whether portable/recovery keys, plaintext vault data, device tokens, invites,
  backups, or release artifacts may be exposed;
- any known exploitation or disclosure deadline;
- a safe way to contact you.

If private vulnerability reporting is unavailable, do not publish technical
details. Ask the repository owner for a private security contact through the
hosting platform without including the vulnerability. A dedicated private
address/reporting channel is a release blocker and must be added here before the
first public release.

Never send real secrets as evidence. Generate a unique fake canary and redact
tokens, authorization headers, MongoDB credentials, portable/recovery keys,
passphrases, key-file contents, decrypted records, and memory dumps. If a dump is
strictly necessary, coordinate a protected transfer and retention plan first.

## Response and disclosure process

Maintainers should:

1. acknowledge privately and assign a tracking identifier;
2. reproduce without requesting production secrets;
3. assess affected versions, data exposure, exploitability, and whether keys or
   device tokens require rotation/revocation;
4. prepare tests that fail before the fix and cover adjacent trust boundaries;
5. obtain security review proportional to impact;
6. release a minimal supported fix with an advisory, upgrade instructions, and
   any recovery/rotation steps;
7. coordinate public disclosure after users have a practical mitigation.

These are process targets, not guaranteed response times while the project has
no published security team or supported release. Once ownership and service
levels are established, this section must name them explicitly.

## Security model summary

The planned baseline is:

- Node.js `>=24.19.0 <25` LTS with strict ESM TypeScript;
- client-side XChaCha20-Poly1305 authenticated encryption and secretstream
  through standard `libsodium-wrappers` 0.8.4 (not the sumo build);
- a mandatory 256-bit random portable vault key, with HKDF-SHA-256 deriving only
  a VRK-wrapping KEK;
- optional Argon2id passphrase slots and independent recovery/device slots;
- independent random 256-bit VRK, group, item, attachment, device, and recovery
  keys;
- versioned envelopes with fresh nonces and context-bound AAD;
- an API and MongoDB that store ciphertext, wrapped keys, public KDF parameters,
  opaque sync metadata, and hashes of session/device tokens, enrollment
  credentials, and invites, but cannot decrypt vault records.

Full details and current limitations are in
[docs/cryptography.md](./docs/cryptography.md),
[docs/threat-model.md](./docs/threat-model.md), and
[docs/portable-key-and-device-enrollment.md](./docs/portable-key-and-device-enrollment.md).
This disclosure is a design description until the corresponding status rows are
verified.

## What must never be submitted or stored

Plaintext portable keys, passphrases, recovery keys, device tokens, enrollment
invites, root/group/item/attachment keys, decrypted credential data, notes,
private keys, MongoDB credentials, or production dumps must not be placed in:

- issues, pull requests, patches, commit messages, or test fixtures;
- command-line arguments, URLs, shell history, screenshots, or recordings;
- logs, telemetry, crash reports, snapshots, or CI artifacts;
- email/chat reports without a separately agreed protected transfer;
- MongoDB or API payloads as plaintext.

If you believe real material was exposed, treat it as compromised: revoke the
affected device token/invite, rotate the affected unlock slot or data key as
appropriate, preserve only sanitized incident evidence, and follow the provider-
specific credential rotation process.

## Dependency and cryptography policy

- Do not invent cryptographic primitives or add placeholder/fake cryptography.
- Security-sensitive dependencies require a documented purpose, current
  maintenance/advisory review, lockfile pinning, dependency-tree review, and
  cross-platform/package inspection.
- Avoid install scripts unless required and reviewed. Minimize native and
  transitive code at the plaintext boundary.
- Keep Node.js on a supported patched 24.x LTS release; Node.js recommends LTS
  lines for production: [Node.js release policy](https://nodejs.org/en/about/previous-releases).
- Passphrase Argon2id uses the asynchronous Node 24 `crypto.argon2`, marked
  stable in Node 24.19. Supported 24.x updates still require RFC-vector and
  serialized-parameter compatibility tests. The native `argon2` package is
  excluded to avoid another binary/install-script dependency:
  [Node stability commit](https://github.com/nodejs/node/commit/7bb6dab70c5ad2a8585c26a3f1cd1da2907f33ee).
- HKDF must follow [RFC 5869](https://datatracker.ietf.org/doc/html/rfc5869), and
  Argon2id parameters/formats must follow the project contract and
  [RFC 9106](https://datatracker.ietf.org/doc/html/rfc9106).
- Primitive, parameter-floor, AAD, envelope, key-file, or key-lifecycle changes
  require a new version where interpretation changes, migration tests, threat-
  model update, and security review.
- A clean audit is not proof of secure design. Releases also require tamper,
  AAD-swap, malformed-input, concurrency, canary-leak, restore, and platform
  testing described in [docs/security-testing.md](./docs/security-testing.md).

## Safe research guidelines

For a future hosted service or official release, researchers must limit testing
to accounts, devices, vaults, servers, and data they own or have explicit
authorization to test. Do not:

- access, modify, retain, or disclose another person's vault or metadata;
- degrade service, bypass rate limits at scale, or run destructive/denial tests
  against shared infrastructure;
- use social engineering, credential stuffing, malware, persistence, or physical
  attacks;
- publish an unpatched exploit or any retrieved secret;
- test third-party providers outside their own rules.

Stop if a test exposes data outside the authorized scope, preserve minimal
sanitized evidence, and report privately. These guidelines do not grant access
to any system or create a safe-harbor promise. Any future disclosure program
must publish its own explicit terms.

## Security update and release policy

Security fixes must include a regression test and must not weaken an assertion,
silently change the wire/crypto format, or add a server-side decryption path.
Maintainers must determine whether users need to upgrade clients/servers, rotate
portable or recovery slots, rotate data keys, revoke devices/tokens, recreate
backups, or restore from a known-good revision.

Public release artifacts require passing format/lint/type/test/build/audit and
plaintext-canary gates, package allowlist inspection, an SBOM, provenance-
capable least-privilege CI, verified platform artifacts, and signed checksums
where practical. Publishing, tagging, or signing is a separate authorized action
and is never implied by this policy.

The prepared npm workflow uses no long-lived registry token. It packs once,
inspects and offline-installs that exact archive, verifies the embedded
CycloneDX SBOM against the executable hash, and gives the same `.tgz` to npm OIDC
with provenance. A tag/package-version mismatch or any workspace protocol,
unexpected archive path, missing license, fixture canary, runtime dependency, or
failed platform smoke test closes publication.

## Important limitations

Initial-vault creation is an explicit, disabled-by-default server capability.
Enabling it opens a rate-limited provisioning endpoint; deployment operators
must restrict the provisioning window and disable it afterward. The backend
transaction has real replica-set evidence and native session storage has real
Windows Credential Manager evidence, but macOS/Linux native behavior and the
end-user `creds init` composition are not yet verified.

The design cannot protect plaintext from malware or an administrator/root user
on an unlocked host, keyloggers, screen/terminal capture, clipboard monitoring,
or memory scraping. Anyone holding a valid unlock method can decrypt the slot it
opens. Device revocation prevents future API access but cannot erase secrets
already decrypted. A malicious server can deny, delete, withhold, or replay data
within the documented rollback-detection limits. JavaScript memory wiping and
clipboard clearing are best effort.

Losing every valid portable, passphrase, recovery, and remembered-device unlock
method makes the encrypted vault unrecoverable. There is intentionally no API-
side recovery backdoor.
