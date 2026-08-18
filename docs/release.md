# npm release

Kavrix publishes one platform-independent JavaScript package through npm trusted
publishing. Do not publish from a workstation and do not configure a long-lived
npm token.

## Artifact contract

The `kavrix` archive may contain only:

- `dist/**/*.js`
- `dist/**/*.d.ts`
- `dist/*.cdx.json`
- `README.md`
- `LICENSE`
- npm-generated `package.json`

MongoDB `7.5.0` is the only external runtime dependency. The compiled bundle
contains the CLI plus reviewed bundled libraries. The generated CycloneDX 1.6
SBOM records bundled components and the complete lockfile-resolved MongoDB
runtime graph. Workspace protocols, TypeScript source, tests, local state,
coverage, credentials, and plaintext canaries are forbidden.

## Local preflight

Run from the repository root:

```sh
pnpm install --frozen-lockfile
pnpm verify
pnpm --filter kavrix package:smoke
pnpm --filter kavrix pack:check
pnpm audit --audit-level high
```

`package:smoke` builds the exact archive, installs it in a temporary directory,
checks the allowlist and SBOM, rejects plaintext canaries/private paths, and
executes the installed version/help commands.

## Release commit

1. Set `apps/cli/package.json` to the intended unused npm version.
2. Update user documentation and release notes.
3. Run the full local preflight.
4. Commit and push the reviewed change to `main`.
5. Wait for CI and CodeQL to pass for the exact commit.

The release workflow independently requires those exact-SHA checks. It will not
publish a tag whose commit has failing or missing CI/CodeQL evidence.

## Automatic publication

Create and push a tag that exactly matches the package version:

```sh
git tag v<package-version>
git push origin v<package-version>
```

A `v*` tag starts `.github/workflows/publish.yml`. The workflow:

1. proves the tag is contained in `main` and matches `kavrix`'s version;
2. requires successful exact-SHA CI and CodeQL runs;
3. installs with the frozen lockfile and reruns verification/audit;
4. creates and inspects one release archive;
5. passes that immutable archive to the protected `npm` environment;
6. publishes through npm OIDC with provenance;
7. reconciles registry SHA-512 integrity with the inspected archive; and
8. creates the GitHub release only after npm confirms the version.

Stable versions publish to `latest`; `-beta.N` versions publish to `beta`.

## Safe retry

If publication needs to be retried for an existing tag, dispatch the workflow
from `main` with that exact tag:

```sh
gh workflow run publish.yml \
  --repo d4rkNinja/kavrix \
  --ref main \
  -f tag=v<package-version>
```

The retry is idempotent. If npm already contains the version, the workflow
requires its immutable integrity to match before continuing. Never delete and
recreate a published npm version.

## Required external configuration

- npm trusted publisher: repository `d4rkNinja/kavrix`, workflow `publish.yml`,
  environment `npm`, permission to publish.
- GitHub `npm` environment: deployment policy restricted to `main` and `v*` tags.
- Repository rulesets: protect `main` and release-tag creation.
- npm account: 2FA enabled; no token-based publication secret in GitHub.

For maximum security, require an environment reviewer and disallow administrator
bypass. This intentionally trades zero-click releases for a human approval at
the final publish boundary.

## Evidence limits

A successful package pipeline proves source/build/package policy for its runner.
It does not prove a user's MongoDB TLS configuration, backup policy, Windows ACL
behavior on every filesystem, or resistance to a compromised unlocked host.
