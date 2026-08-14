# Fresh-home recovery and second-device acceptance design (#47)

## Goal

Prove the complete command-only Device A to Device B journey through the
existing production composition: Device A creates encrypted data and an invite,
Device B joins from an empty home using the portable key, synchronizes and
decrypts locally, and a later Device B request is denied after Device A revokes
the device.

## Architecture

The acceptance test runs the real CLI catalog against two isolated
`CREDS_HOME` directories. Each home uses the real production environment,
SQLite local store, lifecycle journal, cryptographic session, and protected
state composition. The only test-owned adapters are the native keychain entry
factory and clipboard factory, which stand in for operating-system services
while delegating all vault logic to the production packages.

The test control plane implements the canonical bootstrap, session, vault,
invite, enrollment, key-slot, device-revoke, sync-pull, and sync-push routes.
It validates every request and response with the shared schemas, authenticates
opaque bearer classes, stores only vault/key-slot ciphertext and opaque sync
records, and maintains one-time invite and device-revocation state. It never
receives the portable key, VRK, or decrypted field values.

## Data flow

1. Device A runs production `init`, creates a group, credential, username, and
   sensitive password, then synchronizes the encrypted mutations.
2. Device A issues an invite with `device invite create`, and the test captures
   only the rendered invite token for the explicit framed join input.
3. Device B starts with a distinct empty home and runs `device join` with the
   invite and portable key in one bounded secret frame batch. Recovery creates
   the local device slot/profile and performs first opaque sync.
4. Device B runs `show`; the output proves the username decrypts locally while
   the sensitive password remains redacted. The local SQLite bytes and all
   captured server bodies are scanned for plaintext canaries and the portable
   key.
5. Device A revokes Device B. A fresh Device B sync attempt fails with the
   generic authentication result, proving server-side access denial without
   exposing token or secret material.

## Failure and security coverage

- Empty-home isolation and real resource cleanup are asserted for both homes.
- Invite, session, and successor headers are treated as opaque credentials;
  their bodies are schema-validated and never compared to plaintext canaries.
- The server fixture rejects malformed route payloads, wrong vault bindings,
  reused invites, revoked sessions, and stale key-slot revisions.
- Device B must not be able to read before successful enrollment, and revocation
  must deny a new authenticated session even though B's local encrypted cache
  remains present.
- The test does not inspect or decrypt server state. Local decryption is
  verified only through the production read/show path.

## Out of scope

Join crash-boundary injection is covered by #46 and the lower-level join
recovery suites. Backup/restore and whole-repository plaintext scanning remain
in #48 and #49. No API/Mongo implementation or new cryptographic primitive is
introduced.

## Verification

The focused test, affected CLI/client/local-store suites, package typechecks,
targeted lint/format/diff checks, CLI build, and packed smoke must pass on the
managed Windows environment. The issue remains local-only until external
GitHub mutation is explicitly authorized.
