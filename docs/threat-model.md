# Threat Model

> Design status: this is the pre-implementation threat model and therefore a
> set of required controls, not a statement that the controls have been built or
> tested. Verification status lives in
> [implementation-status.md](./implementation-status.md).

## Scope and security objectives

This model covers the `creds` CLI/TUI, local encrypted state, native keychain
integration, the zero-knowledge sync API, MongoDB, encrypted backups, attachment
storage, and the data exchanged among them.

Security objectives, in priority order, are:

1. Keep vault plaintext and unwrapped encryption keys out of the API, MongoDB,
   logs, command arguments, and unprotected persistent storage.
2. Detect modification or context swapping of ciphertext before returning any
   plaintext.
3. Admit only authenticated, non-revoked devices to server-side vault records.
4. Make deletion, schema change, sync conflict, key rotation, and restore
   explicit and recoverable where promised.
5. Minimize secret lifetime and accidental disclosure in the local terminal,
   clipboard, child processes, errors, and memory.

Availability is a goal but cannot be guaranteed by client-side encryption. A
malicious or failed service can deny access or destroy the only remote copy.

## Assets

### Confidential

- Portable vault keys and portable-key-file contents
- Master passphrases and key-file protection passphrases
- Recovery keys and device-local unlock secrets
- Unwrapped VRK, group, item, and attachment keys
- Decrypted group, item, note, history, audit, preference, and attachment data
- Plaintext device bearer tokens and enrollment invites
- MongoDB connection strings containing credentials

### Integrity-sensitive

- Wrapped-key slots and their active/revoked/version state
- Ciphertext envelopes, nonces, AAD context, and key versions
- Group templates, stable field keys, archived/orphaned values, and migrations
- Sync sequence, record revisions, cursors, idempotency results, and tombstones
- Device and invite state, token hashes, recovery kits, and backup manifests
- Audit/history retention and rotation checkpoints

### Availability-sensitive

- Every active unlock slot and recovery kit
- Encrypted records, attachments, history, and tombstones
- Device access and the API/MongoDB service
- The newest successfully committed state during sync or rotation

## Trust zones

| Zone                                   | Trust assumption                                                    | Consequence if compromised                                                        |
| -------------------------------------- | ------------------------------------------------------------------- | --------------------------------------------------------------------------------- |
| User and local CLI/TUI while unlocked  | Trusted to handle plaintext for the requested operation             | Same-user malware or host compromise can read active secrets                      |
| Native OS keychain                     | Trusted to enforce OS account/device protection                     | A compromised OS or account may recover remembered material                       |
| Local ciphertext cache                 | Untrusted for confidentiality and integrity until AEAD verification | Theft reveals metadata/ciphertext; tampering must fail closed                     |
| Network                                | Untrusted; TLS is still required                                    | TLS failure can expose tokens/traffic and enable denial or replay attempts        |
| Sync API                               | Trusted for authorization/coordination, not confidentiality         | It can deny, delete, withhold, reorder, or observe metadata, but must not decrypt |
| MongoDB and its administrators/backups | Untrusted for confidentiality                                       | A dump must not contain plaintext or unwrapped decryption keys                    |
| Terminal, clipboard, child processes   | Hostile disclosure surfaces                                         | Explicit, narrow release of a secret may be observed or retained                  |
| Dependencies and build/release systems | Supply-chain risk                                                   | Malicious code can bypass all client-side protections                             |

## Adversaries and capabilities

The design considers:

- an attacker with a MongoDB dump, leaked backup, or database-administrator
  access;
- a network attacker when TLS is correctly configured, plus a separate case for
  TLS misconfiguration;
- an unauthenticated or revoked API client;
- a malicious or compromised storage server that alters, swaps, replays,
  withholds, or deletes opaque records;
- a thief holding a powered-off or locked device and its local ciphertext;
- a local low-privilege observer of shell history, process listings, terminal
  output, logs, temporary files, or clipboard content;
- malformed input intended to trigger parser confusion, excessive allocation,
  path traversal, terminal control injection, or cryptographic misuse;
- accidental operator actions and interrupted processes;
- a compromised dependency, build worker, or release artifact.

This model does not assume the API or database is honest with ciphertext. It
does assume reviewed cryptographic primitives behave as specified and that the
local OS is not fully compromised during unlock.

## Threats and required controls

| Threat                                                    | Required controls                                                                                                                                              | Residual risk                                                                                                                           |
| --------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------- |
| Stolen MongoDB dump or leaked database backup             | Client-side XChaCha20-Poly1305; random key hierarchy; wrapped keys only; public KDF parameters; hashed device tokens/invites; plaintext-canary scans           | Record counts, sizes, opaque relationships, revisions, and timestamps remain visible; unlock-secret compromise defeats the related slot |
| Database administrator reads collections                  | Same as dump controls; API never receives decryption APIs or plaintext keys                                                                                    | Administrator can delete, replay, or selectively withhold records                                                                       |
| Network interception                                      | HTTPS with certificate verification; bearer-token authentication; AEAD remains end-to-end; no secrets in URLs                                                  | A TLS endpoint compromise can steal tokens and observe metadata, though not decrypt vault payloads                                      |
| Unauthorized API access                                   | High-entropy per-device tokens, server-side token hashes, constant-time verification where applicable, scopes, rate limits, revocation                         | A stolen live token grants its configured server access until expiry/revocation; it does not itself decrypt records                     |
| Enrollment-invite theft or replay                         | Independent random invite; masked/stdin input; hash-only storage; short expiry; single use; revocation; rate limits; atomic consume                            | Theft before legitimate use may enroll an attacker to opaque data, but the attacker still needs a valid unlock key to decrypt it        |
| Portable key submitted to server by bug                   | Narrow API schemas reject unlock/key fields; request bodies are not logged; contract and canary tests inspect traffic                                          | A malicious dependency inside the client process can still exfiltrate it                                                                |
| Offline guessing of a passphrase slot                     | Argon2id with per-slot random salt, serialized parameters, secure floor and calibrated higher cost; generic errors                                             | Human-chosen passphrases may remain guessable; a portable key is high entropy and is not treated as a passphrase                        |
| Portable/recovery key guessing                            | At least 256 bits of CSPRNG entropy; HKDF-SHA-256 domain-separated KEK; no reversible verifier                                                                 | Theft or disclosure of the actual key defeats that active slot                                                                          |
| Ciphertext, nonce, or tag modification                    | AEAD verification before parsing/use; no partial plaintext; typed internal error mapped to generic unlock/decrypt failure                                      | Availability can still be attacked by corrupting data                                                                                   |
| Ciphertext moved between vaults/groups/items/fields/slots | Canonical, unambiguous AAD binds immutable IDs, payload type, schema version, and key version                                                                  | Incorrect or mutable AAD design would reintroduce substitution risk and requires dedicated tests                                        |
| Malformed/oversized envelope or backup                    | Runtime schemas, strict versions and bounds, streaming verification, bounded allocation, fuzz/property tests                                                   | Parser/library vulnerabilities remain possible                                                                                          |
| Rollback/replay by server                                 | Monotonic server revision, protected highest-seen revision per retained device, versioned history and explicit conflict behavior                               | New/reinstalled devices and deletion of all protected local state weaken detection; no transparency log is planned initially            |
| Lost but locked device                                    | Ciphertext-only cache, native keychain protections, session auto-lock, device-token revocation, removal of remembered material                                 | Revocation cannot erase plaintext already viewed, copied, or cached by the device/OS                                                    |
| Accidental logging or telemetry                           | Telemetry off by default; structured allowlist logging; redaction; no bodies/auth headers; canary tests across logs/errors/snapshots                           | OS crash dumps or compromised logging dependencies may still capture process memory                                                     |
| Shell history and process-list disclosure                 | No secret-valued flags; masked prompt, protected file, or explicit stdin; `spawn`/`execFile` arrays with `shell: false`                                        | Explicit `--stdout`, `--key-stdin`, or user-authored shell redirection has unavoidable local exposure risk                              |
| Terminal escape/OSC injection                             | Treat all stored text as hostile; strip or encode control sequences; bound output; ANSI-free redirected output                                                 | Terminal emulator defects are outside the application's control                                                                         |
| Clipboard retention/monitoring                            | Copy without print, single value, auto-clear after comparison, no old-value restoration, no headless use by default                                            | OS clipboard history, sync, and monitoring malware may retain the secret; clearing is best effort                                       |
| Unsafe key file                                           | Dedicated format, size/type/ownership/ACL checks, symlink rejection, 0600/user-only permissions, optional Argon2id+AEAD protection, no silent copy             | User override, backup/sync software, or weak file passphrase can expose it                                                              |
| Plaintext temporary/export files                          | No plaintext temp files by default; explicit destination; restrictive permissions; guarded unsafe export; cleanup after verification failure                   | Filesystems, backups, editors, and deletion semantics may retain explicitly exported plaintext                                          |
| Schema/template deletion loses values                     | Archive encrypted orphan values, preview affected items, resumable versioned migration, separate purge                                                         | Explicit purge or loss of all history is irreversible                                                                                   |
| Interrupted key rotation                                  | Checkpointed migration, old key retained until new envelopes authenticate, idempotent retries, last-slot guard                                                 | Keeping an old slot during an explicit grace period extends its exposure window                                                         |
| Conflict overwrites a secret                              | Optimistic concurrency; no silent last-write-wins; encrypted history; local user resolution                                                                    | A user can choose the wrong version; server can suppress one side                                                                       |
| Attachment path traversal or partial output               | Encrypted metadata, safe filename/path handling, explicit destination, per-chunk authentication, temp output removed on failure                                | Explicit exports become plaintext at the chosen destination                                                                             |
| Dependency/build compromise                               | Minimal pinned dependencies, advisory and install-script review, lockfile review, provenance, SBOM, secret scanning, signed checksums, platform artifact tests | Supply-chain compromise inside the trusted client can exfiltrate plaintext; audits reduce but do not eliminate this risk                |

## Required abuse-case tests

The following are release-blocking security behaviors:

- Alter the nonce, ciphertext, authentication tag, AAD, item ID, group ID, slot
  ID, payload type, schema version, and key version independently. Every case
  must return no plaintext.
- Move a valid encrypted item to another group/vault and a wrapped item key to
  another item. Authentication must fail.
- Use wrong portable, passphrase, and recovery keys. User output must not reveal
  which prefix, vault, slot, or credential component was correct.
- Replay used, expired, revoked, and malformed enrollment invites concurrently.
  At most one atomic consume may succeed.
- Revoke a device token and verify subsequent sync is rejected without implying
  remote erasure of already decrypted data.
- Put unique canary strings in every secret class, then scan MongoDB, API and CLI
  logs, local cache, temporary directories, backups, errors, snapshots, argv,
  environment, and completion output.
- Inject CSI, OSC, C0/C1 controls, embedded NULs, bidirectional controls, long
  Unicode, and hostile filenames into every renderable field.
- Interrupt initialization, migration, sync, backup restore, and each rotation
  checkpoint. The last committed state must remain usable and no last valid
  unlock slot may be lost.

The full plan is in [security-testing.md](./security-testing.md).

## Explicit limitations

Kavrix cannot fully protect secrets from:

- malware running as the same user while the vault is unlocked;
- a compromised operating system, administrator/root account, kernel,
  hypervisor, terminal emulator, runtime, or cryptographic dependency;
- keyloggers, screen capture, terminal recording, clipboard monitoring/history,
  or memory scraping while plaintext is active;
- an attacker who has a portable key or its unprotected key file, a master
  passphrase, recovery key, remembered-device material, or another valid unlock
  slot;
- a malicious service deleting or indefinitely withholding records;
- rollback beyond the documented highest-seen-revision guarantee;
- metadata analysis of IDs, record/attachment sizes, timing, revisions, device
  activity, network addresses, and traffic volume;
- data that a legitimate user deliberately prints, exports, injects into a child
  process, or gives to another application;
- guaranteed memory erasure in JavaScript/V8 or guaranteed clipboard clearing
  across operating systems;
- future cryptanalytic breaks or undisclosed implementation vulnerabilities.

The design must never be described as unhackable, risk-free, military-grade, or
as protecting plaintext on a compromised unlocked host.

## Recovery and availability assumptions

There is no server-side recovery bypass. Loss of every active portable,
passphrase, recovery, and remembered-device slot makes the ciphertext
unrecoverable. Recovery material therefore needs an offline storage plan, and
encrypted backups need periodic restore drills.

Client-side encryption does not replace replication or backup. Device
revocation stops future authorized synchronization but cannot claw back secrets
already decrypted. Trash/history mitigate accidents only within their retention
and purge policies.

## Review triggers

Revisit this threat model before changing any primitive, envelope or AAD schema,
key-slot behavior, input channel, keychain adapter, API endpoint, persistence
metadata, logging policy, backup format, attachment format, sharing model,
runtime major version, or release target. Also revisit it after a vulnerability,
new supported platform, third-party security review, or material change in
attacker assumptions.
