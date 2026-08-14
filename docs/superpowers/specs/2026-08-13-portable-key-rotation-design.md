# Portable-key rotation design

## Scope

`creds key rotate` changes only the credential that wraps the existing vault
root key. It does not rotate the vault key version, decrypt or re-encrypt
preferences/items/attachments, or send a portable key to the API. The API sees
only the public key-slot envelope and an encrypted audit sidecar.

## Command surface

- `creds key rotate --generate-file <path>` creates a fresh portable key in a
  protected key file and completes the rotation.
- `creds key rotate --replacement-file <path>` imports an existing portable key
  file and completes the rotation.
- `creds key rotate resume <operation-id> --replacement-file <path>` resumes a
  journaled operation after an interruption.
- `creds key rotate list` lists only operation IDs, public state, and timestamps.

Reauthentication uses the existing masked/device/key-file flow. Generation and
file import never place key material in argv, logs, JSON output, SQLite, HTTP
requests, or the operation journal. Generated files are bound to the new slot;
imported files must be unbound. A generated file is read back before network
publication to confirm possession and binding.

## Durable state machine

The local rotation journal stores public slot envelopes, revisions, source
kind/path-independent metadata, and an authenticated checkpoint. It never
stores the replacement key or the vault root key.

```text
prepared --publish pending--> pending-published
pending-published --promote--> active-published
active-published --confirm replacement and revoke old--> completed
```

Every remote mutation is followed by a vault read-back. If the mutation or the
journal write is interrupted, resume compares the fetched vault against the
exact operation snapshot and advances only an already-applied, identical
transition. Any concurrent or divergent change fails closed; the old active
slot is not revoked in that case.

## Authenticated checkpoint transcript

The crypto package adds a portable-slot-specific HMAC checkpoint. It binds the
operation ID, vault, source/replacement slot IDs, source revision, canonical
source/replacement slot digests, current lifecycle state, remote revision, and
an ordered transcript digest. The checkpoint is stored beside the public
journal record and verified after reauthentication on every resume. This is
separate from the existing payload-rotation checkpoint, whose key-version
contract intentionally requires `fromKeyVersion < toKeyVersion`.

## Safety ordering

1. Authenticate the current device/session and unwrap the existing root key.
2. Build and locally verify the replacement slot; persist `prepared`.
3. Publish/read back the replacement as `pending`; persist the checkpoint.
4. Promote/read back the replacement as `active`; persist the checkpoint.
5. Unlock the active replacement on this device and compare its root key in
   constant time.
6. Revoke/read back the old slot; persist `completed`.

The old slot remains active until step 5 succeeds. Because the source and
replacement use the same current key version and the same root key, encrypted
payload bytes remain unchanged throughout.

## Failure and exposure guidance

Generic lifecycle errors do not reveal whether authentication, journal, or
remote state was close. A failed rotation leaves the old slot usable unless a
server-side revocation was already confirmed. If a portable key file may have
been exposed, users must revoke that slot (and any copied file) separately;
rotating a replacement credential does not revoke unrelated device/session
tokens.

## Focused verification

Tests cover generated and imported replacement paths, no plaintext canary in
the journal or captured HTTP requests, unchanged encrypted preferences, exact
resume after each remote/journal boundary, idempotent replay, authenticated
checkpoint tampering, source/replacement divergence, wrong-key confirmation,
and the rule that old-slot revocation occurs only after replacement
confirmation.
