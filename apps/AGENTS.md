# Application-layer engineering guide

These applications compose Kavrix's library packages into runnable processes.
Keep policy, cryptography, persistence contracts, and wire schemas in their
canonical packages rather than redefining them here.

## `apps/cli`

- The public executable is `creds`; keep the product label and command name easy
  to rename.
- Commands call use-case ports. They do not import MongoDB, implement encryption,
  or use production fake data.
- Read secrets only from a masked prompt, an explicitly requested stdin flow, a
  protected Kavrix key file, or the native keychain. Never accept a secret value
  in argv, a URL, a normal flag, or an environment variable.
- Generate command descriptors and field views from canonical schemas and group
  templates. Do not build separate forms for each credential type.
- Sanitize all untrusted terminal text. Piped and structured output is ANSI-free
  and redacts secrets by default.
- Copy and reveal operations are explicit, field-scoped, time-bounded, and never
  print the value as a side effect.

## `apps/api`

- The API is a zero-knowledge authorization, synchronization, and ciphertext
  storage service. It must never import a decrypt/unwrap function or receive a
  portable key, passphrase, recovery key, unwrapped data key, or plaintext vault
  payload.
- Infer request and response types from `@kavrix/schemas`; do not declare parallel
  DTO interfaces.
- Authenticate and rate-limit before expensive work, validate every body and
  response, bind all records to the authenticated vault, and return generic
  authentication errors.
- Persist bearer-token hashes only. Credential-class transitions must be atomic,
  replay-bounded, globally unique, and safe under concurrent requests.
- Production startup is fail-closed: bootstrap is disabled by default, proxy
  trust is explicit, and errors/logs never expose connection strings or tokens.

## Required verification

Run the application's format, lint, typecheck, build, unit, integration, coverage,
and package-smoke gates that apply. API persistence changes require a real MongoDB
replica-set test; CLI changes require actual packed-executable tests.
