# Application-layer engineering guide

These applications compose Kavrix's library packages into runnable processes.
Keep policy, cryptography, persistence contracts, and wire schemas in their
canonical packages rather than redefining them here.

## `apps/cli`

- The product is Kavrix and the public executable is `kavrix`.
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

There is no `apps/api` in this repository. Kavrix is local-first: storage is a
local protected file or the user's own MongoDB deployment, and there is no
Kavrix-hosted service. Do not create server applications here without an
explicit architecture decision.

## Required verification

Run the application's format, lint, typecheck, build, unit, integration, coverage,
and package-smoke gates that apply. API persistence changes require a real MongoDB
replica-set test; CLI changes require actual packed-executable tests.
