# Self-hosting Kavrix

Kavrix now has a production-runnable API process in the source workspace, but it
does not yet have a supported binary distribution or container image. Treat this
as an evaluation deployment, not a support or availability commitment. The API
is an opaque storage and synchronization service: it stores ciphertext,
authenticated envelopes, token hashes, and bounded sync metadata, and has no
vault-decryption capability.

## Runtime topology

Use Node.js `>=24.12.0 <25 || >=25.1.0` (24.19.x LTS is the tested baseline),
pnpm 11.21.x, and a transaction-capable MongoDB replica set.
A standalone `mongod` is insufficient because bootstrap, enrollment, revocation,
sync idempotency, and opaque record changes use transactions.

Put the API behind a TLS reverse proxy. Production mode rejects requests that do
not resolve to HTTPS. Proxy trust is disabled unless the operator supplies an
explicit IP-address or CIDR allowlist; hostnames and universal ranges such as
`0.0.0.0/0` are rejected. The process does not accept TLS private keys.

Install and build the exact workspace lockfile, then start the private API
package:

```sh
pnpm install --frozen-lockfile
pnpm --filter @kavrix/api build
KAVRIX_MONGODB_URI='mongodb://kavrix-api:REDACTED@mongo.internal:27017/kavrix?replicaSet=rs0&tls=true' \
  KAVRIX_API_TRUSTED_PROXIES='10.20.0.10/32' \
  pnpm --filter @kavrix/api start
```

Do not put the MongoDB URI in command arguments, checked-in environment files,
image layers, or logs. The environment-variable contract is required by the
current entrypoint, so use a service manager or orchestrator that injects the
value and restricts process/environment inspection. The example value is a
placeholder, not a usable credential.

The safe defaults are production mode, `127.0.0.1:3000`, database `kavrix`, a
24 MiB request-body limit, a 15-second graceful-shutdown deadline, no trusted
proxy, and vault bootstrap disabled.

## Configuration

| Variable                         | Required | Meaning                                                                                                          |
| -------------------------------- | -------- | ---------------------------------------------------------------------------------------------------------------- |
| `KAVRIX_MONGODB_URI`             | yes      | MongoDB connection URI; `mongodb://` and `mongodb+srv://` are accepted.                                          |
| `KAVRIX_DATABASE_NAME`           | no       | MongoDB database name; defaults to `kavrix`.                                                                     |
| `KAVRIX_API_ENVIRONMENT`         | no       | `production`, `development`, or `test`; defaults to `production`. Do not deploy `development` or `test`.         |
| `KAVRIX_API_HOST`                | no       | Listen IP/hostname; defaults to loopback. Use `0.0.0.0` only inside an appropriately isolated network namespace. |
| `KAVRIX_API_PORT`                | no       | TCP port from 1 through 65535; defaults to `3000`.                                                               |
| `KAVRIX_API_TRUSTED_PROXIES`     | no       | Comma-separated explicit IP/CIDR list. Configure the exact TLS proxy hops only.                                  |
| `KAVRIX_API_BODY_LIMIT_BYTES`    | no       | Request limit from 1 KiB through 64 MiB; the application default is 24 MiB.                                      |
| `KAVRIX_API_SHUTDOWN_TIMEOUT_MS` | no       | Graceful-close deadline from 100 ms through 300 seconds; defaults to 15 seconds.                                 |
| `KAVRIX_API_BOOTSTRAP_ENABLED`   | no       | Exact `true` or `false`; defaults to `false`.                                                                    |

Unknown `KAVRIX_API_*` variables and malformed values fail before MongoDB is
contacted. Exit code `78` means invalid configuration, `1` means startup or
shutdown failure, and `0` means a clean `SIGINT`/`SIGTERM` shutdown. Diagnostic
events never include configuration values or upstream exception text.

## Bootstrap and steady state

The bootstrap route is absent by default. Enable it only for a controlled initial
vault-provisioning window, complete provisioning with an independently generated
session bearer, then restart with `KAVRIX_API_BOOTSTRAP_ENABLED=false`. Do not
leave public bootstrap enabled. Its idempotency and credential-claim controls do
not replace network isolation and a short operator-controlled window.

`GET /health` is a process liveness endpoint. In production it is subject to the
same HTTPS enforcement and source rate limiting as other routes. It does not
prove MongoDB writability, replica-set durability, backup freshness, or end-to-end
client decryptability, so do not use it alone as a readiness or data-safety check.

## Operator requirements

- Use MongoDB authentication, encrypted transport, least-privilege database
  roles, replica-set durability, tested backup/restore, retention, and monitoring.
- Restrict ingress to the TLS edge and database egress to the intended replica
  set. Never expose the process's direct HTTP listener publicly.
- Capture structured Fastify request logs only in access-controlled storage.
  Authorization and successor-token headers are redacted, while startup errors
  are intentionally generic.
- Send `SIGTERM` for deployment shutdown and give the process at least the
  configured close deadline before an orchestrator sends a forced kill.
- Monitor liveness, MongoDB health, replica lag, disk, connection saturation,
  rate-limit pressure, and error rates without recording request bodies or
  credentials.

## Current deployment limitations

No maintained image, image SBOM/provenance, migration CLI, compatibility window,
automated rollback procedure, or supported backup runbook is published. The API
package remains private to the workspace. MongoDB initialization is idempotent at
startup, but schema compatibility across future releases is not yet guaranteed.
The liveness route is not a dependency-aware readiness check. Validate an exact
commit in a disposable environment before considering a deployment.

For local integration evidence, point the suites at an isolated replica set:

```sh
export KAVRIX_MONGODB_URI='mongodb://127.0.0.1:27017/?replicaSet=rs0&directConnection=true'
pnpm --filter @kavrix/storage test:integration
pnpm --filter @kavrix/api test:integration
```

The tests create and remove unique databases. See the
[Security Policy](../SECURITY.md) and [Release Process](./release.md); do not
publish, tag, or create a release from this procedure.
