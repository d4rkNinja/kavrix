# Agent setup and troubleshooting

Kavrix starts an agent process with a local broker endpoint and a session token.
The agent receives no vault credential values. Its children request a named
permission through `kavrix agent exec`; the broker authorizes each request and
injects the referenced secret into the authorized child only. This requires the
agent to use that command; arbitrary commands are not automatically intercepted.

## Configure and validate

Use an existing bound database profile with the required credential. The
[getting-started guide](getting-started.md) covers vault setup and storage.
Create a non-secret project file named `kavrix.yaml`:

```yaml
version: 1
agents:
  bot:
    permissions:
      gh-issue-list:
        secret: github/token
        commands: [gh]
        env: GITHUB_TOKEN
      forbidden:
        deny: true
```

`gh-issue-list` is the permission key; `gh` is the permitted executable basename.
The `env` mapping is required for a credential-backed agent request. This example
permits the `gh` executable, not only its `issue list` subcommand. Use the
canonical permission fields for executable hashes, working-directory restrictions,
confirmation, TTL, and use limits when needed; see [command reference](cli-reference.md).

Validate before launching:

```sh
kavrix agent run --agent bot --config kavrix.yaml --dry-run --json
kavrix agent exec gh-issue-list --config kavrix.yaml --dry-run --json
```

The first checks the named agent and datastore binding. The second checks that
the permission exists in a configured agent. Neither unlocks the vault, verifies
credential existence, evaluates a future invocation, or creates a broker session.
Success here does not mean a later operation is authorized.

Without `--config`, `agent run`, `agent exec --dry-run`, and project-aware `run`
discover exactly one `kavrix.yaml`, `kavrix.yml`, or `kavrix.json` in the current
working directory. Multiple defaults require an explicit path. Invalid or
unreadable files fail closed. Explicit paths never fall back to discovery.

## Start and use a live broker

Restart the live agent session after editing its project permissions. The broker
uses the validated configuration loaded at startup; file edits do not replace
that running session's permission snapshot.

Start your installed agent executable after the literal separator, for example:

```sh
kavrix agent run --agent bot --config kavrix.yaml -- codex
```

Use `--profile <profile-id>` and `--vault <vault-id>` when the selected profile's
default vault is not the intended target. Unlock through the masked prompt or
an explicitly requested stdin flow. Do not put protected values in command arguments.

In that agent process tree, request the exact configured permission:

```sh
kavrix agent exec gh-issue-list -- gh issue list
```

That child receives `GITHUB_TOKEN`; the agent itself does not. Child output is
bounded and secret-redacted, and authorization outcomes are audited. Agent
descendants inherit broker access. This does not protect an unlocked host from
same-user malware, administrators, or an authorized child that misuses its secret;
see the [threat model](threat-model.md).

## Use the TUI

Open the Agent screen, press `g`, enter `bot`, then enter the project path or
leave it empty for discovery. This performs configuration dry-run without unlock
input. It does not start or monitor a broker. Use the CLI to launch a live agent;
inspect audit through the Policy/Grant/Audit screen after unlocking.

## Diagnose failures

- Missing project file: start in the project directory or pass `--config`.
- Multiple defaults: choose one explicitly; Kavrix does not guess which policy wins.
- Agent not defined: match the top-level agent name, including case.
- Unknown permission: use `gh-issue-list` from the example, not the executable name `gh`.
- `no-injection-mapping`: add `env` to an allow entry and validate the configuration.
- Other denials: check command allowlists, executable pins, directory restrictions,
  confirmation, and active TTL/use limits. Dry-run cannot prove runtime authorization.
- Broker unavailable: invoke `agent exec` from the running agent's process tree.
- Broker busy: at most four requests execute concurrently, with at most 32 queued
  requests and a ten-second admission deadline. A long-running child does not
  occupy every execution slot. The busy response uses the existing `invalid-request`
  reason and exit code 14; review whether the requested operation is safe to retry.

Windows command scripts cannot be run targets because they require shell
re-parsing. Use a native executable. Never send session tokens, passphrases,
connection strings, or decrypted values in a bug report.
