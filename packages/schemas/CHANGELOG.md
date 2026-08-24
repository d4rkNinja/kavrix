# @kavrix/schemas

## 0.2.0

### Minor Changes

- 3757e77: Add credential execution and policy firewall capabilities:

  - `kavrix run`: process-scoped secret execution with environment-only injection, project-file mappings, TTL caps, confirmations, and redacted JSON capture.
  - `kavrix policy` / `kavrix grant` / `kavrix audit`: sealed authorization state with allowlists, executable pins, working-directory restrictions, reveal separation, temporary grants, and stable exit codes.
  - `kavrix agent run` / `kavrix agent exec`: brokered credential firewall for AI coding agents.
  - MongoDB store: eagerly materialize both collections on connect so first-use transactions are race-free on empty deployments.
