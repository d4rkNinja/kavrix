# Branch deployment to Sudarsan

Open Actions > Deploy selected branch to server > Run workflow.
Keep **Use workflow from** on `main`. Select the target repository branch in the **branch** dropdown.
The server refreshes branch choices every five minutes; reopen or refresh the Actions page after adding a branch.
Choose **build** to verify without switching the running service, then **deploy** to activate.
The branch input works even when an older branch has no deployment workflow.
Pushes and pull requests do not deploy. Existing CI and release workflows are preserved.

Target: `/home/gandiv/projects/kavrix/app`. Runner label: `sudarsan-d4rkninja-kavrix`.
The workflow uses pinned checkout and a read-only token. Only trusted repository writers
may run server deployments; branch code executes on the production host as gandiv.
Do not add pull_request or pull_request_target triggers to this production workflow.
The server's private LAN address needs no public inbound SSH access.

Builds use committed lockfiles in isolated `.deploy/releases` directories. Server env files
are linked locally, never committed or uploaded. Original source checkout and local changes
are preserved. Build logs and runtime configuration remain protected on the server.
A global lock serializes builds across projects to bound memory use.

Deployment switches only this project's PM2 processes or static dist path. Nginx's existing
canonical roots remain valid. Failed runtime health checks restore the prior targeted PM2
configuration/static path. At most the current and previous successful releases are retained
after activation. Do not manually erase `.deploy` while a release is running.
DevProfile checks /health/ready; Karnsha checks process/listener availability, which does not prove all database readiness.
Database migrations are deliberately separate and must be reviewed for the selected branch.
No automatic database migration, npm publication, CLI network operation, or artifact signing occurs.

This project has no currently registered production service. Deploy publishes the built
release through `.deploy/current`; it does not start a new API/CLI/network service.

Deployment state is excluded from the server checkout through git info/exclude. Builds use their own cloned git metadata, so git-aware scripts see the selected commit. The global lock is stored under ~/.local/state/server-deploy.
The current main branch builds the Kavrix CLI; it no longer contains the older API workspace. The CLI output is validated without npm publication.
