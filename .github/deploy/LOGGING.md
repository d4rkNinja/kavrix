# GitHub deployment diagnostics

Build/install/check output streams into grouped GitHub Actions logs after redaction.
The private server log still retains raw output for operators; PM2 state and captured
environment output are not streamed. Known server/environment secrets, credential
URLs, authorization headers, common token formats, and private-key blocks are masked.
Do not deliberately print secrets: automatic redaction cannot recognize every possible
application-specific secret or arbitrary transformed value.

Failures add file/line annotations where compiler output supports them and a run
summary containing the command, original exit code, error excerpt, revision, phase,
and rollback outcome. Full sanitized output is in the step log. Untrusted command
output cannot inject GitHub workflow commands. No log artifacts or third-party
logging service is used.

The reporting change preserves build gates, process management, rollback operations,
and private runtime settings. A reporting update does not fix application errors.
