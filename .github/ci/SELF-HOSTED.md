# Server CI and hosted-minute policy

Linux verification runs manually from Actions -> Server Linux CI on the repository-specific Sudarsan runner. It keeps Linux static checks, complete unit tests, three supported Node runtime checks, MongoDB probe, dependency audit, package checks, and coverage checks. The test MongoDB is temporary, bound to loopback port 37018, and removed after the job. Production databases and the Docker socket are not used.

The original full-platform CI and npm publication workflows are paused through GitHub workflow settings to prevent hosted-minute usage. Their source and release gates are preserved. Server Linux CI is not a substitute for the full-platform release gate. Windows/macOS/arm64 validation needs compatible self-hosted machines before restoring the original pipeline. npm trusted publication must use a supported publishing environment; it was not changed to token-based authentication.

CodeQL and dependency review now use the Linux server runner. Fork pull requests cannot execute repository code on the production server runner.

Server tools: /home/gandiv/.local/share/ci-tools, MongoDB 8.0.16 with verified SHA256, and pymongo 4.15.3. Do not point the test helper at production databases.

To restore the previous hosted workflows intentionally: gh workflow enable ci.yml -R d4rkNinja/kavrix; gh workflow enable publish.yml -R d4rkNinja/kavrix. These use hosted runners and can consume hosted minutes.
