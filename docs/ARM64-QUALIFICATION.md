# Experimental ARM64 target

ARM64 qualification is deferred beyond M2 by the owner's scope decision. Current Linux arm64 artifacts are cross-compiled experimental builds. Native tests and operating evidence are required before advertising supported ARM64 deployment.

Promotion requires all of the following evidence on native ARM64.

- The complete Go and pinned CRS compatibility suites pass.
- Fresh installation and the complete packaged-service, TLS, account and recovery workflow pass on the declared distribution and systemd version.
- The two-hour multi-application event/audit fault profile passes, with full reconciliation and finite resource use.
- Gateway-process RSS, CPU and latency define an ARM64-specific reference capacity profile.
- Abrupt VM interruption and the declared previous/current upgrade/rollback pair preserve acknowledged state.
- Artifacts retain exact binary/package hashes, platform/kernel details, test settings and documented limits.

An opt-in job in `.github/workflows/m2-qualification.yml` prepares native hosted execution. Building an artifact or preparing a job does not establish native qualification. ARM64 promotion is a separate supported-platform decision and does not block the scoped Linux amd64 M2 milestone.
