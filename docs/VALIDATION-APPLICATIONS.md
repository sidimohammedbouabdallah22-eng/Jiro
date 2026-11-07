# Application routing validation

Recorded on 3 November 2026 against the schema-2 application increment. Tests use synthetic policies, temporary storage and harmless local backends.

## Checks

| Check | Result and evidence |
|---|---|
| Root Go suite on Windows | Passed, including actual candidate/admin subprocess recovery tests, the schema-1 storage fixture and previous-binary policy compatibility. `artifacts/applications-full-tests.log` |
| Focused application, certificate and recovery regressions | Passed. `artifacts/applications-regression.log` |
| Full gateway, certificate and operations tests on Linux amd64 | Passed in Ubuntu 24.04 under WSL. Optional subprocess tests require executable environment variables. The separate packaged service exercise runs actual candidate rehearsal and cutover. `artifacts/applications-{gateway,certificates,operations}-linux.log` |
| Full pinned CRS compatibility corpus | 5,193 passed, zero failed/skipped/ignored/errors, using the existing 16 reviewed platform adaptations. The lab uses its established single-application PL4 detection profile. Multi-application tests separately exercise the production per-application compiler. `artifacts/applications-crs-regression.json` |
| Real Chrome console | Passed login, migration, creation, selection, isolated enforcement, removal, retained event filtering across restart and existing policy/exception/history workflows. `artifacts/applications-browser.log` |
| Linux package and systemd service | Passed staged installation/refusal, dedicated account, hardening, file credentials, trusted TLS, certificate rejection/renewal, forwarded identity, schema-2 migration, separate portal rule, SNI/Host mismatch refusal, event filtering, restart, backup/verify/upgrade rehearsal and service cutover to restored two-application state. `artifacts/applications-systemd.log` |
| Concurrent mixed traffic | 1,024 requests from 16 workers reconciled 256 clean, 256 blocked, 256 detection-only and 256 unrouted requests. All 768 security occurrences were durably acknowledged, with 256 application-filtered events for each inspected application. `TestApplicationConcurrentTrafficAccounting` |
| Static checks | `go vet ./...` passed. `artifacts/applications-vet.log` |
| Authority fuzzing | 74,527 executions passed canonicalization and normalization invariants in ten seconds with two workers. `artifacts/applications-authority-fuzz.log` |
| Packages | Linux amd64 and arm64 archives built with matching SHA-256 sidecars. amd64 service executed under WSL. arm64 build only |

The focused tests cover separate backend selection with duplicate custom rule IDs across engines, independent modes/body limits/scoped exceptions/response inspection, unknown and malformed host refusal, normalized authority, absolute-form refusal, forwarded-host spoofing, and real TLS HTTP/2 SNI boundaries. They also cover deep-copy isolation, partial compiler failure, failed persistence with reserved orphan revision, in-flight upstream retention, migration/validation separation, restart and whole-deployment rollback.

Certificate tests refuse uncovered application activation and renewals dropping a configured hostname. A failed policy commit retains prior certificate requirements. A concurrent reload waits for the policy commit and validates the resulting hostname set. API tests check authentication, foreign origins, stale revisions, change reasons and durable create/delete audit outcomes.

The recovery tests preserve both applications and their policies through backup/restore. A schema-1-only capability profile is refused for active schema 2 and for a legacy policy with schema-2 committed ancestors. The preserved previous Windows executable is refused for the migrated checkpoint and successfully rehearses against the pre-migration checkpoint.

## Evidence boundaries

One full Linux gateway run alongside Windows recovery tests and the systemd qualification hit the event database's five-second startup deadline in `TestHistoryWriteFailurePreservesPolicy`, before the test's injected history failure. The affected test passed three isolated repetitions in 0.14–0.27 seconds. The subsequent isolated full Linux suite passed. The failing run is retained in `artifacts/applications-gateway-linux-concurrent-startup-timeout.log`, with the repeats in `artifacts/applications-linux-startup-recheck.log`. Shared-host contention is a possible cause. The cause remains unconfirmed, and startup/resource contention belongs in sustained sizing qualification.

The existing raw CRS result remains 15 expectation differences and one fixture error before the 16 documented adaptations. The new compatibility run preserves that accounting. This increment's mixed-traffic test is bounded and synthetic. Earlier single-application long-soak results do not establish multi-application sizing.

Eight applications, 16 hosts each and 96 KiB compact configuration are initial implementation bounds. Resource, storage and administrator authority are shared. Per-application fairness, upstream pools, per-application certificates, native arm64/additional distribution testing, fresh-VM installation, sustained multi-application sizing, representative business workflows and independent security review remain qualification or roadmap work. [Application contract](APPLICATIONS.md), [Progress](PROGRESS.md)
