# Appliance operations validation

Validation date is 2 November 2026. These checks qualify the implemented service, certificate and administration-journal paths on synthetic local state. They establish an initial operating increment toward M2.

| Check | Recorded result |
|---|---|
| Windows root `go test ./...` with candidate/admin/schema-1 reader integration enabled | Passed |
| Windows root `go vet ./...` | Passed |
| Linux amd64 administration-journal, certificate-manager, complete gateway and complete operations test binaries under WSL | Passed |
| Chrome compiled-server check including audit table and certificate status | Passed |
| Prometheus common v0.67.5 parser against emitted samples | 57 fixed, label-free metric families accepted |
| Linux amd64 systemd package and disposable service drill on Ubuntu 24.04/systemd 255 | Passed |
| Linux arm64 package | Cross-build passed, native execution pending |
| Twelve-second mixed-load/outage/restart smoke | 1,112 requests and 377 observed/committed/collected security occurrences reconciled, zero drops or invariant failures |

## Administration evidence

Journal tests verify exclusive process ownership, concurrent serialized appends, file-sync acknowledgement, sequence/hash preservation across reopen, cursor pagination, corruption detection and rejection of an incomplete final line. A child process is killed after an acknowledged intent, and reopening retains that intent. Separate injected closed-file and capacity failures keep audit health degraded and reject further appends.

Audit and certificate health use immutable cached status snapshots. Regression tests hold the corresponding I/O locks and verify that health reads still complete, so monitoring stays responsive during those operations.

Gateway tests cover failed login auditing, core policy activation intents/outcomes, omission of supplied credentials and arbitrary change reasons, authenticated audit pagination, restart persistence and refusal of policy changes after journal failure. Normal application traffic remains available under the active policy during that failure.

Recovery tests and real candidate processes include the journal in the checkpoint, reject a candidate without audit-format support, preserve record count/bytes/terminal hash during migration rehearsal and restore the original journal. Earlier schema-1 reader qualification uses the documented test fixture, whose reader now supports this audit format. It remains a synthetic compatibility fixture.

## Certificate evidence

TLS tests establish real handshakes and compare presented serial numbers before and after reload. Invalid/mismatched PEM pairs, expired/future validity and hostname mismatches preserve the previous active certificate. Polling activates a valid replacement. An audit-intent failure prevents activation. Expiry warnings cover both the leaf and an earlier-expiring supplied CA certificate. Initial malformed input is refused.

The service drill uses an independent curl client with the explicit synthetic certificate trust anchor and expected hostname. A half-published renewal fails validation while the original certificate continues serving. Publishing its matching key and sending SIGHUP activates the replacement. These fixtures exercise renewal consumption independently of certificate authority issuance.

## Linux service evidence

The package is extracted into an owned temporary staging tree. The installer populates that tree and refuses a second install. The sysusers definition is dry-run against that tree. Qualification creates a uniquely named disposable service account, launches the packaged unit with its original hardening settings and isolated paths, verifies the service runs under that unprivileged UID with `NoNewPrivs`, and confirms the administrator token is absent from the process environment.

The packaged server serves a benign application request over TLS and blocks the XSS fixture. The drill performs a policy change, verifies activation and certificate audit records, restarts the service and checks that the journal survives. After stopping, the packaged recovery tool creates/verifies a checkpoint, rehearses the candidate and prepares rollback state. The service then starts against that restored copy and serves the expected application and revision. The disposable service, account and owned directories are cleaned up.

The repeatable drill is `sudo bash scripts/qualify-linux-service.sh /absolute/package.tar.gz`. CI includes a Linux service job using the same path. Hosted CI execution has its own results when run after publication.

## Evidence and remaining scope

Logs are saved under `artifacts/` as `appliance-all-tests.log`, `appliance-focused-tests.log`, `appliance-adminaudit-linux-tests.log`, `appliance-certificates-linux-tests.log`, `appliance-gateway-linux-tests.log`, `appliance-operations-linux-tests.log`, `appliance-browser-check.log`, `appliance-parser-check.log`, `linux-service-qualification.log`, and `soak-appliance-operations.json`.

Local Linux tests use cross-compiled Go test binaries with CGO disabled. The Linux race detector remains configured in CI and was not run locally for this increment. The long soak and full CRS corpus evidence remain in their existing reports. This increment ran a short delivery regression and focused service/TLS/administration checks.

Further qualification includes native arm64, additional distributions, host first-install/upgrade exercises in fresh VMs, longer load under service limits, certificate-provider integration and power-loss behavior. The 3 November increment adds independently acknowledged audit forwarding, read-only offline archive replay, transactional storage startup, account publication crash tests and two-application 30-minute fault soaks. The updated staged package exercise passes audit export with systemd file credentials and retained receiver receipts across restored-service cutover. Evidence and remaining closure gates are tracked in the M2 guide. Certificate issuance currently uses an external provider. Audit archival is an explicit stopped-service procedure, and interrupted operation outcomes require reconciliation against their durable intent and actual active state. [M2 qualification](M2-QUALIFICATION.md), [Operating guide](LINUX-OPERATIONS.md)
