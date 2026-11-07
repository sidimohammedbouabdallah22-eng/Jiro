# Linux service, certificate lifecycle and administration audit

## Build and install

Build an amd64 or arm64 development package from the repository root. The packaging command cross-compiles static Go executables, includes systemd files, installer, operating guides and third-party license notices, and writes a SHA-256 sidecar.

```sh
go run ./cmd/waf-package -arch amd64 -version development -out artifacts
```

The package requires systemd credentials and unified cgroups. Fresh installation and restored-service cutover have passed on Ubuntu 22.04 amd64 with systemd 249 and Ubuntu 24.04 amd64 with systemd 255 in VirtualBox. Staged qualification also runs under Ubuntu 24.04 WSL. Credential paths use `${CREDENTIALS_DIRECTORY}` in `ExecStart` to support both tested versions. arm64 packages await native service qualification. Package labels identify local builds. Release signing and supported upgrade-line qualification remain release work. [VM execution guide](VIRTUALBOX-QUALIFICATION.md), [M2 evidence](M2-QUALIFICATION.md)

On the target host, check the checksum, extract into a private working directory, then run the installer from that directory.

```sh
sha256sum -c openwaf-development-linux-amd64.tar.gz.sha256
mkdir openwaf-package
tar -xzf openwaf-development-linux-amd64.tar.gz -C openwaf-package
sudo sh openwaf-package/install.sh
```

The installer refuses an existing binary or unit. `DESTDIR=/absolute/staging/root sh install.sh` stages files for review and skips host user creation, credentials and systemd changes. An actual installation creates the `openwaf` service account through systemd-sysusers, creates a root-readable random administrator credential when absent, and reloads unit definitions. Starting and enabling the service are explicit operator steps after certificate and application configuration.

| Location | Purpose |
|---|---|
| `/usr/lib/openwaf/` | Server, recovery administrator and reference collector executables |
| `/usr/lib/systemd/system/openwaf.service` | Packaged unit |
| `/etc/openwaf/openwaf.env` | Bind addresses and certificate locations |
| `/etc/openwaf/admin-token` | Root-owned administrator credential, mode 0600 |
| `/var/lib/openwaf/` | Service-owned policy, history, security database and administration journal |

The unit uses `LoadCredential` to make a private runtime credential available to the service. `-admin-token-file` and `-event-export-token-file` also support other service managers. Supplying both a credential file and its corresponding nonempty environment value is rejected. Keep non-secret settings in `openwaf.env` and add export settings through a reviewed unit override when required.

The unit uses an unprivileged service account, empty capabilities, `ProtectSystem=strict`, `ProtectHome`, private temporary files and devices, restricted address families and writable state managed by `StateDirectory`. Its defaults include a 2 GiB memory ceiling, 256 tasks and 8,192 file descriptors. Size these limits against the workload and existing connector budgets. The default application listener is loopback port 8443, and management remains loopback port 8081. Public binding, firewall rules, TLS identity and backend isolation require operator configuration.

When deploying behind a proxy, configure its exact egress CIDRs in `OPENWAF_TRUSTED_PROXIES` and restart. The empty default uses direct connection identity. Preserve this environment setting with deployment backups and verify candidate flag support before cutover. [Trusted proxy contract](TRUSTED-PROXIES.md)

Install a valid certificate chain and matching key. Give the `openwaf` group read access to the certificate directories and key while retaining root write ownership. For example, use root-owned directories with mode 0750 and group `openwaf`, and a private key with mode 0640. The packaged paths are `/etc/openwaf/tls/current/fullchain.pem` and `/etc/openwaf/tls/current/privkey.pem`. Set `OPENWAF_TLS_HOSTNAMES` to the real comma-separated DNS names or IPs that the certificate must cover.

```sh
sudo systemctl enable --now openwaf
sudo systemctl status openwaf
sudo journalctl -u openwaf --since '10 minutes ago'
```

Access the management console through a secured management tunnel, such as `ssh -L 8081:127.0.0.1:8081 operator@gateway`. Retrieve the credential through the host's controlled administrator access. Configure the actual upstream in the console. The initial policy uses the existing local development upstream until changed. Use authenticated health checks to confirm readiness after service startup. `Type=exec` confirms process execution independently of application initialization.

## Certificate renewal and activation

The certificate authority or existing ACME client supplies PEM files. OpenWAF polls the configured paths every 30 seconds by default. `-tls-reload-interval` accepts 1 second through 1 hour. `systemctl reload openwaf` sends SIGHUP to request an immediate reload. The System screen offers the same reload operation through the authenticated API.

Publish each renewed chain and key together using a new root-owned version directory and an atomic `current` symlink replacement. Retain the previous directory for operator rollback. OpenWAF supports ordinary certificate-file symlinks used by renewal tools. An inconsistent pair observed while publishing is rejected, and the next poll retries it.

Before switching the certificate for new handshakes, OpenWAF checks matching key material, bounded PEM sizes and chain length, validity intervals of supplied certificates, supplied-chain signature order, leaf server-auth usage, SAN identity and configured hostname coverage. Certificates and keys stay in their external files. Initial validation failure prevents listener startup. Invalid renewals retain the previous certificate. Existing connections keep their negotiated TLS session.

TLS uses a minimum of TLS 1.2. Local loading does not establish public CA trust or revocation status. Verify the deployed chain with an independent client using the expected hostname and its normal trust roots. A chain can omit its root, as expected for a TLS server chain.

Certificate activation has a durable audit intent and outcome. Audit intent failure prevents activation. If recording the outcome fails after activation, certificate and audit health report the failure. Inspect the active fingerprint and journal before retrying. File polling retries invalid replacements, and repeated identical validation errors are collapsed into one rejection audit entry until state changes.

Expiry of the leaf or a supplied chain certificate within 30 days degrades health and sets `openwaf_tls_expiring` to 1. The active leaf's expiry is exposed as `openwaf_tls_not_after_timestamp_seconds`, and the earliest supplied-chain expiry as `openwaf_tls_chain_not_after_timestamp_seconds`. The console shows that earliest expiry. An expired active certificate remains configured for TLS, and validating clients reject it. Monitor the existing scrape target and certificate metrics using the operator's alerting system.

The authenticated APIs are `GET /api/v1/certificates` and `POST /api/v1/certificates/reload` with an empty JSON object. They report the active leaf fingerprint, validity, last attempt/success and bounded error codes. Certificate paths and expected hostnames are startup settings.

## Durable administration journal

The default journal is `<policy path>.audit.jsonl`. `-audit-file` selects a custom location. Each bounded JSON record has an increasing sequence, random ID, correlation ID, UTC timestamp, operation, actor, outcome, revision, optional resource digest, previous-record hash and SHA-256 hash. Each append completes a file sync before acknowledgement. The journal has its own process lease and remains separate from the high-volume security-event database.

It records management mutation attempts and outcomes, including login failures, successful login/logout, validation, policy apply and rollback requests. Core policy activation also records the candidate revision and policy digest before durable mutation, followed by an outcome. Certificate activation/rejection and server start/stop intent use the same journal. Unauthenticated read requests and capacity refusals before management admission are excluded. Records use fixed operation names and omit credentials, cookies, request bodies, arbitrary request paths, policy text and change reasons. Policy history retains its existing operator-supplied reason.

An intent must commit before a management mutation proceeds. Journal exhaustion or failure refuses new administrative changes while traffic continues under the active policy. Intent and outcome records bracket operations across separate files. A process interruption or outcome-sync failure can leave an intent whose operation committed. Reconcile its policy revision/digest or active certificate fingerprint with actual state. The API preserves the actual mutation result when an outcome write subsequently fails, and operational health remains degraded.

Local account sessions attribute activity to individual usernames, with administrator, operator and viewer roles. Bootstrap credentials, token-based sessions and trusted local callers retain their existing attribution. Account saves revoke earlier sessions for that account. See [traffic and access controls](TRAFFIC-AND-ACCESS.md). The journal is bounded to 32 MiB, with records at most 2 KiB, and retains every record until the operator archives it. Monitor `openwaf_audit_bytes / openwaf_audit_limit_bytes` and `openwaf_audit_healthy`. Local hash chaining detects accidental corruption and editing without recomputing the chain. Configured independent export retains canonical records at a separately operated receiver with durable deduplication. The package includes a credential-file systemd override example. Offline `waf-admin audit-export` replays stopped archives without rewriting their bytes. [Audit export setup and recovery contract](AUDIT-EXPORT.md)

`GET /api/v1/audit?limit=100&before=<sequence>` returns newest-first records. `before` is exclusive and `limit` is 1 through 100. The System screen shows and exports the latest 20 records. Read endpoints remain available when audit writes fail, provided the service is running.

For retention, stop the service, create and verify a recovery set containing the active journal, and preserve a separately protected archive. Record the last sequence/hash from the manifest. Move the stopped journal to a private, uniquely named archive location and restart to begin a new journal. Preserve the old archive and checkpoint metadata across this boundary. A corrupt or incomplete final record causes startup to refuse the journal. Preserve the damaged original and restore a verified checkpoint through the documented recovery procedure. Native Ubuntu 24.04 passed three abrupt guest poweroffs with acknowledged event, policy, account and audit reconciliation, plus actual r5/r6 live upgrade/rollback. Physical host/controller power failure remains unqualified. The 25-request/second reference profile and exact limits are recorded in [M2 evidence](M2-QUALIFICATION.md).

## Backup, upgrade and rollback

Schema-2 deployments require the certificate bundle to cover every configured application hostname. Host migration is explicit through the console. Back up before migration, and preserve the earlier checkpoint for rollback to a schema-1-only executable. Candidate checks include schemas throughout committed history. [Applications and migration](APPLICATIONS.md)

The current `waf-admin` automatically includes an existing default journal in backup and inspection. Supply `-audit-file` when the server uses a custom path. Older checkpoints without a journal remain readable. A restored journal is placed beside the restored policy as `policy.json.audit.jsonl`. Upgrade checks require a candidate advertising audit format 1 and compare journal sequence, bytes and terminal hash before and after rehearsal.

Before replacing an installed binary, stop the service and follow the checkpoint and candidate rehearsal procedure. Preserve the original executables, `/etc/openwaf/openwaf.env`, credential source, certificate version directories and unit overrides alongside the protected checkpoint. Recovery sets include their explicit state members, and deployment settings and TLS secrets need their own protected backup.

```sh
sudo systemctl stop openwaf
sudo /usr/lib/openwaf/waf-admin backup -config /var/lib/openwaf/policy.json -binary /usr/lib/openwaf/waf-server -out /private/backups/before-upgrade
sudo /usr/lib/openwaf/waf-admin upgrade-check -backup /private/backups/before-upgrade -candidate /private/candidate/waf-server
```

Use a root-owned, trusted candidate. Install the qualified candidate only after reviewing the rehearsal result. Preserve a verified rollback binary and recovery set. Rollback prepares restored state in a new directory, after which the operator selects the restored paths and restores service ownership before starting. Keep the failed newer state for investigation. [Recovery procedure](BACKUP-RESTORE-UPGRADES.md)

The unit and credential model follow systemd's execution and service contracts. Certificate callbacks follow the Go TLS configuration contract. [systemd execution](https://www.freedesktop.org/software/systemd/man/latest/systemd.exec.html) · [systemd service](https://www.freedesktop.org/software/systemd/man/latest/systemd.service.html) · [Go TLS](https://pkg.go.dev/crypto/tls#Config)
