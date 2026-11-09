# Coordinated business recovery qualification

The 9 November 2026 rehearsals pass for the selected Jiro build both in the owned
WSL2 lab and on a separately provisioned Ubuntu 24.04 amd64 OS. These are
functional maintenance-window rehearsals. Actual deployment sizing, identity and
TLS configuration, operator notifications, independent review and the business
pilot remain open.

The package SHA-256 is
`f7efe1e953fac810f932bb7f59fe373b0fb2b0577b328ecca40b33bd3c097063`.
The restored/running WAF SHA-256 is
`75ee8698e1ef1b5e5bf9e039943d6d2e80e3076354cee343d5dc67a8c38ad3d8`.
Evidence is retained in `artifacts/m4-business-recovery-9b203110` with its
frozen measurement source, private capture and independent `verification.json`.

## Fresh-host repetition

`artifacts/m4-fresh-business-9554b566/result.json` and `verification.json` pass
on `openwaf-m2-24.04-1780797d`, prepared from the verified stock Ubuntu cloud
image. The VM has one vCPU, 4 GiB RAM and a 32-GiB disk. The larger disk holds
the image archive, imported images, databases, application files and retained
capture. The source distro is stopped before target activation and stays stopped.
The target's machine identity differs. Initial checks verify no Jiro installation,
configuration or service identity, and no Docker images, containers or volumes.
Ubuntu packages provide Docker 29.1.3 and socat; exact versions are recorded.

The runner extracts the immutable checkpoint from the retained cold recovery
bundle.
Both databases receive logical imports into fresh volumes. Installed application
images load from the archive, and document/custom volumes preserve numeric
ownership. Captured service definitions are remapped to the new root and fixture
identities. The actual restored executable, credentials, policy and history verify.
The source containers remain absent on the target.

All 182 checkpoint-era files totaling 130,457,600 bytes verify. Four genuine
browser sessions pass, including both products' authentication and four new
700-KiB upload/download round trips. All 186 expected files then verify, totaling
133,324,800 bytes. The run records 164 HTTP requests. Both new XSS probes are
blocked. The original two security events survive exactly, followed by two new
events. All four records match receiver bytes, with an empty outbox and zero
write failures, queue loss, ingest timeouts or export failures.

The 4,556,318,720-byte private capture retains checkpoint members, canonical
source/restored SQL, volume inventories and archives, executable bytes,
credentials, continued administration journal and stopped security databases.
The independent checker binds these bytes to the native restore and browser
records. Ten invalid qualification claims reject. Twelve recovery tests pass,
including invalid fresh-host preconditions rejected before mutation and refusal
to run the three new entrypoints with Python assertions disabled. Twenty-four
other focused Python/Node checks pass.

The successful native run freezes its executed sources. Subsequent assertion-mode
guards have a separate regression verifying refusal before qualification begins. The VM,
all four restored containers and the source distro finish stopped. Disks and
private evidence remain retained. This closes the controlled fresh-OS business
recovery gate for this package. Deployment throughput and the eventual
organization's DNS, certificates, identity provider and operations remain open.

Reproduce with `qualify-virtualbox.py --prepare-only --cpus 1 --memory-mib 4096
--disk-gib 32`, the pinned Ubuntu image/checksum list and selected package. Then
run `qualify-fresh-business-recovery.py` with explicit `--vm`, `--package`,
`--donor-report` and `--disposable-vm`. The donor is the retained cold business
recovery report. The harness requires its synthetic fixtures and an owned VM.
It is a lab procedure with loopback HTTP and bootstrap administration.
Application TLS and administrator-factor recovery have separate current-package
[fresh-host evidence](M4-FRESH-HOST-RECOVERY.md).

Recheck independently with `check-fresh-business-evidence.py` and explicit
report/package paths. Archives contain database contents, documents, application
secrets and administrator credentials. They remain private and unencrypted.

## Coordinated checkpoint and activation

The runner drains requests and event export, stops the WAF and its dedicated
receiver, then stops both application containers before taking component
snapshots. MariaDB dumps include the business schema, rows, routines, triggers
and events. Canonical data and schema dumps are also retained for comparison.
After dumping, both source databases stop. The source cohort stays stopped
through replacement activation.

The checkpoint includes the production `waf-admin backup` recovery set, policy
history, administration journal, bootstrap credential, event credential, service
definitions, collector executable and private fixture metadata. Installed
application filesystem state and the database image are serialized into an
image archive. Dolibarr documents and custom files have separate volume
archives with content, mode, UID, GID and link inventories. Docker documents
this distinction between committed image state and mounted volume data.
[Docker image checkpoints](https://docs.docker.com/reference/cli/docker/container/commit/),
[Docker volume recovery](https://docs.docker.com/engine/storage/volumes/).

An immutable manifest binds thirty-nine component files totaling 2,835,204,640
bytes. Snapshot application images are evicted from the local image store before
the archive is loaded again. Replacement containers use distinct internal
networks and fresh named volumes. Database imports use the exact recorded
MariaDB image. Schema and row dumps must match before application startup.
[MariaDB dump options](https://mariadb.com/docs/server/clients-and-utilities/backup-restore-and-import-clients/mariadb-dump).

Validated volume archives are extracted with numeric ownership in bounded,
network-disabled utility containers. The WAF recovery CLI restores into a new
directory. The service identity receives explicit group traversal/execution
permissions, while root retains ownership of executables and private credential
copies. Activation waits for the actual process path and executable byte hash.
The service consumes restored credentials and restored state through the
retained service definitions.

The private capture is 4,556,318,720 bytes. The independent checker streams
large archive hashes, reads the actual source/restored database and volume
payloads, and binds report metadata to the embedded native restore record.

## Verified results

| Component | Result |
| --- | --- |
| Database schema and rows | Both Dolibarr and PrestaShop match their checkpoint dumps before startup |
| Installed applications | Exact recorded snapshot image identities loaded from the retained archive |
| Application volumes | Documents and custom files match all 2,419 inventory entries and 1,656,052,576 regular-file bytes, including root ownership |
| Database volumes | Two fresh database volumes receive logical imports |
| WAF policy and history | Exact bytes preserved, including the upload-route reservation |
| Executables and credentials | Restored WAF and collector match package bytes, with both credential copies matching the checkpoint |
| Administration journal | Checkpoint bytes preserved as the prefix of the continued journal |
| Business authentication | Eight genuine browser sessions pass across before/after workflows |
| Existing files | All 178 files from the preceding endurance run plus four pre-checkpoint uploads verify after restore |
| New writes | Four more post-restore uploads verify, giving eight new upload/download round trips and 186 known files in the restored application |
| Isolation | All four post-restore document names remain absent from the original application volume |
| Security events | Two original events survive exactly and two new XSS blocks arrive, with all four sender/receiver payloads identical and empty outbox |
| Storage and delivery | Ingest timeouts, queue loss, failed writes and export failures remain zero |
| Qualification integrity | Ten fabricated report claims are rejected; twenty-eight focused Python/Node checks pass |

The rehearsal records 328 HTTP requests. Every accepted browser workflow passes
its response and content checks. Capacity measurements remain in the separate
[shared-NAT endurance qualification](M4-NAT-ABUSE.md).

## Findings retained during development

Six unqualified attempts remain available. `0df8a36d` rejected a seed email
outside the existing lab's narrow format. `b30e5465` used the helper's smaller
default admission profile and refused four browser assets. The runner now uses
the already qualified 64 process slots, 128 connections, 32 application slots,
64 source-lane children and the selected body/buffer profile.

`f92b6956` restored document contents and child metadata but detected the volume
root changing from UID/GID 33 to root ownership. Numeric-owner extraction and a
specific root-directory regression correct that path. `caa3de3c` hit a SQL import
race against MariaDB's temporary initialization server. Readiness now requires
an authenticated TCP query before import, consistent with MariaDB's documented
container-health distinction.
[MariaDB health checks](https://mariadb.com/docs/server/server-management/automated-mariadb-deployment-and-administration/docker-and-mariadb/using-healthcheck-sh).

`5c4e332e` reached WAF activation but failed an immediate process-identity
assertion. A bounded identity wait now handles the systemd exec transition and
still requires the exact executable path and hash. Private recovery directories
receive explicit service-group traversal and a real service-user execution
check. `24436262` failed during source-lane startup before traffic; subsequent
capture errors replaced its primary diagnostic. Failure logs now append so the
initial cause survives cleanup failures. The successful repeat retains each of
these checks and freezes its sources through completion.

## Reproduce and remaining boundaries

Use the owned WSL2 fixture, selected package with checksum sidecar and an exact
prior-file manifest. The runner requires at least fifteen GiB free space on
both the Windows host and the guest. Run from the repository root.

```powershell
python scripts/qualify-business-recovery.py --package <selected-package> --wsl-fixture <owned-fixture.private.json> --prior-files <prior-run/files.json>
python scripts/check-business-recovery-evidence.py <recovery-run/result.json> --package <selected-package>
python -m unittest discover -s scripts -p test_business_recovery.py
```

Backups, image archives, SQL dumps, fixture files, browser credentials and raw
captures are private, unencrypted lab artifacts with restricted directory ACLs
and guest permissions. Publication includes reviewed source and result summaries.
The production WAF recovery CLI covers WAF state; the rehearsal coordinates the
separate upstream application backups. A deployment operator must own that
application recovery procedure and its maintenance window.

After verification, all four replacement containers stop, original service
configuration is restored, the original application origins are restored and
both source applications stop. The dedicated WSL2 distribution is terminated.
The original VirtualBox VM retains its powered-off, one-CPU configuration.
The fresh-host repetition above closes the controlled business-data recovery
gate. Actual deployment TLS/provider recovery, operator notification, watchdog
supervision, independent review and thirty reviewed pilot days remain M4 work.
