# Fresh-host recovery qualification

## Selected upload-reservation build, 9 November 2026

The selected package passes fresh-OS recovery in
`artifacts/m4-fresh-restore-da9e1f8e/result.json` and `verification.json`.
Package SHA-256 is
`f7efe1e953fac810f932bb7f59fe373b0fb2b0577b328ecca40b33bd3c097063`.
The restored server SHA-256 is
`75ee8698e1ef1b5e5bf9e039943d6d2e80e3076354cee343d5dc67a8c38ad3d8`.

The donor is `openwaf-m2-24.04-af0a1646`, with operational fixture
`owaf-m2-9dffe4f1`. The new target is `openwaf-m2-24.04-0de3d6f6`, provisioned
from the same verified stock Ubuntu 24.04 image identified below. Its one vCPU
and 2 GiB RAM support this functional rehearsal. Both VMs finish powered off.

The clean-OS preconditions, distinct machine identity and donor-off activation
checks pass. All six deployment assets retain their hashes and restricted modes.
TLS verification remains enabled for both application names. The original
localhost management origin is retained through a new SSH tunnel. Browser
passkey/TOTP authentication advances the restored counter from six to seven.
Viewer password login, scoped automation access and application isolation pass.

All sixteen checkpoint security events and 139 administration records survive.
The independent audit receiver preserves all 149 newer receipts from the stopped
donor. Two new blocks produce eighteen matching security records, with empty
outboxes. All 151 final journal records reach the audit receiver, including
shutdown. Twelve invalid proof mutations reject. The checker verifies retained
database and archive bytes independently of the runner's success flag.

This qualifies the controlled-backend WAF recovery procedure on the current
package. Business database recovery has separate same-host WSL2 evidence.
The subsequent coordinated Dolibarr/PrestaShop/Jiro repetition passes on
another fresh Ubuntu VM, with both business databases, installed applications
and document/custom volumes restored from the cold checkpoint.
[Business recovery proof](M4-BUSINESS-RECOVERY.md).
The eventual deployment's DNS/certificate chain and identity-provider recovery,
independent review and the pilot remain open. The retained passkey proof uses
a synthetic authenticator.

## Earlier candidate, 5 November 2026

The 5 November 2026 drill passes for its recorded candidate on a separately
provisioned Ubuntu 24.04 amd64 VirtualBox OS with one vCPU and 2 GiB RAM.
This closes the controlled-backend fresh-host lab gate. M4 and the business
pilot remain open.

- Evidence: `artifacts/m4-fresh-restore-df422373/result.json` and `verification.json`.
- Candidate archive SHA-256: `7bfe3b73b7a11318302662ad31e3ec36e671a25d88ff2f5bf182ff1a9c922cb2`.
- Restored/running server SHA-256: `cef0916699fa8adef803c46e74d2a73f995156b15a550f5304283a0d3216794f`.
- Donor: `openwaf-m2-24.04-af0a1646`; target: `openwaf-m2-24.04-f32c4fb6`.
- Ubuntu image SHA-256: `9a1e3959c9f4ad9d4752101fd4ff9a43191fb7d72e61fa20e033f9fd235ce794`.
  The provisioner checks the cached cloud image against its archived official
  checksum list. It creates a new disk from that stock image, not the donor disk.

## What passed

Before installation, the target has no OpenWAF account, group, service,
installation, configuration or state. Its machine identity differs from the
donor's. The donor's service and both receivers are stopped for export, and the
donor is powered off before target activation. Both machines end powered off;
their disks and all failed evidence remain retained.

The private recovery set combines the immutable `post-upgrade` WAF checkpoint
from `owaf-m2-d3cee4f8` with six deployment assets, six historical service/env
definitions and the controlled backend helper. The independent audit receiver
is migrated from its **current stopped receipt store**, separately from the
older WAF checkpoint. It is not rolled back with that checkpoint. The security
event receiver is restored from the checkpoint's coordinated recovery set.

The packaged installer creates the fresh service identity. Packaged `waf-admin
restore` creates new state; the restored executable is checked against the
selected package and used by the service. Ownership is assigned using the new
host's actual UID/GID. New systemd definitions point to the new paths and restored
credentials. Historical definitions are retained as provenance, not installed
with donor paths. All checkpoint-member hashes verify before activation.

| Check | Result |
|---|---|
| Policy/history | Revision 7 and immutable history bytes preserved |
| Checkpoint security events | All 16 IDs and payloads preserved |
| Initial administration journal | All 139 records preserved |
| Independent audit receiver | All 165 existing records, payloads and deduplication receipts preserved |
| Deployment assets | All six hashes and restricted modes verified: TLS certificate/key, admin/event/audit credentials, authentication configuration |
| Accounts and authorization | Passwords, factors, bindings, assignments and token state preserved; only expected factor replay counters/account revision advance |
| Authentication | Real browser passkey assertion, TOTP and viewer password login pass; scoped token reads only its assigned application and cannot read audit |
| Traffic | Four clean requests return 200 with the expected backend body; two XSS requests return 403, across both application hosts |
| TLS | Certificate verification enabled; served DER bytes match the restored certificate |
| New delivery | Both new security events arrive; all 18 sender records match receiver bytes; live pending counts zero |
| Final audit delivery | All 151 captured journal records received, including the final `service.stopping` record after the live snapshot |

The independent checker reads the retained source and stopped-target database
bytes, checks member/asset hashes, account changes, all event IDs/payloads,
occurrence-aware receiver digests/totals, current audit receipts and shutdown
delivery. It also rejects 12 invalid report mutations. Measurement sources and
the clean-OS provisioner snapshot are preserved and checked.

## Reproduce

Prepare a new owned VM with `scripts/qualify-virtualbox.py --prepare-only`, the
pinned image/checksum list and selected package. This mode reports
`prepared: true`, `qualification_performed: false`, `passed: false`: preparation
does not claim fresh-install qualification. Keep the resulting VM name/key.

Run `scripts/qualify-m4-fresh-restore.py` with explicit `--donor`, `--target`,
`--source-fixture`, `--source-proof`, `--package` and `--disposable-vm` arguments.
The source fixture must have this drill's retained current-build checkpoint and
deployment assets; this is a lab harness, not a general customer restore CLI.
The source proof is the private synthetic passkey/TOTP credential artifact.
The original administrator origin must be free for the new host's SSH tunnel.

Verify independently:

```powershell
python scripts/check-fresh-restore-evidence.py `
  artifacts/m4-fresh-restore-df422373/result.json `
  --package artifacts/rule-candidate-5777d82f469c/openwaf-rule-candidate-linux-amd64.tar.gz
```

Private transfer/capture archives contain credentials, enrolled test factors,
accounts and event/audit payloads. Their Windows directory ACLs are restricted;
do not publish them or the private browser proof. SHA-256 verifies recorded
identity; it is not a signed release or protection against an attacker who can
rewrite the evidence.

## Findings and limits

Two failed attempts remain retained. `m4-fresh-restore-683d3d66` stopped before
installation because a reboot cleared the package from `/tmp`. The runner now
transfers and verifies the package on every attempt.
`m4-fresh-restore-3dc81a78` exposed the restored parent directory's intentional
root-private permissions. The corrected harness grants service-group traversal,
assigns state ownership and checks readability as the service user before
activation. A second clean VM supplied the passing rerun. A transient VirtualBox
metadata lock also interrupted failed-run cleanup reporting; the runner now
retries metadata reads and attempts cleanup for each VM independently. All
participating VMs were subsequently confirmed powered off.

The runtime Go binary did not change. This qualifies WAF state, its dedicated
reference receivers and two controlled HTTP backends on a fresh OS. It does not
qualify PrestaShop/Dolibarr databases, actual business infrastructure, remote
collector topology, customer identity-provider/factor recovery, another OS or
ARM64. Network listener/origin settings intentionally remain the same through
loopback SSH forwarding. A customer topology change needs its own procedure.

A checkpoint restores the historical account/factor/revocation timeline.
Reconcile later security changes before exposing a customer restore. Keeping
newer independent audit receipts does not merge those changes into the WAF's
account store. No zero-RPO or customer RTO claim is made.

The subsequent [deployed fault/alert lab](PILOT-ALERTS.md) now passes 14 cases,
including certificate/storage/export faults, durable alert retries and a real
missing-sample interval. Operator delivery qualification with the selected
recipient and independent supervision remain open. Broader business
workflows/capacity, customer configuration, independent review and 30 actual
reviewed pilot days remain gates. [Current ledger](M4-CURRENT-CANDIDATE.md)
