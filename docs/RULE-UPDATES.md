# Pinned rule-update qualification

Rules, engine and recommended configuration are embedded in versioned binaries. Updates use an isolated candidate and the existing guarded upgrade/recovery workflow.

Run the following from the source root with explicit pins.

```powershell
python scripts/qualify-rule-update.py --engine v3.8.2-0.20261029104012-08aa51147300 --crs v4.30.0 --configuration v3.8.1
```

The same script is available through the manually dispatched **Qualify pinned rule candidate** workflow. It pins the qualified Go 1.27.3 toolchain. Workflow inputs become environment values passed as quoted arguments. Branch names and floating versions are rejected by the script.

The script copies bounded source/build inputs to `artifacts/rule-candidate-<id>/source`. Runtime policy, credentials, backups, reference checkouts and prior artifacts are excluded. It updates the three pinned modules in that copy and pairs the CRS test corpus to the selected CRS version. The live source dependency files retain their existing pins.

Qualification builds the server, administrator and strict legacy fixture, runs unit/integration/recovery tests, vet, a pinned vulnerability scanner, the focused connector comparison and the entire upstream CRS corpus. Success requires every corpus case evaluated and passing, with no skips, ignores or errors. The result records original source hashes, the exact compatibility-adaptation digest, resolved dependency graph, phase logs, corpus accounting and candidate executable hash. License material is collected for the selected modules. The resulting Linux package and SHA-256 sidecar are retained.

Review changed upstream rules, engine behavior and each compatibility adaptation. A passing regression result has `activation_approved` false until an explicit review manifest matches its `review_required` pins, adaptation hash and executable hash. A review manifest adds `reviewer` and `reason`. Passing `--review <file>` reruns qualification and records that matching attestation. This is a local review record. Release signing and independent approval ownership remain release work.

After qualification, exercise representative sanitized business workflows in detection mode, review false positives, then test enforcement. Take a coordinated pre-update recovery set and run `waf-admin upgrade-check` against the exact candidate. Activate its matching package through the documented stopped-service procedure. Check inspection, application routing, authentication, health, export and audit. Retain the old executable and pre-update recovery set. Rehearse rollback before wider rollout. [Recovery and upgrade procedure](BACKUP-RESTORE-UPGRADES.md)

Candidate reports and CI uploads provide regression evidence. Native service/endurance qualification and organization-specific tuning remain separate gates. Upstream rules stay intact, and local exceptions remain explicit, scoped and reviewable. [CRS tuning guidance](https://coreruleset.org/docs/2-how-crs-works/2-3-false-positives-and-tuning/)
