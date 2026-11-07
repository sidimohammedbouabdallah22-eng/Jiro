Current recovery tooling and schema qualification are documented in [backup, restore and upgrades](BACKUP-RESTORE-UPGRADES.md). The policy-import notes below describe the earlier policy-safety slice.

# Trying the policy-safety build

The development build is at bin/openwaf-next.exe. Your running binary, active policy and administrator token were not replaced during development. The browser tests use a temporary policy and separate local ports.

## Run the new build

1. Stop the current server with Ctrl+C in its own terminal.
2. Back up config/policy.json, any existing config/policy.json.history directory, and the administrator credential using your normal private backup location. Keep the credential out of shared support bundles.
3. From the project directory, run `./scripts/start.ps1`. The launcher builds bin/openwaf.exe from the new source and reuses your administrator token as documented in README.md.
4. Refresh the console. The first startup imports the existing unversioned policy as schema 1 with application ID primary; it does not change its inspection settings. The initial history entry appears as an imported policy.
5. Use Rules & exceptions for narrow exceptions and Policy history to compare/restore settings. Enter a reason for each console save or rollback.

To compile a policy without starting the server, generating history, or needing a token:

```powershell
./bin/openwaf-next.exe -check-config -config config/policy.json
```

## Storage behavior to know

The .history directory is part of the policy's recoverable state. Keep it with the active JSON file. A .lock file remains after shutdown; its presence alone does not mean another process is running. Do not remove it while the service is active. The operating system releases the held lease on process exit.

Once imported, edit through the console/API. Changing active JSON settings at the same recorded revision will fail verification on save/startup. A missing active policy with existing history will not boot fresh defaults. A rollback creates a newer revision with earlier settings; it does not delete the intervening history or reuse revision numbers.

Stop the development service before restoring a filesystem backup, and restore its active policy and matching full history together. Do not prune referenced snapshot files or run multiple nodes/older binaries against this same state. The first bound is 1,000 snapshot files, with 256 KiB maximum per snapshot. Automated retention and qualified database migration are later work.

Policy history and SQLite security events are now durable; traffic counters remain process-local. Use the current recovery guide to include event/outbox and optional collector state consistently. The current shared-token/session actor identifies a credential/session, not an individual person.

