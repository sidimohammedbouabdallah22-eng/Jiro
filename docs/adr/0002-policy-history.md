# ADR 0002 — one active policy commit point with immutable revision snapshots

Status: accepted for the single-application policy-safety slice. SQLite-backed multi-application storage remains roadmap work.

## Context

The foundation already uses a JSON file for active configuration. Adding a separate authoritative history database without a defined migration would create two commit points: database transaction and active-file replacement. A failure between them could make the UI's history disagree with the active or restarted policy.

This slice needs durable history, narrow exceptions and safe rollback while preserving the current single-policy installation. It does not yet require database-backed search, multiple writers, multiple applications or a durable security-event store.

## Decision

Keep the active JSON file as the sole commit point. Prepare a flushed immutable snapshot first, then atomically replace the active file, then publish the compiled runtime pointer. Each snapshot names its parent. Expose only the chain reachable from the active policy. Skip orphan revision numbers instead of reusing or displaying them. Enforce an exclusive process lease and integrity checks before editing and on startup.

Restoring an earlier revision creates a new revision, retaining the intervening history. The console records a change reason and a session/API identity. A browser preview or validation never creates a committed revision.

Do not edit files after import or operate several nodes against one history directory. Stop the development service before copying/restoring the complete policy/history backup. The first implementation caps snapshots at 1,000 files and 256 KiB each; retention and full power-loss qualification remain incomplete.

## Consequences

This makes ordinary process-crash and failed-write behavior testable without expanding the runtime storage stack during a connector decision. It is not a substitute for the planned event database, a tamper-proof administration audit or multi-node state.

When SQLite policy storage is introduced, migrate to one authoritative transactional representation and make JSON an import/export format. The migration must preserve revision lineage, reasons and rollback behavior, include backup/restore tests, and explicitly retire this active-file commit protocol. Do not dual-write two independent authorities.
