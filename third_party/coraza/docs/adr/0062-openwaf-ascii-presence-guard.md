# ADR-0062: Conservative ASCII character-presence rejection in OpenWAF

- **Status:** proposed
- **Date:** 2026-11-04
- **Version:** OpenWAF downstream (post-v3.8.1)
- **PR:** No linked PR; local downstream change
- **Issue(s):** No linked issue
- **Deciders:** OpenWAF maintainer review pending
- **Category:** Perf

## Context and Problem

OpenWAF's full-CRS 900-KiB JSON benchmark spent approximately 95% of CPU in Go's regex matcher. An initial Windows benchmark took 4.75 seconds per inspection. The upstream experimental literal prefilter remains disabled in the production policy compiler.

## Decision Drivers

- Preserve matching/capture semantics, all CRS rules and the existing matcher.
- Bound analysis memory and keep request payloads out of persistent caches/logs.
- Retain an exact baseline build for comparisons.

## Considered Options

- Retain the existing CPU cost and lower body/rate budgets.
- Enable the upstream experimental literal extractor, requiring separate security qualification.
- Add a weaker necessary-character condition, with a structural safety argument and differential tests.

## Decision Outcome

Use a downstream character-presence guard for large ASCII values. Literal characters and character classes require at least one applicable ASCII character. Concatenation combines requirements with AND; alternation combines them with OR. Captures and mandatory repetitions inherit their child's requirement. Optional/unknown constructs and zero-width boundaries impose no requirement. Non-ASCII input always runs the original matcher. Analysis exceeding 64 levels or 4,096 nodes also falls back. Values below 4,096 bytes run the original matcher.

By structural induction, every successful ASCII match satisfies this condition. The guard can therefore reject only impossible matches. It never infers adjacency/order, rewrites regexes, bypasses captures on a possible match, changes CRS scoring or retains request data across transactions. Early positive checks are monotone and only return to the original matcher. Binary-regex paths remain unchanged. `openwaf.no_ascii_guard` supplies an unoptimized baseline build.

This is independently identified OpenWAF downstream code, not an upstream release or an assertion that experimental prefilter behavior has been qualified. Rule/corpus, adversarial differential, race and native contention evidence are required before a release claim.

## Technical Discussion

No substantive technical discussion recorded; maintainer and independent review remain pending.

## Consequences

OpenWAF maintains a small local patch over an exact upstream source snapshot. Upstream notices and license remain. Unicode and many diverse ASCII values still require the original work. This optimization does not provide CPU-time isolation between applications or hard preemption of inspection.

## References

- ADR-0044 and ADR-0061: existing transformation caching, which remains unchanged.
- OpenWAF `docs/M4-FINDINGS.md`, finding M4-PERF-001.
