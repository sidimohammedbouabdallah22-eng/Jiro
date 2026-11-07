# OpenWAF downstream Coraza patch

This directory is a source snapshot of `github.com/corazawaf/coraza/v3` at
`v3.8.2-0.20261029104012-08aa51147300`, with OpenWAF's Apache-2.0 downstream
ASCII character-presence guard. It is not an upstream Coraza release.
`OPENWAF-UPSTREAM.json` records original file hashes and the patch identity.
Upstream licenses, notices, tests and documentation remain intact.

The patch initializes the normal UTF-8 regex operator with a bounded necessary
condition for values at least 4,096 bytes long. It preserves the existing matcher,
capture handling, binary regex path, rule order, transformations and CRS scoring.
Unicode input and unknown/over-budget analyses fall back to the original matcher.
There is no cross-request payload cache. The upstream experimental `SecRxPreFilter`
remains Off in the production configuration. Its separate behavior is unchanged.

The added implementation is `internal/operators/rx_ascii_guard*.go`; the hook is
one initialization in `rx.go`. Differential cases and fuzzing are added to the
existing `rxprefilter_test.go`. ADR-0062 records the safety argument and limits.
The proposed ADR awaits maintainer/independent review; no upstream submission has
been made. Build tag `openwaf.no_ascii_guard` provides baseline measurements.

The local replacement is explicit in all OpenWAF Go modules. Runtime/candidate
metadata identifies `+openwaf-ascii-presence-v1`. Rule-update qualification copies
and hashes this source and refuses a different engine pin until the patch is
rebased and reviewed. Changing the upstream module version alone cannot silently
claim to have updated these local sources.

Runtime changes to the patch require a new patch identity and fresh qualification.
An upstream security update must review/rebase this snapshot as part of the update.
If the patch cannot be maintained, remove the local replacements, select an exact
upstream version and requalify the original matcher with appropriate body/admission
budgets. The baseline build tag disables this optimization but does not update the
underlying pinned engine. Preserve this provenance record in distributed packages.

Go module downloads omit nested modules from upstream's workspace. To run this
snapshot's tests, use `GOWORK=off`; OpenWAF's `tools/crscheck` runs the applicable
full pinned CRS corpus through its real connector. Do not infer untested platform
support from the source snapshot.
