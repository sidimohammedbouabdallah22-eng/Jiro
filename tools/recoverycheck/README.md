# Test-only schema-1 reader

This executable exercises the recovery capability protocol with a strict schema-1 reader. It is not a previous released OpenWAF build and cannot serve traffic. Policy compilation uses the current pinned engine. Tests distinguish this storage-compatibility fixture from the actual current server executable.

Build with `go build -o ../../bin/waf-schema1-fixture.exe .` on Windows (omit `.exe` on Linux), then set `OPENWAF_RECOVERY_LEGACY` when running `go test ./internal/operations` from the root. Set `OPENWAF_RECOVERY_CANDIDATE` to the actual current waf-server as well. The drill verifies schema-1 migration by the real candidate, rejection of schema 2 by the legacy profile, restoration of the schema-1 checkpoint and successful reading by this fixture. No in-place database downgrade is performed.
