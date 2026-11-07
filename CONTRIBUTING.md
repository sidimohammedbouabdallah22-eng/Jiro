# Contributing

OpenWAF is a pre-production project undergoing application, resource and
operational qualification. Public reports should distinguish measured results
from hypotheses and unresolved release gates.

## Start with a reproducible issue

Include the source revision, operating system, Go version, application policy
with credentials removed, expected behavior and a minimal synthetic reproducer.
Performance reports should also identify hardware, concurrency, body sizes,
traffic schedule, resource limits and event-delivery accounting.

Use the reporting route in [SECURITY.md](SECURITY.md) for vulnerabilities.

## Local checks

Go 1.27.3 is the toolchain used for the current qualification. The module declares
Go 1.26 as its minimum. Node.js is required for browser development tooling.

```sh
go build ./cmd/waf-server
go test ./...
go vet ./...
```

Some operational tests need candidate server, administrator and legacy fixture
binaries. The commands and environment are recorded in
[the verification workflow](.github/workflows/check.yml).

Run the pinned CRS corpus from its separate tool module.

```sh
cd tools/crscheck
go run .
```

The private VM/business-application harness needs separately provisioned lab
fixtures. See the qualification documentation for its scope and prerequisites.

## Changes and review

Keep changes focused and explain their security and operational effects.
Include a targeted regression for a reproduced defect. Preserve supported
policy schemas, failure behavior and durable-event accounting. Rule exceptions
need an explicit scope, reason and evidence that other inputs remain inspected.

The Coraza tree has a documented downstream patch. Preserve its provenance and
upstream license notices. Review upstream-directed changes separately from
application integration changes.

AI-assisted contributions are welcome. Describe the work accurately, verify
generated code, and include the tests actually executed. Credit upstream work
and collaborators explicitly. Maintainer review is required before merging.

OpenWAF is licensed under Apache-2.0. Contributions are submitted under the
project's Apache-2.0 license, with upstream notices retained.
