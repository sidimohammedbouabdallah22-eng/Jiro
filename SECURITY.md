# Security policy

## Development status

OpenWAF is pre-production. Qualification, independent review and the pilot
remain open. Security fixes currently target the development branch.
The project has no supported production release or response-time commitment.

## Reporting a vulnerability

Use the repository's **Security → Report a vulnerability** route when available.
If that route is unavailable, open a non-sensitive issue requesting a private
reporting channel. Keep exploit details and private data within the agreed
private channel.

A report should include the affected revision, configuration with credentials
removed, impact, prerequisites, a minimal synthetic reproducer and any known
mitigation. Coordinate public disclosure with the maintainer while the report
is assessed and a fix is prepared.

Upstream Coraza or CRS findings should also follow the affected upstream
project's reporting policy. Clarify whether a finding concerns OpenWAF's
connector, its downstream patch, its management interface or upstream rules.

Use owned or explicitly authorized test systems. Qualification fixtures and
deliberately vulnerable applications belong in isolated labs.
