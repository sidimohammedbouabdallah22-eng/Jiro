# M4 business-application qualification

The owner selected **Dolibarr first, ERPNext later** on 4 November 2026.
The first cohort is DVWA, PrestaShop and Dolibarr. Existing WordPress and
Keycloak evidence remains useful. These are representative lab workloads;
they do not replace the actual business pilot or start its 30-day clock.

## Selection and provenance

| Application | Purpose | Upstream starting point |
|---|---|---|
| DVWA | Paired direct-backend exploits and enforcing-WAF rejection | Existing pinned isolated fixture |
| PrestaShop | A real storefront, cart and administrative commerce workflow | [Source](https://github.com/PrestaShop/PrestaShop), [official containers](https://github.com/PrestaShop/docker), [9.2.0 release](https://github.com/PrestaShop/PrestaShop/releases/tag/9.2.0) |
| Dolibarr | SMB ERP/CRM documents, permissions, uploads and exports | [Source](https://github.com/Dolibarr/dolibarr), [official containers](https://github.com/Dolibarr/dolibarr-docker), [24.0.1 release](https://github.com/Dolibarr/dolibarr/releases/tag/24.0.1) |
| ERPNext, second cohort | Python/Frappe workflows and a different request/API stack | [Source](https://github.com/frappe/erpnext), [official containers](https://github.com/frappe/frappe_docker) |

GitHub's upstream latest-release endpoints reported PrestaShop 9.2.0 and
Dolibarr 24.0.1 when checked on 4 November. They were selection candidates at
that point; both pinned products have since been installed and qualified within
the scopes below. Before a new installation, review upstream
security advisories and the supported image/version pairing, resolve an amd64
image digest, and record image metadata and application versions in the lock
file. Never silently substitute `latest` or a development branch.

Review the upstream [PrestaShop advisories](https://github.com/PrestaShop/PrestaShop/security/advisories)
and [Dolibarr advisories](https://github.com/Dolibarr/dolibarr/security/advisories),
release notes and image dependencies at pinning time. A recent release or an
empty advisory page is not evidence that an application is free of vulnerabilities.

PrestaShop core uses OSL-3.0 and its modules use AFL-3.0
([upstream license](https://github.com/PrestaShop/PrestaShop/blob/develop/LICENSE.md)).
Dolibarr uses GPL-3-or-later ([upstream](https://github.com/Dolibarr/dolibarr)).
Run the applications as separate qualification dependencies, retaining their
notices; this is not a proposal to incorporate their code into the WAF.

The first cohort is PHP-heavy. ERPNext deliberately adds another stack later.
Prefer these maintained products over a random storefront demonstration with
unknown maintenance and unrealistic checkout behavior.

## Required workflows

| Target | Benign workflow assertions | Paired adverse checks |
|---|---|---|
| PrestaShop | Search and product variants; cart quantity/update/remove; customer login and address; discount; completed order with offline/test payment; back-office product rich text and image upload | Injection in matching parameters, CSRF failure, unauthenticated/low-privilege mutations, oversized upload, wrong application host |
| Dolibarr | Customer/contact creation and search; quote/order/invoice lifecycle; PDF content/download; attachment upload/download; CSV import/export; Unicode names and descriptions | Injection in matching fields, CSRF failure, role restrictions, unauthorized document access, oversized upload, exception-scope escape |
| ERPNext later | Authenticated JSON/RPC workflows, role boundaries, imports/exports and asynchronous completion | Injection pairs, failed authorization/CSRF, body limits and WebSocket handshake boundaries |

Check committed application state and document contents, not just HTTP 200 or
page titles. Distinguish a WAF refusal from an application's own validation or
authorization refusal. Application authorization is the application's duty;
passing such tests does not make the WAF an authorization engine. WebSocket
handshake coverage must not be described as frame/payload inspection.

For each false block, retain the request shape, rule IDs and intended business
operation; redact credentials and personal data. Require the narrowest host,
method, route and field exception supported by the policy model, with matching
attack and neighboring-route negative tests. Do not disable a rule globally to
make a workflow green. Record unresolved cases and failures.

## Deployment and evidence

Run one application cohort at a time on the owned lab VM. Record CPU, memory,
disk headroom and per-container limits before installation and measurement.
The current 1-vCPU/4-GiB VM is a starting environment, not an asserted resource
minimum for these products. Measure fit; use a separately recorded larger
profile if necessary. Do not mix installation CPU with gateway sizing.

Use synthetic customers, documents and orders, no real payment credentials,
and no external mail/payment integration. Bind lab access to loopback through
the existing SSH path; do not expose DVWA publicly. Retain private credentials
separately from publishable reports. Preserve failed fixtures and stop owned
services/containers after qualification.

Evidence must identify the exact WAF package/server hashes, application image
digests, policy revision and exceptions, harness source hashes, workflow state
assertions, request/verdict counts, resource observations and security-event
delivery reconciliation. First establish functional workflows; then replay a
bounded mixed corpus for capacity/endurance using the existing accounting.

## Order and exit criteria

1. Complete current-build recovery, upgrade/rollback and local monitoring drills.
2. Pin and qualify PrestaShop and Dolibarr independently, retaining DVWA pairs.
3. Repeat representative mixed-load/endurance and delivery accounting for the
   selected application topology and operating budget.
4. Add ERPNext as the second cohort; document remaining stack/protocol gaps.
5. Select the actual pilot host, owner/reviewer and workload, finish deployed
   alert/recovery checks and independent review, then begin reviewed operation.

The functional sets now pass: Dolibarr 24.0.1 (19 cases) and PrestaShop
9.2.0 (eight cases), including independent event-database verification. This is
partial coverage of the matrix above. Dolibarr now includes native CSV import,
native multipart attachments, contacts and validated sales orders. Broader
role/CSRF coverage, native export, additional storefront/back-office workflows and deployment
capacity remain open. ERPNext is planned. [Exact builds, results and limits](M4-BUSINESS-RESULTS.md).
The first real-business load profiles are tracked separately from functionality:
[business capacity](M4-BUSINESS-CAPACITY.md).
M4 remains open; the 30-day pilot has not started.
