# Business-product functional qualification

The current boundary/replay candidate is `1af405f4227a`. Dolibarr repeats all 19 cases in `artifacts/m4-business-2be162b6/results-20.json` with independent database verification; PrestaShop repeats all eight cases in `artifacts/m4-business-77aadf7d/results-11.json` with the same independent database checks. The older report numbers and evidence below remain tied to the Host-preservation predecessor. [Current exact-build ledger](M4-CURRENT-CANDIDATE.md), [joint upload/contention results](M4-JOINT-BUSINESS.md).

These are controlled, synthetic workflows on the owned Ubuntu 24.04 amd64 VM
(one vCPU, 4 GiB). They do not establish customer capacity, aggregate false-positive
rates or completion of the planned application matrix. The accepted 5 November
runs use the Host-preservation candidate, server SHA-256
`cef0916699fa8adef803c46e74d2a73f995156b15a550f5304283a0d3216794f`.
Archive: `artifacts/rule-candidate-5777d82f469c/openwaf-rule-candidate-linux-amd64.tar.gz`,
SHA-256 `7bfe3b73b7a11318302662ad31e3ec36e671a25d88ff2f5bf182ff1a9c922cb2`.
Earlier exploratory Dolibarr runs use the previous corrected candidate.

The new candidate passes full unit/integration and vet checks on Windows and
Linux, Windows dependency/connector checks, focused Linux routing/forwarding
race checks, and all 5,193 CRS cases on both platforms with no failures, skips,
ignored cases or errors. Independent review and production activation are not
approved by those checks. Exact upgrade/rollback, three interrupted writes,
same-VM replacement restore and the 30-minute WordPress/DVWA reference have now
also passed on this candidate. Broader business capacity and deployment-specific
qualification remain open. [Current candidate evidence](M4-CURRENT-CANDIDATE.md)

## Dolibarr 24.0.1

All **14 cases** pass in `artifacts/m4-business-2be162b6/results-13.json`
(`business-v2-access` coverage):

- Real browser password login; missing and invalid API keys rejected by Dolibarr.
- Reviewed method tuning with five negative scope/inspection checks.
- Create, read and edit a customer with apostrophes, punctuation and Arabic text;
  find that committed record in the browser.
- Create, price and validate a quote and a separate invoice, each with two units
  at 125 and an asserted pre-tax total of 250.
- Generate and download an actual invoice PDF; upload and download the exact
  bytes of a CSV attachment through the document API.
- Missing/invalid CSRF tokens leave the customer unchanged, while a valid
  browser-form token commits an update.
- A non-administrator reader can read an explicitly assigned customer, cannot
  read an unassigned customer, and cannot create or update customers.
- The reader cannot read the invoice or download its PDF; administrator access
  remains available. Application JSON errors distinguish these denials from WAF
  refusals. These are Dolibarr permissions, not authorization supplied by the WAF.
- SQL injection and XSS refusal with direct-backend application controls.
- Wrong application hostname (421) and over-limit JSON body (413).

This attempt accounts for ten known security occurrences: eight 403s, one 413
and one 421. The complete retained fixture history, including earlier failed
attempts, contains 81 records/81 occurrences. Both captured SQLite databases
pass integrity checks; IDs and payload bytes match, and enqueued/acknowledged
counters reconcile. Final queues, failed writes, drops and ingestion timeouts
are zero. The independent checker also verifies the archived harness hashes.
Archive `databases-13.tar` is retained beside the report. These artifacts are
restricted locally; command logs and fixture credentials must not be published.

The gateway's final systemd CPU/memory and container snapshots are recorded.
They are observations during a functional workflow, not a sustained capacity
measurement. The fixture uses plain HTTP over loopback/SSH; independent verified
TLS transport qualification covers the earlier binary separately. Some owned
packaged M2 fixture services restarted with the VM during these functional runs;
no isolated CPU/capacity claim is made. Final cleanup stops them, and future
business-fixture starts stop those owned packaged dependencies first.

### Narrow method tuning

CRS 911100 initially rejected legitimate PUT updates. The reviewed lab policy
sets `tx.allowed_methods` only for PUT on:

- `/api/index.php/thirdparties/<numeric-id>`
- `/api/index.php/documents/builddoc`

Matching includes the endpoint's optional query string. There is no global rule
exclusion or inspection skip. Neighboring invoice/extra-path PUTs, PATCH, DELETE
and XSS in the permitted customer PUT route remain blocked. Dolibarr still
enforces authentication and permissions. The exact generated custom rules and
applied revision are recorded in the report; application-owner review is needed
before reusing this policy elsewhere.

### Retained attempts and corrections

Attempts 1–5 remain failed: missing Playwright browser binary, baseline PUT
method refusal, a JavaScript helper-name collision, missing typed API validation
arguments, and an unavailable legacy PDF template. The corrected fixture uses
installed Chrome, explicit API arguments and Dolibarr 24's `sponge` PDF model.
These are distinguished from production connector defects.

Attempts 6–8 completed their recorded functional protocols. Later evidence
checks exposed premature status sampling and host/VM clock skew. Attempt 9 uses
explicit event-ID sets, known verdict counts and stable, fully acknowledged
delivery snapshots. It is accepted evidence for the first 11-case set. No failed evidence was
deleted.

Attempt 13 extends that protocol with the three access/CSRF cases. Attempts
10–12 are retained: the reader initially lacked customer assignment, and the
fixture assertions expected descriptive permission errors where Dolibarr returns
a generic JSON `Forbidden`. The accepted cases check the application error code,
unchanged state, positive assignment/administrator controls and document access.
Harness inputs are checked for changes before and after browser execution so an
edited script cannot silently differ from its archived source snapshot.

## PrestaShop 9.2.0

The pinned image is 9.2.0 Apache, amd64. An initial all-internal-network install
failed because the upstream installer downloads language packs. The failed
fixture `artifacts/m4-business-3f93f9fa` is retained and stopped. The corrected
setup permits installation-only outbound networking with no published container
ports, then disconnects that network before activating the WAF. Runtime
network membership and downloaded translation hashes are recorded privately.
This is an installation dependency, not a WAF tuning exception.

All **six cases** pass in `artifacts/m4-business-77aadf7d/results-7.json`:
native storefront search, customer login/address display, product/cart quantity
changes, real checkout with offline bank wire, injection/XSS refusals and
wrong-host/over-limit-body refusals. Customer/address/product setup is seeded
locally; their creation through the WAF is not covered. The test uses generated
canonical URLs rather than legacy controller URLs that can discard search
parameters during canonical redirection.

The independent application-side check verifies committed order 8: exactly one
qualification-product line, quantity two, product total 50, and an unpaid
bank-wire state. No live payment is attempted. This attempt's two 403s, one 413
and one 421 reconcile. Complete retained history contains 15 records and
occurrences, including earlier browser-navigation cancellations. The current
attempt has none. Both captured database payload sets and final counters match;
`databases-7.tar` is retained. No global CRS exclusion or PrestaShop inspection
exception was added.

The next retained installation, `artifacts/m4-business-4d24729b`, failed during
asset finalization after the fixture renamed the administrator directory to
`adminlab`. PrestaShop 9.2's installer expects `admin-dev` on that path. A fresh
fixture, `artifacts/m4-business-77aadf7d`, installs successfully with that setting.
The readiness helper now fails promptly when an installer container exits.

Its first browser check exposed a WAF compatibility defect: schema-2 forwarding
rewrote HTTP Host to the upstream address. PrestaShop's canonical redirect code
uses raw HTTP Host as well as forwarded metadata, producing a redirect loop.
The direct application controls distinguish this behavior from inspection.
Canonical redirects have not been disabled. A regression reproduces the loop;
the correction preserves the already validated schema-2 application authority.
The fixed target still controls dialing/TLS SNI; schema 1 retains its earlier
Host behavior. Unknown hosts and spoofed forwarded headers remain rejected or
replaced. Additional retained harness corrections repair root-created PHP
caches, seed/check as the web identity, parse nested route JSON and inspect
committed order rows without a browser currency context. Canonical redirects
remain enabled. Translation ZIP hashes are locked for future installations;
unexpected bytes fail setup before WAF activation.

The final oracle uses durable event-ID sets, not host timestamps. Normal browser
cancellations can produce 200/499 security records; they are accepted only with
empty rule matches and the explicit cancellation reason, counted and reconciled.
Other unexpected security events fail qualification. A stable complete snapshot
is required after the browser context closes.

## Native ERP workflows, 5 November

The same exact server now passes **19 Dolibarr cases** in
`artifacts/m4-business-2be162b6/results-19.json`. This extends the earlier
14-case access set with real contact creation/customer linkage, reader denial,
validated sales-order lines/totals, native CSV import and native multipart
attachment upload/download. No new CRS exclusion or method exception was added.

The native CSV wizard uploads UTF-8 CSV through multipart, uses the product's
field mapping and simulation, confirms that simulation has not created the
customer, then commits and checks exactly one customer with the intended name,
email, client flag and generated customer code. This is application-native
import, separate from the older base64/JSON CSV attachment check. The native
customer attachment is downloaded with exact-byte verification; paired multipart
XSS and over-limit requests return 403 and 413 respectively. Application reader
denials are checked as product JSON errors, not mistaken for WAF refusals.
The multipart XSS pair is a form field; it does not establish arbitrary uploaded
file-content scanning.

This attempt accounts for nine WAF 403s, two 413s and one 421, with no browser
cancellation. All 123 retained event records/occurrences match the captured
independent receiver. Earlier exploratory attempts 14–18 remain failed and
retained: they exposed required import fields, relative wizard URL resolution,
the explicit simulation action/header-line setting and the hidden legacy upload
button. The accepted test uses the actual native form fields/token and multipart
endpoint; it does not force-click hidden UI controls or skip the simulation.

## Expanded storefront controls, 5 November

All **eight PrestaShop cases** pass in
`artifacts/m4-business-77aadf7d/results-9.json`. Added controls reject an incorrect
customer password without authenticating, remove the cart line and verify its
absence after reload, then re-add quantity two and complete checkout. Independent
application DB inspection confirms order 9: one product line, quantity two,
product total 50, unpaid bank-wire state. No live payment or external email is
used. No WAF exception was added.

The two rule blocks, one body-limit refusal and one hostname refusal reconcile
alongside five explicitly classified browser-navigation cancellations. All 24
retained records/occurrences match the captured receiver. Attempt 8 is retained
as failed: its selector assumed the Classic theme's CSS class, while the pinned
Hummingbird theme uses another class. The accepted selector uses the native
`data-link-action="delete-from-cart"` shared by both templates.

Business capacity is tracked separately in
[business workload measurements](M4-BUSINESS-CAPACITY.md), including the completed
Dolibarr mixed-write profile and independent committed-state probe.

## Remaining coverage

Linked quote-to-invoice transitions, native CSV export, additional document
formats and broader business roles remain open. Native orders, CSV import and
multipart customer attachments now have the bounded coverage above.
The reader and customer-form CSRF cases above are a bounded first permission
profile, not complete endpoint/role coverage. Downloading a CSV attachment alone
does not establish import/export qualification. PrestaShop back-office edits/uploads, discounts, variants and
customer/address creation remain planned beyond the first checkout set.
ERPNext is the second cohort. Broader business load/endurance, actual pilot workload,
business-database recovery, actual operator notification and independent review
remain M4 gates. Separate fresh-OS WAF recovery and deployed fault/alert labs
have since passed within their recorded scopes.

Run `scripts/check-business-evidence.py <results-N.json>` to independently
verify a completed report and its captured databases. See the
[application matrix](M4-BUSINESS-APPLICATIONS.md) for the wider acceptance scope.
Combined verification: `artifacts/m4-business-verification-20261105.json`.
Altered case/count/hash/event-ID proofs were checked for rejection. The accepted
protocol is archived beside each run; exploratory reports use earlier protocols.
Extended access verification: `artifacts/m4-business-access-verification-20261105.json`.
Final cleanup verified no owned active services or containers and powered the
VM off, retaining all fixtures and evidence. Cleanup record:
`artifacts/m4-business-cleanup-20261105.json`.
