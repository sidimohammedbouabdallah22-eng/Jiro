# Export health after a late local checkpoint

The regression is fixed. Candidate `7be7bc728f08` passes both full platform
suites, focused Linux race checks and 27 business workflows. Its sustained abuse
run independently reconciles all 6,640 security occurrences and drains delivery.
[Sustained results](M4-SUSTAINED-FAIRNESS.md).

Candidate `4a145e37f9b5` stops before the workload in
`artifacts/m4-business-abuse-b003efee`: the exporter reports a context deadline
although both security events are durably stored at the receiver and the local
outbox is empty. Independent captured-database accounting verifies all four
preflight requests and both records/occurrences. No delivery loss is established.
The maximum local commit time is 2,343.321 ms, beyond the two-second local
checkpoint acknowledgement wait. The receiver ACK is verified, the checkpoint
commits late, then empty export polls leave the earlier error sticky.

The corrected exporter retains the time of a verified receiver acknowledgement
when its local checkpoint returns an error. Health can recover when a subsequent
successful database query finds the durable outbox empty and the writer has
published zero pending rows. It records the actual earlier receiver-ACK time;
it does not invent another receiver contact. Failure history remains counted.
Unverified receiver responses, pending records and query failures cannot use
this recovery. Failed checkpoints with remaining records still replay through
the existing durable receiver deduplication path. No deadline is widened.

The regression commits the checkpoint, delays publishing the writer result
past the caller deadline, and verifies recovery with no new event and exactly
one collector request. Before publication health remains unhealthy. The old
implementation fails the recovery assertion; the corrected targeted test passes.
Both outputs are retained under `artifacts/m4-upstream-idle-20261106`.

The lab drain now waits for drained counts and healthy storage/export together,
within its original ninety-second deadline. Counts reaching zero before the
export loop publishes its status are not an immediate qualification failure;
a sticky error still fails by the deadline. Write failures, drops, ingest
timeouts and incomplete receipts remain failure conditions.

The first combined correction is frozen in candidate `a720777a5f60`. The latest
qualified lab binary `7be7bc728f08` also contains the client buffer budget.
M4 remains open for deployment-sensitive repetitions, review and the pilot.
