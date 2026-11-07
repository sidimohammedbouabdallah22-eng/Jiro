"""Reconcile a failed abuse run without claiming its unexecuted final probes."""
import argparse
from collections import Counter
import hashlib
import json
from pathlib import Path
import sqlite3
import tarfile


def sha(data):
    return hashlib.sha256(data).hexdigest()


def check(report, package):
    out = report.parent
    r = json.loads(report.read_text())
    rows = json.loads((out / 'requests.json').read_text())
    assert not r['passed'] and r['cleanup']['restored'] and r['vm_powered_off']
    assert r['lanes_cleanup']['stopped']
    assert sha(package.read_bytes()) == r['package_sha256']
    with tarfile.open(package) as tar:
        assert sha(tar.extractfile('usr/lib/openwaf/waf-server').read()) == r['server_sha256']
    for name, digest in r['sources'].items():
        assert sha((out / 'source' / name).read_bytes()) == digest
    for name, key in [('databases.tar', 'sha256'), ('resources.jsonl', 'resources_sha256')]:
        assert sha((out / name).read_bytes()) == r['capture'][key]
    state = r['failure_status']
    assert state['summary']['requests'] == len(rows)
    assert not state['summary']['event_persistence_errors']
    assert state['resources']['active'] == state['resources']['reserved_buffer_bytes'] == 0
    assert state['resources'].get('pending_admissions', 0) == 0
    storage = state['storage']
    assert all(storage[k] == 0 for k in ['pending_writes', 'queue_dropped', 'write_failed', 'ingest_timeouts'])
    assert storage['export']['pending_records'] == 0
    assert not any('error' in row for row in rows), 'transport failure requires a different accounting oracle'
    with tarfile.open(out / 'databases.tar') as tar:
        assert {m.name for m in tar} == {'events.db', 'collector.db'}
        dbs = {}
        for m in tar:
            assert m.isfile() and m.size <= 128 << 20
            db = sqlite3.connect(':memory:')
            db.deserialize(tar.extractfile(m).read())
            assert db.execute('PRAGMA integrity_check').fetchone()[0] == 'ok'
            dbs[m.name] = db
    sender, receiver = dbs['events.db'], dbs['collector.db']
    local = dict(sender.execute('SELECT id,data FROM events'))
    assert local == dict(receiver.execute('SELECT id,data FROM collected_events'))
    events = [json.loads(data) for data in local.values()]
    expected = Counter((row['app'], row['peer'], row['status']) for row in rows if row['status'] in [403, 429, 502, 503])
    totals, observed, exact, wild = Counter(), Counter(), Counter(), Counter()
    for (app, peer, status), n in expected.items():
        totals[(app, status)] += n
    for e in events:
        app, peer, status = e['application_id'], e['ip'], e['status']
        n = max(1, e.get('occurrences', 1))
        observed[(app, status)] += n
        if peer == '*':
            assert e.get('aggregated') and n > 1
            wild[(app, status)] += n
        else:
            exact[(app, peer, status)] += n
    assert totals == observed
    assert all(n <= expected[key] for key, n in exact.items())
    residual = Counter()
    for (app, peer, status), n in expected.items():
        residual[(app, status)] += n - exact[(app, peer, status)]
    assert +residual == +wild
    occurrences = sum(observed.values())
    assert receiver.execute('SELECT records,occurrences FROM collector_totals').fetchone() == (len(events), occurrences)
    assert sender.execute('SELECT count(*) FROM export_outbox').fetchone()[0] == 0
    assert storage['stored'] == storage['export']['acked_records'] == len(events)
    assert storage['committed_occurrences'] == storage['export']['acked_occurrences'] == occurrences
    for db in dbs.values():
        db.close()
    return dict(failed_run_accounting_verified=True, operating_profile_qualified=False,
                requests=len(rows), records=len(events), occurrences=occurrences,
                reported_storage_healthy=storage['healthy'], reported_export_healthy=storage['export']['healthy'],
                legitimate_non_200=sum(row['role'].startswith('legit-') and row['status'] != 200 for row in rows),
                legitimate_capacity_refusals=sum(row['role'].startswith('legit-') and row['status'] in [429,503] for row in rows),
                invalid_responses=sum(not row['valid'] for row in rows),
                upstream_errors=[dict(application=e['application_id'], error_class=e.get('upstream_error_class'),
                                      duration_ms=e.get('duration_ms')) for e in events if e['status'] == 502],
                final_file_and_business_state_probes_executed=False,
                checker_sha256=sha(Path(__file__).read_bytes()))


if __name__ == '__main__':
    if not __debug__:
        raise RuntimeError('verification requires assertions')
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('report', type=Path)
    p.add_argument('--package', type=Path, required=True)
    a = p.parse_args()
    result = check(a.report, a.package)
    (a.report.parent / 'failure-accounting.json').write_text(json.dumps(result, indent=2) + '\n')
    print(json.dumps(result))
