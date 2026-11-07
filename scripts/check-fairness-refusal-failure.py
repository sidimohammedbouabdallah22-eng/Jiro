"""Verify the retained zero-wait refusal failure and later on-disk recheck."""
import argparse
from collections import Counter
import hashlib
import json
from pathlib import Path
import sqlite3
import tarfile


def sha(data):return hashlib.sha256(data).hexdigest()


def main():
    if not __debug__:raise RuntimeError('verification requires assertions')
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('report',type=Path);p.add_argument('--recheck',type=Path,required=True);a=p.parse_args()
    out=a.report.parent;r=json.loads(a.report.read_text());rows=json.loads((out/'requests.json').read_text())
    assert not r['passed'] and r['cleanup']['restored'] and r['vm_powered_off']
    assert [p['name'] for p in r['phases']]==['baseline','erp-abuse','storefront-abuse']
    assert r['phases'][1]['responsiveness_passed'] and not r['phases'][2]['responsiveness_passed']
    assert all(row['valid'] and 'error' not in row for row in rows)
    bad=[row for row in rows if row['role'].startswith('legit-') and row['status']!=200]
    assert Counter(row['role'] for row in bad)=={'legit-shop':3,'legit-download':1}
    for row in bad:
        reason='Client concurrency share exhausted' if row['role']=='legit-download' else 'Application admission share exhausted'
        body=(reason+'\n').encode();assert row['status']==503 and row['response_sha256']==sha(body)
    newer=json.loads(a.recheck.read_text());proof=newer['prior_run_recheck']
    assert proof['artifact']==out.name and proof['result_sha256']==sha(a.report.read_bytes())
    assert proof['business_state_unchanged'] and proof['file_probe']['passed'] and proof['file_probe']['files']==63
    assert proof['file_probe']['bytes']==63*(700<<10)
    for name,digest in r['sources'].items():assert sha((out/'source'/name).read_bytes())==digest
    state=r['failure_status'];storage=state['storage']
    assert state['summary']['requests']==len(rows) and state['summary']['event_persistence_errors']==0
    assert state['resources']['active']==state['resources']['reserved_buffer_bytes']==0
    assert storage['healthy'] and storage['export']['healthy'] and storage['export']['pending_records']==0
    assert all(storage[k]==0 for k in ['pending_writes','queue_dropped','write_failed','ingest_timeouts'])
    assert sha((out/'databases.tar').read_bytes())==r['capture']['sha256']
    with tarfile.open(out/'databases.tar') as tar:
        dbs={}
        assert {m.name for m in tar}=={'events.db','collector.db'}
        for member in tar:
            assert member.isfile() and member.size<=128<<20
            db=sqlite3.connect(':memory:');db.deserialize(tar.extractfile(member).read());assert db.execute('PRAGMA integrity_check').fetchone()[0]=='ok';dbs[member.name]=db
    sender,receiver=dbs['events.db'],dbs['collector.db'];local=dict(sender.execute('SELECT id,data FROM events'));remote=dict(receiver.execute('SELECT id,data FROM collected_events'));assert local==remote
    events=[json.loads(data) for data in local.values()];actual=Counter()
    for e in events:actual[(e['application_id'],e['status'])]+=max(1,e.get('occurrences',1))
    assert actual==Counter((row['app'],row['status']) for row in rows if row['status'] in [403,429,503])
    occurrences=sum(actual.values());assert receiver.execute('SELECT records,occurrences FROM collector_totals').fetchone()==(len(events),occurrences)
    assert sender.execute('SELECT count(*) FROM export_outbox').fetchone()[0]==0
    assert storage['stored']==storage['export']['acked_records']==len(events)
    assert storage['committed_occurrences']==storage['export']['acked_occurrences']==occurrences
    for db in dbs.values():db.close()
    result=dict(evidence_verified=True,operating_profile_qualified=False,legitimate_refusals=4,
                intact_acknowledged_uploads=63,records=len(events),occurrences=occurrences,
                checker_sha256=sha(Path(__file__).read_bytes()))
    (out/'failure-verification.json').write_text(json.dumps(result,indent=2)+'\n');print(json.dumps(result))


if __name__=='__main__':main()
