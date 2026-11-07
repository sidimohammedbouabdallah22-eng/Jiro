"""Verify retained timeout evidence without converting a failed screen into a pass."""
import argparse
from collections import Counter
import hashlib
import json
from pathlib import Path
import sqlite3
import tarfile


def sha(data):return hashlib.sha256(data).hexdigest()


def main():
    if not __debug__:raise RuntimeError('verification requires Python assertions')
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('report',type=Path)
    p.add_argument('--package',type=Path,required=True);a=p.parse_args();out=a.report.parent
    r=json.loads(a.report.read_text());rows=json.loads((out/'requests.json').read_text())
    assert not r['passed'] and r['cleanup']['restored'] and r['vm_powered_off']
    assert r['package_sha256']==sha(a.package.read_bytes())==Path(str(a.package)+'.sha256').read_text().split()[0]
    with tarfile.open(a.package) as tar:assert sha(tar.extractfile('usr/lib/openwaf/waf-server').read())==r['server_sha256']
    for name,digest in r['sources'].items():assert sha((out/'source'/name).read_bytes())==digest
    assert [phase['name'] for phase in r['phases']]==['storefront-baseline','ascii-eight-slots','unicode-eight-slots']
    phase=r['phases'][-1];heavy=[row for row in rows if row['label']==phase['name'] and row['app']=='dolibarr']
    assert not phase['integrity_passed'] and not phase['storefront_budget_passed']
    assert len(heavy)==len(phase['errors'])==8 and set(phase['errors'])=={'TimeoutError'}
    assert all(row['status']==0 and row['error']=='TimeoutError' and row['service_ms']>=44000 for row in heavy)
    assert all(row['valid'] for row in rows if row not in heavy)
    status=r['failure_status'];storage=status['storage']
    assert status['summary']['requests']==len(rows)==319 and status['summary']['errors']==8
    assert status['summary']['event_persistence_errors']==0 and status['resources']['active']==status['resources']['reserved_buffer_bytes']==0
    assert all(storage[k]==0 for k in ['pending_writes','queue_dropped','write_failed','ingest_timeouts'])
    assert storage['export']['pending_records']==0 and storage['healthy'] and storage['export']['healthy']
    assert sha((out/'resources.jsonl').read_bytes())==r['capture']['resources_sha256']
    native=[json.loads(line) for line in (out/'resources.jsonl').read_text().splitlines()]
    pids=set()
    for phase in r['phases']:
        samples=[x for x in native if phase['guest_begin']['monotonic']<=x['monotonic']<=phase['guest_workload_end']['monotonic']]
        assert len(samples)>=20 and all(b['monotonic']-a['monotonic']<4 for a,b in zip(samples,samples[1:]))
        for sample in samples:
            assert all(not v.get('unavailable') for v in sample['processes'].values())
            assert all(not v.get('unavailable') and v['oom_kill']==0 for v in sample['containers'].values())
            pids.add(sample['processes']['gateway']['pid'])
    assert len(pids)==1
    assert sha((out/'databases.tar').read_bytes())==r['capture']['sha256']
    with tarfile.open(out/'databases.tar') as tar:
        assert len(tar.getmembers())==2 and {m.name for m in tar}=={'events.db','collector.db'}
        dbs={}
        for member in tar:
            assert member.isfile() and member.size<=128<<20
            db=sqlite3.connect(':memory:');db.deserialize(tar.extractfile(member).read());assert db.execute('PRAGMA integrity_check').fetchone()[0]=='ok';dbs[member.name]=db
    sender,receiver=dbs['events.db'],dbs['collector.db']
    local=dict(sender.execute('SELECT id,data FROM events'));remote=dict(receiver.execute('SELECT id,data FROM collected_events'));assert local==remote
    events=[json.loads(data) for data in local.values()]
    assert len(events)==8 and all(e['status']==502 and e['upstream_error_class']=='timeout' and e['duration_ms']>30000 and e.get('occurrences',1)==1 for e in events)
    assert receiver.execute('SELECT records,occurrences FROM collector_totals').fetchone()==(8,8)
    assert storage['stored']==storage['export']['acked_records']==storage['committed_occurrences']==storage['export']['acked_occurrences']==8
    assert sender.execute('SELECT count(*) FROM export_outbox').fetchone()[0]==0
    for db in dbs.values():db.close()
    result=dict(evidence_verified=True,qualification_passed=False,requests=len(rows),client_timeouts=8,
                gateway_timeout_events=8,minimum_gateway_duration_ms=min(e['duration_ms'] for e in events),
                maximum_gateway_duration_ms=max(e['duration_ms'] for e in events),
                process_restarts=0,sampled_oom_kills=0,event_loss=0,
                checker_sha256=sha(Path(__file__).read_bytes()),business_pilot_started=False,
                limitation='30-second HTTP context does not preempt synchronous inspection; wide Unicode profile failed')
    (out/'failure-verification.json').write_text(json.dumps(result,indent=2)+'\n');print(json.dumps(result))


if __name__=='__main__':main()
