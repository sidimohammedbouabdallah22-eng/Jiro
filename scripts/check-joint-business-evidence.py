"""Independently reconcile joint business requests, resources and durable exports."""
import argparse
from collections import Counter
import hashlib
import json
from pathlib import Path
import sqlite3
import tarfile


def sha(data):return hashlib.sha256(data).hexdigest()


def check(path,package):
    out=path.parent;r=json.loads(path.read_text());rows=json.loads((out/'requests.json').read_text())
    assert r['passed'] and r['cleanup']['restored'] and r['vm_powered_off']
    assert all(c['passed'] for c in r['cases']) and len(r['cases'])>=6
    assert sha(package.read_bytes())==r['package_sha256']==Path(str(package)+'.sha256').read_text().split()[0]
    with tarfile.open(package) as tar:assert sha(tar.extractfile('usr/lib/openwaf/waf-server').read())==r['server_sha256']
    for name,digest in r['sources'].items():assert sha((out/'source'/name).read_bytes())==digest
    assert all(row['status'] in [200,302,303,403,413,503] for row in rows)
    assert all(row['scheduled_latency_ms']>=row['latency_ms']>=0 for row in rows)
    assert r['spool_before']['files']==r['spool_after']['files']==r['spool_after']['bytes']==0
    files=json.loads((out/'files.json').read_text())
    assert len({(f['kind'],f['ref'],f['name']) for f in files})==len(files)
    probe=next(c for c in r['cases'] if c['name']=='committed files and refused-file absence')
    assert probe['files']==sum(f['committed'] for f in files)
    assert probe['bytes']==sum(f['bytes'] for f in files if f['committed'])
    assert probe['refused_files_absent']==sum(not f['committed'] for f in files)
    for width in [4,8,16,32]:
        burst=[row for row in rows if row['label']=='burst-'+str(width)]
        assert len(burst)==width and all(row['status'] in [200,503] for row in burst)
    assert len([x for x in rows if x['label']=='fairness-shop' and x['status']==200])==8
    assert len([x for x in rows if x['label']=='held-upload' and x['status']==200])==8
    assert len([x for x in rows if x['label']=='fairness-rejection' and x['status']==503])==1
    native=[json.loads(line) for line in (out/'resources.jsonl').read_text().splitlines()]
    assert sha((out/'resources.jsonl').read_bytes())==r['capture']['resources_sha256']
    pids=set()
    for phase in r['phases']:
        offered=[row for row in rows if row['label']==phase['name']]
        assert len(offered)==phase['requests']==int(phase['duration']*phase['erp_rate'])+int(phase['duration']*phase['shop_rate'])
        assert len({row['sequence'] for row in offered})==len(offered)
        assert dict(Counter(str(row['status']) for row in offered))==phase['statuses'] and not phase['errors']
        for app,key in [('dolibarr','p95_erp_ms'),('prestashop','p95_shop_ms')]:
            values=sorted(row['scheduled_latency_ms'] for row in offered if row['app']==app)
            assert round(values[int((len(values)-1)*.95)],3)==phase[key]
        assert sum(row['start_delay_ms']>100 for row in offered)==phase['late_over_100ms']
        begin,end=phase['guest_begin']['monotonic'],phase['guest_end']['monotonic']
        samples=[x for x in native if begin<=x['monotonic']<=end]
        assert len(samples)>30 and samples[0]['monotonic']-begin<4 and end-samples[-1]['monotonic']<4
        assert all(b['monotonic']-a['monotonic']<4 for a,b in zip(samples,samples[1:]))
        span=samples[-1]['monotonic']-samples[0]['monotonic'];cpu=0
        for kind in ['processes','containers']:
            for component in samples[0][kind]:
                values=[x[kind][component] for x in samples];assert all(not v.get('unavailable') for v in values)
                assert all(b['cpu_seconds']>=a['cpu_seconds'] for a,b in zip(values,values[1:]))
                cpu+=100*(values[-1]['cpu_seconds']-values[0]['cpu_seconds'])/span
                if kind=='processes':
                    assert len({v['pid'] for v in values})==1
                    if component=='gateway':
                        pids.add(values[0]['pid']);assert max(v['rss_kib'] for v in values)==phase['gateway_peak_rss_kib']
                else:assert all(v['oom_kill']==0 for v in values)
        first,last=samples[0]['host_cpu_ticks'],samples[-1]['host_cpu_ticks']
        busy=100*(1-((last[3]+last[4])-(first[3]+first[4]))/(sum(last[:8])-sum(first[:8])))
        assert abs(cpu-phase['cpu_components'])<1e-6 and abs(busy-phase['cpu_guest_busy'])<1e-6
        available=min(x['host_available_kib'] for x in samples);assert available==phase['min_host_available_kib']
        meets=all(x['status']==200 for x in offered) and phase['p95_shop_ms']<=2000 and phase['p95_erp_ms']<=(10000 if phase['large'] else 2000) and max(cpu,busy)<=85 and available>=512*1024 and phase['late_over_100ms']<=len(offered)*.01
        assert meets==phase['operating_budget_passed']
        if phase['name']!='large-cpu-screen':assert meets
    assert len(pids)==1 and len(r['phases'])==3 and r['phases'][-1]['duration']>=300
    status=r['final_status'];storage=status['storage']
    assert status['summary']['requests']==len(rows) and status['summary']['event_persistence_errors']==0
    assert status['resources']['active']==status['resources']['reserved_buffer_bytes']==0
    assert storage['healthy'] and storage['export']['healthy']
    assert all(storage[k]==0 for k in ['pending_writes','queue_dropped','write_failed','ingest_timeouts']) and storage['export']['pending_records']==0
    archive=out/'databases.tar';assert sha(archive.read_bytes())==r['capture']['sha256']
    with tarfile.open(archive) as tar:
        assert len(tar.getmembers())==2 and {m.name for m in tar}=={'events.db','collector.db'}
        dbs={}
        for member in tar:
            assert member.isfile() and member.size<=128<<20
            db=sqlite3.connect(':memory:');db.deserialize(tar.extractfile(member).read());assert db.execute('PRAGMA integrity_check').fetchone()[0]=='ok';dbs[member.name]=db
    sender,receiver=dbs['events.db'],dbs['collector.db']
    local=dict(sender.execute('SELECT id,data FROM events'));remote=dict(receiver.execute('SELECT id,data FROM collected_events'));assert local==remote
    events=[json.loads(data) for data in local.values()];observed=Counter()
    for event in events:observed[event['status']]+=max(1,event.get('occurrences',1))
    expected=Counter(row['status'] for row in rows if row['status'] in [403,413,503]);assert observed==expected
    occurrences=sum(observed.values());assert receiver.execute('SELECT records,occurrences FROM collector_totals').fetchone()==(len(events),occurrences)
    assert sender.execute('SELECT count(*) FROM export_outbox').fetchone()[0]==0
    assert storage['stored']==storage['export']['acked_records']==len(events)
    assert storage['committed_occurrences']==storage['export']['acked_occurrences']==occurrences
    for db in dbs.values():db.close()
    return dict(passed=True,requests=len(rows),records=len(events),occurrences=occurrences,statuses=dict(observed),checker_sha256=sha(Path(__file__).read_bytes()),business_pilot_started=False)


if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('report',type=Path);p.add_argument('--package',type=Path,required=True);a=p.parse_args()
    result=check(a.report,a.package);(a.report.parent/'verification.json').write_text(json.dumps(result,indent=2)+'\n');print(json.dumps(result))

