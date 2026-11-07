"""Recompute business capacity claims from offered-load logs and captured DBs."""
import argparse
from collections import Counter
import hashlib
import json
from pathlib import Path
import sqlite3
import tarfile


def sha(data):return hashlib.sha256(data).hexdigest()


def check(path,package):
    report=json.loads(path.read_text());out=path.parent
    assert report['passed'] and report['cleanup']['stopped'] and report['vm_powered_off']
    assert sha(package.read_bytes())==Path(str(package)+'.sha256').read_text().split()[0]==report['package_sha256']
    with tarfile.open(package) as tar:assert sha(tar.extractfile('usr/lib/openwaf/waf-server').read())==report['server_sha256']
    for name,expected in report['sources'].items():assert sha((out/'source'/name).read_bytes())==expected
    workflow=json.loads((out/'source/workflow-report.json').read_text())
    assert sha((out/'source/workflow-report.json').read_bytes())==report['workflow_sha256']
    assert workflow['passed'] and workflow['app']==report['app'] and workflow['server_sha256']==report['server_sha256']
    assert report['environment']['cpus']==1 and 3584*1024<=report['environment']['memory_kib']<=4096*1024
    expected_budget=dict(p95_scheduled_ms=2000,host_busy_percent=85,gateway_cpu_percent_one_vcpu=80,min_host_available_kib=512*1024)
    assert report['budgets']==expected_budget
    raw=out/'resources.jsonl';assert sha(raw.read_bytes())==report['capture']['resource_sha256']
    native=[json.loads(line) for line in raw.read_text().splitlines()]
    expected_statuses=Counter();total_requests=0;all_pids=set();accepted=[]
    for phase in report['phases']:
        rows=json.loads((out/(phase['name']+'.requests.json')).read_text())
        assert len(rows)==phase['completed']==phase['planned']==int(phase['rate']*phase['duration_seconds'])
        assert [row['sequence'] for row in rows]==list(range(len(rows)))
        assert phase['functional_passed'] and all(row['ok'] and row['error'] is None and row['status']==row['expected'] for row in rows)
        assert all(row['status'] in [200,403,413] and row['scheduled_ms']>=row['service_ms']>=0 for row in rows)
        p95=round(sorted(row['scheduled_ms'] for row in rows)[int((len(rows)-1)*.95)],3)
        assert p95==phase['p95_scheduled_ms']
        assert sum(row['late_ms']>100 for row in rows)==phase['late_over_100ms']
        begin,end=phase['guest_begin']['monotonic'],phase['guest_end']['monotonic']
        selected=[row for row in native if begin<=row['monotonic']<=end]
        assert len(selected)>=2 and selected[0]['monotonic']-begin<=6 and end-selected[-1]['monotonic']<=6
        assert all(b['monotonic']-a['monotonic']<=6 for a,b in zip(selected,selected[1:]))
        span=selected[-1]['monotonic']-selected[0]['monotonic'];assert span>30
        resources=phase['resources'];assert len(selected)==resources['samples'] and abs(span-resources['sampled_seconds'])<1e-6
        for name in ['gateway','collector','relay']:
            values=[row['processes'][name] for row in selected];assert all(not row.get('unavailable') for row in values)
            assert len({row['pid'] for row in values})==1
            cpu=100*(values[-1]['cpu_seconds']-values[0]['cpu_seconds'])/span
            assert abs(cpu-resources['processes'][name]['cpu_percent_one_vcpu'])<1e-6
            assert resources['processes'][name]['peak_rss_kib']==max(row['rss_kib'] for row in values)
            if name=='gateway':all_pids.add(values[0]['pid'])
        first,last=selected[0]['host_cpu_ticks'],selected[-1]['host_cpu_ticks']
        busy=100*(1-((last[3]+last[4])-(first[3]+first[4]))/(sum(last[:8])-sum(first[:8])))
        assert abs(busy-resources['host_busy_percent'])<1e-6
        available=min(row['host_available_kib'] for row in selected);assert available==resources['min_host_available_kib']
        for name in ['app','db']:
            values=[row['containers'][name] for row in selected];assert all(not row.get('unavailable') for row in values)
            assert resources['containers'][name]['peak_memory_bytes']==max(row['memory_bytes'] for row in values)
            assert abs(resources['containers'][name]['cpu_percent_one_vcpu']-100*(values[-1]['cpu_seconds']-values[0]['cpu_seconds'])/span)<1e-6
        component_sum=sum(value['cpu_percent_one_vcpu'] for value in resources['processes'].values())+sum(value['cpu_percent_one_vcpu'] for value in resources['containers'].values())
        if 'component_cpu_sum_percent' in resources:
            assert abs(component_sum-resources['component_cpu_sum_percent'])<1e-6
            assert abs(max(busy,component_sum)-resources['max_observed_cpu_percent'])<1e-6
        meets=p95<=2000 and phase['late_over_100ms']<=len(rows)*.01 and max(busy,component_sum)<=85 and resources['processes']['gateway']['cpu_percent_one_vcpu']<=80 and available>=512*1024
        assert meets==phase['accepted_operating_profile']
        if phase['name'].startswith('mixed-') and meets:accepted.append(phase['rate'])
        if phase['name']!='direct-business':
            total_requests+=len(rows)
            expected_statuses.update(row['status'] for row in rows if row['status']!=200)
    assert len(all_pids)==1 and accepted and report['accepted_rate']==max(accepted)
    endurance=report['phases'][-1]
    assert endurance['name']=='business-endurance' and endurance['accepted_operating_profile'] and endurance['rate']==report['accepted_rate']
    assert endurance['duration_seconds']==report['endurance_seconds']>=300
    final,before=report['final'],report['before']
    assert final['summary']['requests']-before['summary']['requests']==total_requests
    assert final['summary']['event_persistence_errors']==0
    storage=final['storage'];assert storage['healthy'] and storage['export']['healthy']
    assert all(storage[key]==0 for key in ['pending_writes','queue_dropped','write_failed','ingest_timeouts']) and storage['export']['pending_records']==0
    archive=out/'databases.tar';assert sha(archive.read_bytes())==report['capture']['sha256']
    with tarfile.open(archive) as tar:
        members=tar.getmembers();assert len(members)==2 and {m.name for m in members}=={'events.db','collector.db'}
        dbs={}
        for member in members:
            assert member.isfile() and member.size<=128<<20
            db=sqlite3.connect(':memory:');db.deserialize(tar.extractfile(member).read());assert db.execute('PRAGMA integrity_check').fetchone()[0]=='ok';dbs[member.name]=db
    sender,receiver=dbs['events.db'],dbs['collector.db']
    local=dict(sender.execute('SELECT id,data FROM events'));remote=dict(receiver.execute('SELECT id,data FROM collected_events'));assert local==remote
    ordered=list(sender.execute('SELECT data FROM events ORDER BY seq'));initial=before['storage']['stored']
    fresh=[json.loads(row[0]) for row in ordered[initial:]]
    observed=Counter()
    for event in fresh:observed[event['status']]+=max(1,event.get('occurrences',1))
    assert observed==expected_statuses and len(fresh)==sum(expected_statuses.values())
    occurrences=sum(max(1,json.loads(row).get('occurrences',1)) for row in local.values())
    assert receiver.execute('SELECT records,occurrences FROM collector_totals').fetchone()==(len(local),occurrences)
    assert storage['stored']==storage['export']['acked_records']==len(local)
    assert storage['committed_occurrences']==storage['export']['acked_occurrences']==occurrences
    assert sender.execute('SELECT count(*) FROM export_outbox').fetchone()[0]==0
    for db in dbs.values():db.close()
    end_resources=endurance['resources']
    end_component=sum(v['cpu_percent_one_vcpu'] for v in end_resources['processes'].values())+sum(v['cpu_percent_one_vcpu'] for v in end_resources['containers'].values())
    result=dict(passed=True,report=str(path),checker_sha256=sha(Path(__file__).read_bytes()),app=report['app'],accepted_offered_rate=report['accepted_rate'],endurance_seconds=report['endurance_seconds'],protected_requests=total_requests,new_verdict_occurrences=dict(observed),retained_security_records=len(local),retained_security_occurrences=occurrences,clock_alignment='guest monotonic phase markers',endurance_max_observed_cpu_percent=max(end_resources['host_busy_percent'],end_component),business_pilot_started=False,customer_sizing_qualified=False)
    (out/'verification.json').write_text(json.dumps(result,indent=2)+'\n');(out/'source/check-business-capacity-evidence.py').write_bytes(Path(__file__).read_bytes())
    return result


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('report',type=Path);parser.add_argument('--package',type=Path,required=True)
    args=parser.parse_args();print(json.dumps(check(args.report,args.package),indent=2))
