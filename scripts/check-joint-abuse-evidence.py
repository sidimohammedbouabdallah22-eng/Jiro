"""Recompute real-business CPU-abuse claims and reconcile durable event receipts."""
import argparse
from collections import Counter
import hashlib
import json
from pathlib import Path
import re
import sqlite3
import tarfile


def sha(data):
    return hashlib.sha256(data).hexdigest()


def check(path, package):
    if not __debug__:
        raise RuntimeError('evidence verification requires Python assertions; do not use -O')
    out = path.parent
    report = json.loads(path.read_text())
    rows = json.loads((out/'requests.json').read_text())
    assert report['passed'] and report['cleanup']['restored'] and report['vm_powered_off']
    assert sha(package.read_bytes()) == report['package_sha256'] == Path(str(package)+'.sha256').read_text().split()[0]
    with tarfile.open(package) as tar:
        assert sha(tar.extractfile('usr/lib/openwaf/waf-server').read()) == report['server_sha256']
    for name, digest in report['sources'].items():
        assert sha((out/'source'/name).read_bytes()) == digest
    assert report['customers_before'] == report['customers_after']
    assert report['customers_before']['customers'] > 0 and len(report['customers_before']['sha256']) == 64
    assert report['policy_restored'] and report['restored_policy']['applications'] == report['original_policy']['applications']
    assert report['restored_policy']['revision'] > report['original_policy']['revision']
    assert report['spool_before']['files'] == report['spool_after']['files'] == report['spool_after']['bytes'] == 0
    assert all(r['valid'] and 'error' not in r and r['status'] in [200,400,403,413,429,503] for r in rows)
    assert all(r['scheduled_ms'] >= r['service_ms'] >= 0 and r['request_bytes'] >= 0 for r in rows)
    names = ['storefront-baseline','ascii-eight-slots','unicode-eight-slots','unicode-one-slot',
             'bounded-oversize-unicode','bounded-small-escaped-unicode']
    indices = [0,3,4,5] if report.get('profile')=='bounded-after-failure' else list(range(6))
    assert [p['name'] for p in report['phases']] == [names[i] for i in indices]
    if report.get('profile')=='bounded-after-failure':
        prior=report['prior_failure'];assert re.fullmatch(r'm4-business-abuse-[a-f0-9]{8}',prior['artifact'])
        failed_path=out.parent/prior['artifact']/'result.json'
        assert sha(failed_path.read_bytes())==prior['result_sha256']
        failed=json.loads(failed_path.read_text())
        assert not failed['passed'] and failed['cleanup']['restored'] and failed['vm_powered_off']
        assert failed['package_sha256']==report['package_sha256'] and failed['server_sha256']==report['server_sha256']
        assert failed['customers_before']==report['customers_before']
        assert failed['phases'][-1]['name']=='unicode-eight-slots' and not failed['phases'][-1]['integrity_passed']
    assert report['budgets'] == dict(storefront_rate=1, storefront_p95_ms=2000, late_fraction=.01)
    raw = out/'resources.jsonl'
    assert sha(raw.read_bytes()) == report['capture']['resources_sha256']
    native = [json.loads(line) for line in raw.read_text().splitlines()]
    pids, phase_requests, accepted = set(), 0, []
    for index, phase in zip(indices, report['phases']):
        selected = [r for r in rows if r['label'] == phase['name']]
        shop = [r for r in selected if r['app'] == 'prestashop']
        heavy = [r for r in selected if r['app'] == 'dolibarr']
        seconds = phase['requested_seconds']
        assert 60 <= seconds <= 300 and phase['storefront_rate'] == 1
        assert len(shop) == phase['storefront_requests'] == seconds
        assert len(heavy) == phase['heavy_requests'] and len(selected) == phase['requests']
        assert {r['sequence'] for r in shop} == {'shop-'+str(i) for i in range(seconds)}
        assert len({r['sequence'] for r in selected}) == len(selected)
        assert phase['workers'] == (0 if index == 0 else 4) and phase['worker_max_attempts_per_second'] == 1
        assert not phase['errors'] and phase['invalid_responses'] == 0 and phase['integrity_passed']
        assert dict(Counter(str(r['status']) for r in shop)) == phase['storefront_statuses']
        assert dict(Counter(str(r['status']) for r in heavy)) == phase['heavy_statuses']
        assert phase['after']['summary']['requests']-phase['before']['summary']['requests'] == len(selected)
        phase_requests += len(selected)
        slots, limit, rate = (8 if index < 3 else 1), (1048576 if index < 4 else 65536), (0 if index < 4 else 1)
        policy = phase['policy']
        erp = next(a for a in policy['applications'] if a['application_id'] == 'dolibarr')
        storefront = next(a for a in policy['applications'] if a['application_id'] == 'prestashop')
        assert storefront == next(a for a in report['original_policy']['applications'] if a['application_id']=='prestashop')
        assert erp['traffic_controls']['max_concurrent'] == slots and erp['traffic_controls']['requests_per_second'] == rate
        assert erp['policy']['request_limit'] == limit and erp['policy']['mode'] == 'enforcing'
        original = next(a for a in report['original_policy']['applications'] if a['application_id']=='dolibarr')
        assert {k:v for k,v in erp['policy'].items() if k!='request_limit'} == {k:v for k,v in original['policy'].items() if k!='request_limit'}
        size, kind = [(0,'ascii'),(900<<10,'ascii'),(900<<10,'unicode'),(900<<10,'unicode'),
                      (900<<10,'unicode'),(32<<10,'escaped')][index]
        assert phase['body_bytes'] == size
        if size:
            # Reconstruct exact public synthetic bytes without importing the driver.
            suffix = '' if kind=='ascii' else 'é'
            overhead = len(json.dumps({'payload':suffix},ensure_ascii=kind=='escaped',separators=(',',':')).encode())
            body = json.dumps({'payload':'a'*(size-overhead)+suffix},ensure_ascii=kind=='escaped',separators=(',',':')).encode()
            assert len(body) == size and sha(body) == phase['body_sha256']
            assert heavy and all(r['request_bytes']==size and r['request_sha256']==sha(body) for r in heavy)
            for worker in range(4):
                indices = [int(r['sequence'].split('-')[2]) for r in heavy if r['sequence'].startswith('erp-'+str(worker)+'-')]
                assert indices and sorted(indices) == list(range(len(indices))) and len(indices) <= seconds+1
        else:
            assert not heavy and phase['body_sha256']==sha(b'')
        for group, field, key in [(shop,'scheduled_ms','storefront_p95_ms'),(shop,'scheduled_ms','storefront_p99_ms'),(heavy,'scheduled_ms','heavy_p95_ms')]:
            values = sorted(r[field] for r in group)
            fraction = .99 if key=='storefront_p99_ms' else .95
            expected = round(values[int((len(values)-1)*fraction)],3) if values else None
            assert phase[key] == expected
        late = sum(r['start_delay_ms']>100 for r in shop)
        assert phase['storefront_late_over_100ms'] == late
        budget = all(r['status']==200 for r in shop) and phase['storefront_p95_ms']<=2000 and late<=seconds*.01
        assert phase['storefront_budget_passed'] == budget and phase['required'] == (index in [0,4,5])
        if phase['required']:
            assert budget
        if budget:
            accepted.append(phase['name'])
        begin, end = phase['guest_begin']['monotonic'], phase['guest_workload_end']['monotonic']
        samples = [s for s in native if begin<=s['monotonic']<=end]
        assert len(samples)>=20 and samples[0]['monotonic']-begin<4 and end-samples[-1]['monotonic']<4
        assert all(b['monotonic']-a['monotonic']<4 for a,b in zip(samples,samples[1:]))
        span = samples[-1]['monotonic']-samples[0]['monotonic']
        facts = phase['resources'];assert facts['samples']==len(samples) and facts['sampled_seconds']==span
        cpu = 0
        for group in ['processes','containers']:
            for name in samples[0][group]:
                values = [s[group][name] for s in samples]
                assert all(not v.get('unavailable') for v in values)
                assert all(b['cpu_seconds']>=a['cpu_seconds'] for a,b in zip(values,values[1:]))
                value = 100*(values[-1]['cpu_seconds']-values[0]['cpu_seconds'])/span
                cpu += value;assert abs(value-facts[group][name]['cpu_percent'])<1e-6
                if group=='processes':
                    assert len({v['pid'] for v in values})==1 and facts[group][name]['pid']==values[0]['pid']
                    assert max(v['rss_kib'] for v in values)==facts[group][name]['peak_rss_kib']
                    if name=='gateway':pids.add(values[0]['pid'])
                else:
                    assert all(v['oom_kill']==0 for v in values) and facts[group][name]['oom_kill']==0
                    assert max(v['memory_bytes'] for v in values)==facts[group][name]['peak_memory_bytes']
        first,last = samples[0]['host_cpu_ticks'],samples[-1]['host_cpu_ticks']
        busy = 100*(1-((last[3]+last[4])-(first[3]+first[4]))/(sum(last[:8])-sum(first[:8])))
        assert abs(cpu-facts['component_cpu_percent'])<1e-6 and abs(busy-facts['guest_busy_percent'])<1e-6
        assert abs(max(cpu,busy)-facts['observed_cpu_percent'])<1e-6
        assert min(s['host_available_kib'] for s in samples)==facts['min_available_kib']
    assert len(pids)==1
    assert len([r for r in rows if r['label']=='bounded-controls' and r['status']==403])==1
    assert len([r for r in rows if r['label']=='bounded-controls' and r['status']==413])==1
    assert Counter(r['status'] for r in rows if r['label']=='bounded-rate-control')==Counter({400:1,429:1})
    assert len(rows)==phase_requests+5  # one preflight plus two inspection and two rate controls
    status=report['final_status'];storage=status['storage']
    assert status['summary']['requests']==len(rows) and status['summary']['event_persistence_errors']==0
    assert status['resources']['active']==status['resources']['reserved_buffer_bytes']==0
    assert storage['healthy'] and storage['export']['healthy']
    assert all(storage[k]==0 for k in ['pending_writes','queue_dropped','write_failed','ingest_timeouts'])
    assert storage['export']['pending_records']==0
    archive=out/'databases.tar';assert sha(archive.read_bytes())==report['capture']['sha256']
    with tarfile.open(archive) as tar:
        assert len(tar.getmembers())==2 and {m.name for m in tar}=={'events.db','collector.db'}
        dbs={}
        for member in tar:
            assert member.isfile() and 0<member.size<=128<<20
            db=sqlite3.connect(':memory:');db.deserialize(tar.extractfile(member).read());assert db.execute('PRAGMA integrity_check').fetchone()[0]=='ok';dbs[member.name]=db
    sender,receiver=dbs['events.db'],dbs['collector.db']
    local=dict(sender.execute('SELECT id,data FROM events'));remote=dict(receiver.execute('SELECT id,data FROM collected_events'));assert local==remote
    events=[json.loads(data) for data in local.values()];observed=Counter()
    for event in events:observed[event['status']]+=max(1,event.get('occurrences',1))
    assert observed==Counter(r['status'] for r in rows if r['status'] in [403,413,429,503])
    occurrences=sum(observed.values())
    assert receiver.execute('SELECT records,occurrences FROM collector_totals').fetchone()==(len(events),occurrences)
    assert sender.execute('SELECT count(*) FROM export_outbox').fetchone()[0]==0
    assert storage['stored']==storage['export']['acked_records']==len(events)
    assert storage['committed_occurrences']==storage['export']['acked_occurrences']==occurrences
    for db in dbs.values():db.close()
    return dict(passed=True,requests=len(rows),records=len(events),occurrences=occurrences,statuses=dict(observed),
                accepted_storefront_screens=accepted,checker_sha256=sha(Path(__file__).read_bytes()),business_pilot_started=False)


if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('report',type=Path);p.add_argument('--package',type=Path,required=True)
    a=p.parse_args();result=check(a.report,a.package)
    (a.report.parent/'verification.json').write_text(json.dumps(result,indent=2)+'\n');print(json.dumps(result))
