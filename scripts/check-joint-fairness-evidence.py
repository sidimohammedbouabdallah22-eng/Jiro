"""Independently check real-peer bidirectional abuse and committed large uploads."""
import argparse
import base64
import csv
from collections import Counter
import hashlib
import json
import io
from pathlib import Path
import sqlite3
import tarfile


def sha(data):return hashlib.sha256(data).hexdigest()


def percentile(values):
    values=sorted(values);return round(values[int((len(values)-1)*.95)],3) if values else None


def check(path,package):
    if not __debug__:raise RuntimeError('verification requires assertions')
    out=path.parent;r=json.loads(path.read_text());rows=json.loads((out/'requests.json').read_text());files=json.loads((out/'files.json').read_text())
    assert r['passed'] and r['cleanup']['restored'] and r['lanes_cleanup']['stopped'] and r['vm_powered_off']
    assert sha(package.read_bytes())==r['package_sha256']==Path(str(package)+'.sha256').read_text().split()[0]
    with tarfile.open(package) as tar:assert sha(tar.extractfile('usr/lib/openwaf/waf-server').read())==r['server_sha256']
    for name,digest in r['sources'].items():assert sha((out/'source'/name).read_bytes())==digest
    assert r['customers_before']==r['customers_after'] and r['store_before']==r['store_after']
    if 'upload_fixture_sha256' in r:
        content=(out/'upload-content.bin').read_bytes();assert len(content)==700<<10 and sha(content)==r['upload_fixture_sha256']
        if r['upload_format']=='mixed-csv':
            parsed=list(csv.reader(io.StringIO(content.decode('utf-8'),newline='')))
            assert len(parsed)>1000 and all(len(row)==5 for row in parsed)
            assert b'\xd9' in content and b'\xc3' in content and any('\n' in field for row in parsed for field in row)
    else:
        content=b'OpenWAF sustained upload\n'+b'a'*((700<<10)-len(b'OpenWAF sustained upload\n'))
    assert r['original_policy']['applications']==r['restored_policy']['applications']
    peers={'upload':'127.0.0.2','storefront':'127.0.0.3','attacker':'127.0.0.10','second-attacker':'127.0.0.11'}
    assert {k:v['peer'] for k,v in r['lanes'].items()}==peers
    assert all(row['peer']==peers[row['lane']] and row['valid'] and 'error' not in row for row in rows)
    assert all(row['scheduled_ms']>=row['service_ms']>=0 for row in rows)
    assert [p['name'] for p in r['phases']]==['baseline','erp-abuse','storefront-abuse','simultaneous-abuse']
    assert [p['targets'] for p in r['phases']]==[[],['dolibarr'],['prestashop'],['dolibarr','prestashop']]
    raw=out/'resources.jsonl';assert sha(raw.read_bytes())==r['capture']['resources_sha256']
    native=[json.loads(line) for line in raw.read_text().splitlines()]
    assert r.get('sampler_version',1)==native[0].get('sampler_version',1)
    if r.get('sampler_version',1)==2:
        for name in ['gateway','collector']:
            assert len({(s['processes'][name]['pid'],s['processes'][name]['start_ticks']) for s in native})==1
        previous=None
        for sample in native:
            assert sample['sampler_version']==2 and sample['collection_ms']>=0
            process=sample['processes']['gateway'];attestation=process['executable'];key=attestation['signature']
            assert len(key)==7 and key[0]==process['pid'] and key[1]==process['start_ticks']
            assert attestation['sha256']==r['server_sha256']
            if key!=previous:assert attestation['recomputed']
            previous=key
    vcpus=r.get('vcpus',1);assert vcpus in [1,2,4]
    if 'guest_logical_cpus' in r:assert r['guest_logical_cpus']==vcpus
    all_pids=set();qualified=True;phase_count=0
    for phase in r['phases']:
        selected=[row for row in rows if row['label']==phase['name']]
        shop=[row for row in selected if row['role']=='legit-shop']
        uploads=[row for row in selected if row['role']=='legit-upload']
        downloads=[row for row in selected if row['role']=='legit-download']
        heavy=[row for row in selected if row['role']=='abuse']
        flows=[f for f in r['uploads'] if f['phase']==phase['name']];seconds=phase['seconds']
        assert len(selected)==phase['requests'] and len(shop)==phase['storefront_requests']==seconds
        assert len(uploads)==len(flows)==phase['upload_workflows']==seconds//20
        assert {row['sequence'] for row in shop}=={'shop-'+str(i) for i in range(seconds)}
        assert len(heavy)==phase['abuse_requests'] and {row['app'] for row in heavy}==set(phase['targets'])
        if heavy:
            body=json.dumps({'payload':'a'*((900<<10)-16)+'é'},ensure_ascii=False,separators=(',',':')).encode()
            assert len(body)==900<<10
            assert all(row['lane']=='attacker' and row['request_bytes']==len(body) and row['request_sha256']==sha(body) for row in heavy)
            for app in phase['targets']:
                for worker in range(4):
                    prefix=app+'-burn-'+str(worker)+'-'
                    indices=[int(row['sequence'][len(prefix):]) for row in heavy if row['sequence'].startswith(prefix)]
                    assert indices and sorted(indices)==list(range(len(indices))) and len(indices)<=seconds+1
        assert phase['before']['summary']['requests']+len(selected)==phase['after']['summary']['requests']
        assert Counter(str(row['status']) for row in selected)==phase['statuses']
        assert Counter(str(row['status']) for row in heavy)==phase['abuse_statuses']
        assert phase['integrity_passed'] and not phase['errors']
        for app in phase['policy']['applications']:
            limits=app['traffic_controls'];expected=r['limits']
            assert app['policy']['request_limit']==expected['request_limit']==1048576
            assert limits['max_concurrent']==expected['application_slots']
            assert limits['max_client_concurrent']==expected['client_slots']
            assert limits['client_requests_per_second']==expected['client_rate']
            assert limits['client_burst']==expected.get('client_burst',expected['client_rate'])
            assert limits.get('max_client_buffer_mib',0)==expected.get('client_buffer_mib',0)
            assert limits.get('admission_wait_ms',0)==r.get('admission_wait_ms',0)
            original=next(a for a in r['original_policy']['applications'] if a['application_id']==app['application_id'])
            assert app['policy']==original['policy'] # No exclusions, reduced bodies or engine changes.
        for flow in flows:
            index=flow['sequence'];up=next(row for row in uploads if row['sequence']=='upload-'+str(index))
            assert up['lane']=='upload' and up['status']==flow['upload_status'] and up['request_bytes']>900000
            file=next(f for f in files if f['name']==flow['name'])
            assert file['bytes']==700<<10 and file['committed']==(up['status']==200)
            assert file['sha256']==sha(content)
            body=json.dumps(dict(filename=file['name'],modulepart='invoice',ref=file['ref'],filecontent=base64.b64encode(content).decode(),fileencoding='base64',overwriteifexists=0),separators=(',',':')).encode()
            assert up['request_sha256']==sha(body) and up['request_bytes']==len(body)
            if up['status']==200:
                down=next(row for row in downloads if row['sequence']=='download-'+str(index))
                assert down['lane']=='upload' and down['status']==flow['download_status']
                assert flow['passed']==(down['status']==200)
                assert flow['scheduled_ms']+1e-6>=up['service_ms']+down['service_ms']
            else:assert not flow['passed'] and not any(row['sequence']=='download-'+str(index) for row in downloads)
        assert phase['storefront_p95_ms']==percentile([row['scheduled_ms'] for row in shop])
        assert phase['upload_workflow_p95_ms']==percentile([f['scheduled_ms'] for f in flows])
        late=sum(row['start_delay_ms']>100 for row in shop+uploads)
        assert late==phase['legitimate_late_over_100ms']
        accepted=all(row['status']==200 for row in shop) and all(f['passed'] for f in flows) and phase['storefront_p95_ms']<=2000 and phase['upload_workflow_p95_ms']<=10000 and late<=(seconds+seconds//20)*.01
        assert accepted==phase['responsiveness_passed']
        if phase['required']:assert accepted
        qualified=qualified and accepted
        begin,end=phase['guest_begin']['monotonic'],phase['guest_workload_end']['monotonic']
        samples=[s for s in native if begin<=s['monotonic']<=end]
        assert len(samples)>=20 and samples[0]['monotonic']-begin<4 and end-samples[-1]['monotonic']<4
        assert all(s.get('cpus',1)==vcpus for s in samples)
        assert all(b['monotonic']-a['monotonic']<4 for a,b in zip(samples,samples[1:]))
        span=samples[-1]['monotonic']-samples[0]['monotonic'];facts=phase['resources'];cpu=0
        assert facts['samples']==len(samples) and facts['sampled_seconds']==span
        assert len(samples[0]['containers'])==8
        assert {name for name in samples[0]['containers'] if name.startswith('source-relay-')}=={'source-relay-'+name for name in peers}
        for kind in ['processes','containers']:
            for name in samples[0][kind]:
                values=[s[kind][name] for s in samples];assert all(not v.get('unavailable') for v in values)
                assert all(b['cpu_seconds']>=a['cpu_seconds'] for a,b in zip(values,values[1:]))
                value=100*(values[-1]['cpu_seconds']-values[0]['cpu_seconds'])/span;cpu+=value
                assert abs(value-facts[kind][name]['cpu_percent'])<1e-6
                if kind=='processes':
                    assert len({v['pid'] for v in values})==1 and facts[kind][name]['pid']==values[0]['pid']
                    assert facts[kind][name]['peak_rss_kib']==max(v['rss_kib'] for v in values)
                    if name=='gateway':all_pids.add(values[0]['pid'])
                else:
                    assert all(v['oom_kill']==0 for v in values) and facts[kind][name]['peak_memory_bytes']==max(v['memory_bytes'] for v in values)
        first,last=samples[0]['host_cpu_ticks'],samples[-1]['host_cpu_ticks']
        busy=100*(1-((last[3]+last[4])-(first[3]+first[4]))/(sum(last[:8])-sum(first[:8])))
        assert abs(cpu/vcpus-facts['component_cpu_percent'])<1e-6 and abs(busy-facts['guest_busy_percent'])<1e-6
        assert abs(max(cpu/vcpus,busy)-facts['observed_cpu_percent'])<1e-6
        assert facts['min_available_kib']==min(s['host_available_kib'] for s in samples)
        phase_count+=len(selected)
    assert len(all_pids)==1 and len(rows)==phase_count+4
    if 'responsiveness_passed' in r:
        assert r['responsiveness_passed']==qualified and r['measurement_integrity_passed']
    assert len({f['name'] for f in files})==len(files)==len(r['uploads'])
    probe=r['files_verified'];assert probe['passed'] and probe['files']==sum(f['committed'] for f in files)
    assert probe['bytes']==sum(f['bytes'] for f in files if f['committed']) and probe['refused_files_absent']==sum(not f['committed'] for f in files)
    assert r['spool_after']['files']==r['spool_after']['bytes']==0
    status=r['final_status'];storage=status['storage'];identity=status['client_identity']
    assert identity['trusted_networks']==[] and identity['forwarded_requests']==0
    assert status['summary']['requests']==len(rows) and status['summary']['event_persistence_errors']==0
    assert status['resources']['active']==status['resources']['reserved_buffer_bytes']==0
    if r.get('admission_wait_ms',0):
        q=status['resources'];assert q['pending_admissions']==0 and q['max_pending_admissions']==8
        assert q['max_pending_per_application']==4 and q['max_pending_per_client']==1
        assert q['admission_wait_entered']==sum(q[k] for k in ['admission_wait_admitted','admission_wait_expired','admission_wait_cancelled','admission_wait_policy_changed','admission_wait_rate_refused'])
    assert storage['healthy'] and storage['export']['healthy'] and storage['export']['pending_records']==0
    assert all(storage[k]==0 for k in ['pending_writes','queue_dropped','write_failed','ingest_timeouts'])
    assert sha((out/'databases.tar').read_bytes())==r['capture']['sha256']
    with tarfile.open(out/'databases.tar') as tar:
        assert len(tar.getmembers())==2 and {m.name for m in tar}=={'events.db','collector.db'}
        dbs={}
        for member in tar:
            assert member.isfile() and member.size<=128<<20
            db=sqlite3.connect(':memory:');db.deserialize(tar.extractfile(member).read());assert db.execute('PRAGMA integrity_check').fetchone()[0]=='ok';dbs[member.name]=db
    sender,receiver=dbs['events.db'],dbs['collector.db'];local=dict(sender.execute('SELECT id,data FROM events'));remote=dict(receiver.execute('SELECT id,data FROM collected_events'));assert local==remote
    events=[json.loads(data) for data in local.values()];actual=Counter();wildcards=Counter();totals=Counter()
    for event in events:
        # The event schema emits peer_ip only for forwarded identities. With
        # no trusted proxies the resolved ip itself is the TCP peer address.
        assert event['ip'] in peers.values() or (event['ip']=='*' and event.get('aggregated') and event.get('occurrences',1)>1)
        if 'peer_ip' in event:assert event['ip']==event['peer_ip']
        count=max(1,event.get('occurrences',1));totals[(event['application_id'],event['status'])]+=count
        if event['ip']=='*':wildcards[(event['application_id'],event['status'])]+=count
        else:actual[(event['application_id'],event['ip'],event['status'])]+=count
    expected=Counter((row['app'],row['peer'],row['status']) for row in rows if row['status'] in [403,429,503])
    assert totals==Counter((row['app'],row['status']) for row in rows if row['status'] in [403,429,503])
    assert all(count<=expected[key] for key,count in actual.items())
    residual=Counter()
    for (app,peer,status),count in expected.items():residual[(app,status)]+=count-actual[(app,peer,status)]
    assert +residual==+wildcards
    assert {e['ip'] for e in events if e['status']==403}=={'127.0.0.10','127.0.0.11'}
    occurrences=sum(totals.values())
    assert receiver.execute('SELECT records,occurrences FROM collector_totals').fetchone()==(len(events),occurrences)
    assert sender.execute('SELECT count(*) FROM export_outbox').fetchone()[0]==0
    assert storage['stored']==storage['export']['acked_records']==len(events)
    assert storage['committed_occurrences']==storage['export']['acked_occurrences']==occurrences
    for db in dbs.values():db.close()
    return dict(evidence_verified=True,responsiveness_passed=qualified,
                sustained_profile_qualified=qualified and not r['screen_only'] and min(p['seconds'] for p in r['phases'][1:])>=300,
                requests=len(rows),files=probe['files'],bytes=probe['bytes'],records=len(events),occurrences=occurrences,
                mixed_source_occurrences=sum(wildcards.values()),
                checker_sha256=sha(Path(__file__).read_bytes()),business_pilot_started=False,
                scope='one real attacker address per targeted application; source identity cannot be replaced by untrusted XFF')


if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('report',type=Path);p.add_argument('--package',type=Path,required=True);a=p.parse_args()
    result=check(a.report,a.package);(a.report.parent/'verification.json').write_text(json.dumps(result,indent=2)+'\n');print(json.dumps(result))
