"""Verify the adverse multi-address admission boundary; never call it a guarantee."""
import argparse
from collections import Counter
import hashlib
import json
from pathlib import Path
import sqlite3
import tarfile


def sha(data):return hashlib.sha256(data).hexdigest()


def p95(values):
    values=sorted(values);return round(values[int((len(values)-1)*.95)],3) if values else None


def check(report,package):
    if not __debug__:raise RuntimeError('verification requires assertions')
    out=report.parent;r=json.loads(report.read_text());rows=json.loads((out/'requests.json').read_text());files=json.loads((out/'files.json').read_text())
    assert r['passed'] and r['screen_only'] and r['source_boundary'] and r['abuse_body_bytes']==32768
    assert r['cleanup']['restored'] and r['lanes_cleanup']['stopped'] and r['vm_powered_off']
    assert sha(package.read_bytes())==r['package_sha256']==Path(str(package)+'.sha256').read_text().split()[0]
    with tarfile.open(package) as tar:assert sha(tar.extractfile('usr/lib/openwaf/waf-server').read())==r['server_sha256']
    for name,digest in r['sources'].items():assert sha((out/'source'/name).read_bytes())==digest
    assert r['customers_before']==r['customers_after'] and r['store_before']==r['store_after']
    for prior in r.get('prior_run_rechecks',[]):
        name=prior['artifact'];assert name.startswith('m4-business-abuse-') and len(name)==len('m4-business-abuse-')+8 and all(c in '0123456789abcdef' for c in name[-8:])
        old_dir=out.parent/name;old_path=old_dir/'result.json';manifest=old_dir/'files.json'
        assert sha(old_path.read_bytes())==prior['result_sha256'] and sha(manifest.read_bytes())==prior['files_manifest_sha256']
        old=json.loads(old_path.read_text());old_files=json.loads(manifest.read_text());probe=prior['file_probe']
        assert not old['passed'] and prior['protected_state_unchanged'] and probe['passed']
        assert old['customers_before']==r['customers_before'] and old['store_before']==r['store_before']
        assert probe['files']==sum(f['committed'] for f in old_files)
        assert probe['bytes']==sum(f['bytes'] for f in old_files if f['committed'])
        assert probe['refused_files_absent']==sum(not f['committed'] for f in old_files)
    content=(out/'upload-content.bin').read_bytes()
    assert len(content)==700<<10 and sha(content)==r['upload_fixture_sha256']
    slots=r['limits']['application_slots'];client_slots=r['limits']['client_slots']
    assert client_slots<slots<=2*client_slots and client_slots in [1,2,3]
    assert r['original_policy']['applications']==r['restored_policy']['applications']
    assert all(row['valid'] and 'error' not in row for row in rows)
    peers={'upload':'127.0.0.2','storefront':'127.0.0.3','attacker':'127.0.0.10','second-attacker':'127.0.0.11'}
    assert all(row['peer']==peers[row['lane']] for row in rows)
    assert [phase['name'] for phase in r['phases']]==['baseline','multi-source']
    count=0
    for phase in r['phases']:
        selected=[row for row in rows if row['label']==phase['name']];count+=len(selected)
        shop=[row for row in selected if row['role']=='legit-shop'];up=[row for row in selected if row['role']=='legit-upload']
        heavy=[row for row in selected if row['role']=='abuse'];flows=[f for f in r['uploads'] if f['phase']==phase['name']]
        assert len(selected)==phase['requests'] and len(shop)==phase['seconds'] and len(up)==len(flows)==phase['seconds']//20
        assert phase['after']['summary']['requests']-phase['before']['summary']['requests']==len(selected)
        assert Counter(str(row['status']) for row in selected)==phase['statuses']
        assert {row['sequence'] for row in shop}=={'shop-'+str(i) for i in range(phase['seconds'])}
        assert phase['storefront_p95_ms']==p95([row['scheduled_ms'] for row in shop])
        assert phase['upload_workflow_p95_ms']==p95([flow['scheduled_ms'] for flow in flows])
        if phase['name']=='multi-source':
            body=json.dumps({'payload':'a'*((32<<10)-16)+'é'},ensure_ascii=False,separators=(',',':')).encode()
            assert {row['peer'] for row in heavy}=={'127.0.0.10','127.0.0.11'}
            assert all(row['request_bytes']==32768 and row['request_sha256']==sha(body) for row in heavy)
        else:assert not heavy and phase['responsiveness_passed']
        for app in phase['policy']['applications']:
            assert app['policy']['request_limit']==1048576
            original=next(a for a in r['original_policy']['applications'] if a['application_id']==app['application_id'])
            assert app['policy']==original['policy'] and not app['policy']['inspect_response']
            assert app['traffic_controls']['max_concurrent']==slots and app['traffic_controls']['max_client_concurrent']==client_slots
            assert app['traffic_controls']['client_requests_per_second']==2
            assert app['traffic_controls']['client_burst']==r['limits']['client_burst']
            assert app['traffic_controls'].get('max_client_buffer_mib',0)==r['limits']['client_buffer_mib']
            assert app['traffic_controls'].get('admission_wait_ms',0)==r['admission_wait_ms']
        assert phase['integrity_passed'] and not phase['errors']
    assert count+4+2*slots==len(rows) # two preflights, two legitimate refusals and all held requests
    held=r['held_boundary'];assert not held['admission_guarantee'] and held['occupied_resources']['active']==2*slots
    assert held['body_bytes']==32768
    assert held['occupied_resources']['reserved_buffer_bytes']==2*slots*4*(32768+1)
    assert held['legitimate_upload_status']==held['legitimate_storefront_status']==503
    assert held['recovered_resources']['active']==held['recovered_resources']['reserved_buffer_bytes']==0
    requests=[row for row in rows if row['label']=='held-boundary']
    bad=[row for row in requests if row['role']=='held-abuse'];good=[row for row in requests if row['role']=='held-legitimate']
    expected_held=Counter({(app,peer):n for app in ['dolibarr','prestashop'] for peer,n in [('127.0.0.10',client_slots),('127.0.0.11',slots-client_slots)]})
    assert len(bad)==2*slots and Counter((row['app'],row['peer']) for row in bad)==expected_held
    assert all(row.get('request_id') for row in bad) and len({row['request_id'] for row in bad})==len(bad)
    assert len(good)==2 and all(row['status']==503 for row in good)
    assert {row['app'] for row in good}=={'dolibarr','prestashop'}
    assert all(row['status']==(400 if row['app']=='dolibarr' else 200) for row in bad)
    assert all(row['request_bytes']==32768 for row in bad)
    assert all(f['bytes']==len(content) and f['sha256']==sha(content) for f in files if f['name']!=held['refused_file'])
    refused=next(f for f in files if f['name']==held['refused_file']);assert not refused['committed'] and refused['bytes']==700<<10
    probe=r['files_verified'];assert probe['passed'] and probe['files']==sum(f['committed'] for f in files)
    assert probe['bytes']==sum(f['bytes'] for f in files if f['committed']) and probe['refused_files_absent']==sum(not f['committed'] for f in files)
    assert r['spool_after']['files']==r['spool_after']['bytes']==0
    native_file=out/'resources.jsonl';assert sha(native_file.read_bytes())==r['capture']['resources_sha256']
    native=[json.loads(line) for line in native_file.read_text().splitlines()];pids=set()
    assert r.get('sampler_version',1)==native[0].get('sampler_version',1)
    if r.get('sampler_version',1)==2:
        for name in ['gateway','collector']:
            assert len({(s['processes'][name]['pid'],s['processes'][name]['start_ticks']) for s in native})==1
        previous=None
        for sample in native:
            process=sample['processes']['gateway'];proof=process['executable'];key=proof['signature']
            assert sample['sampler_version']==2 and key[0]==process['pid'] and key[1]==process['start_ticks']
            assert proof['sha256']==r['server_sha256']
            if key!=previous:assert proof['recomputed']
            previous=key
    for phase in r['phases']:
        samples=[s for s in native if phase['guest_begin']['monotonic']<=s['monotonic']<=phase['guest_workload_end']['monotonic']]
        assert len(samples)>20 and all(b['monotonic']-a['monotonic']<4 for a,b in zip(samples,samples[1:]))
        for sample in samples:
            assert sample.get('cpus',1)==r.get('vcpus',1)
            assert len(sample['containers'])==8 and all(not v.get('unavailable') and v['oom_kill']==0 for v in sample['containers'].values())
            assert all(not v.get('unavailable') for v in sample['processes'].values());pids.add(sample['processes']['gateway']['pid'])
    assert len(pids)==1
    status=r['final_status'];storage=status['storage']
    assert status['summary']['requests']==len(rows) and status['summary']['event_persistence_errors']==0
    assert status['client_identity']['trusted_networks']==[] and status['client_identity']['forwarded_requests']==0
    assert status['resources']['active']==status['resources']['reserved_buffer_bytes']==0
    q=status['resources'];assert q['pending_admissions']==0
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
    events=[json.loads(data) for data in local.values()];observed=Counter();exact=Counter();wild=Counter()
    expected=Counter((row['app'],row['peer'],row['status']) for row in rows if row['status'] in [429,503])
    totals=Counter()
    for (app,peer,status),n in expected.items():totals[(app,status)]+=n
    for event in events:
        app,peer,status=event['application_id'],event['ip'],event['status'];n=max(1,event.get('occurrences',1))
        observed[(app,status)]+=n
        if peer=='*':
            assert event.get('aggregated') and n>1
            wild[(app,status)]+=n
        else:exact[(app,peer,status)]+=n
    assert observed==totals
    assert all(n<=expected[key] for key,n in exact.items())
    residual=Counter()
    for (app,peer,status),n in expected.items():residual[(app,status)]+=n-exact[(app,peer,status)]
    assert +residual==+wild
    for app,peer in [('dolibarr','127.0.0.2'),('prestashop','127.0.0.3')]:
        assert any(e['application_id']==app and e['ip'] in [peer,'*'] and e['status']==503 and not e['upstream_attempted'] for e in events)
    occurrences=sum(observed.values());assert receiver.execute('SELECT records,occurrences FROM collector_totals').fetchone()==(len(events),occurrences)
    assert sender.execute('SELECT count(*) FROM export_outbox').fetchone()[0]==0
    assert storage['stored']==storage['export']['acked_records']==len(events)
    assert storage['committed_occurrences']==storage['export']['acked_occurrences']==occurrences
    for db in dbs.values():db.close()
    result=dict(evidence_verified=True,universal_admission_guarantee=False,held_legitimate_requests_refused=2,
                small_probe_responsiveness=r['responsiveness_passed'],requests=len(rows),records=len(events),occurrences=occurrences,
                files=probe['files'],refused_uploads=probe['refused_files_absent'],checker_sha256=sha(Path(__file__).read_bytes()))
    return result


if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('report',type=Path);p.add_argument('--package',type=Path,required=True);a=p.parse_args()
    result=check(a.report,a.package)
    (a.report.parent/'boundary-verification.json').write_text(json.dumps(result,indent=2)+'\n');print(json.dumps(result))
