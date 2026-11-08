"""Recompute browser/NAT outcomes from retained requests, files and durable receipts."""
import argparse
import base64
from collections import Counter
import hashlib
import json
from pathlib import Path
import sqlite3
import tarfile

from joint_business_lab import resources


def sha(data):
    return hashlib.sha256(data).hexdigest()


def p95(values):
    values = sorted(values)
    return round(values[int((len(values)-1)*.95)],3) if values else None


def verify_files(files, probe):
    ambiguous = {item['name']:item for item in probe.get('ambiguous_files',[])}
    assert len(ambiguous) == len(probe.get('ambiguous_files',[]))
    assert set(ambiguous) == {f['name'] for f in files if f.get('commit_unknown')}
    committed = []
    for flow in files:
        actual = ambiguous.get(flow['name'])
        is_committed = flow['committed']
        if actual is not None:
            assert actual['bytes'] == (flow['bytes'] if actual['committed'] else 0)
            assert actual['sha256'] == (flow['sha256'] if actual['committed'] else None)
            is_committed = actual['committed']
        if is_committed:
            committed.append(flow)
    assert probe['passed'] and probe['files'] == len(committed)
    assert probe['bytes'] == sum(flow['bytes'] for flow in committed)
    assert probe['refused_files_absent'] == len(files)-len(committed)
    return committed


def check(path, package):
    if not __debug__:
        raise RuntimeError('verification requires assertions')
    out = path.parent
    assert not (out/'measurement-invalid.json').exists(), 'measurement invalidated; retain as diagnostic evidence'
    report = json.loads(path.read_text())
    assert not report.get('shutdown_forced',False), 'forced lab shutdown requires diagnostic review'
    endurance = report.get('abuse_endurance',False)
    rows = json.loads((out/'requests.json').read_text())
    files = json.loads((out/'files.json').read_text())
    assert (report.get('completed',False) if endurance else report['passed'])
    if 'baseline_qualified' in report:
        baseline = report['phases'][0]
        assert baseline['name'] == 'nat-baseline'
        assert report['baseline_qualified'] == all(baseline[key] for key in [
            'browser_passed','integrity_passed','responsiveness_passed',
            'coverage_passed','resource_budget_passed'])
    assert report['cleanup']['restored'] and report['lanes_cleanup']['stopped']
    assert report['vm_powered_off'] and report['original_cpu_restored']
    assert report['screen_only'] and not report['business_pilot_started']
    assert report['vcpus'] == report['guest_logical_cpus'] == 4
    assert sha(package.read_bytes()) == report['package_sha256'] == Path(str(package)+'.sha256').read_text().split()[0]
    with tarfile.open(package) as archive:
        assert sha(archive.extractfile('usr/lib/openwaf/waf-server').read()) == report['server_sha256']
    for name, digest in report['sources'].items():
        assert sha((out/'source'/name).read_bytes()) == digest
    assert sha((out/'source/browser-nat.cjs').read_bytes()) == report['browser_source_sha256']
    if 'linux_qualification_sha256' in report:
        qualification = package.parent/'linux-native/result.json'
        assert sha(qualification.read_bytes()) == report['linux_qualification_sha256']
        qualified = json.loads(qualification.read_text())
        assert qualified['passed'] and qualified['package_sha256'] == report['package_sha256']
    assert report['original_policy']['applications'] == report['restored_policy']['applications']
    assert report['customers_before'] == report['customers_after']
    for name in ['orders','order_detail']:
        assert report['store_before'][name] == report['store_after'][name]
    assert report['spool_before']['files'] == report['spool_after']['files'] == report['spool_after']['bytes'] == 0
    peers = {'upload':'127.0.0.2','storefront':'127.0.0.3','attacker':'127.0.0.10','second-attacker':'127.0.0.11'}
    assert {name:lane['peer'] for name,lane in report['lanes'].items()} == peers
    assert all(row['peer'] == peers[row['lane']] and 'error' not in row for row in rows)
    raw = (out/'resources.jsonl').read_bytes()
    assert sha(raw) == report['capture']['resources_sha256']
    native = [json.loads(line) for line in raw.splitlines()]
    if 'gateway_cpu_control' in report:
        control = report['gateway_cpu_control']
        assert control['quota_percent'] in [0,200]
        assert control['cpu_max'] == ('200000 100000' if control['quota_percent'] else 'max 100000')
        assert all(sample['gateway_cpu_control']['cpu_max']==control['cpu_max'] for sample in native)
        for first,last in zip(native,native[1:]):
            for key in ['usage_usec','nr_throttled','throttled_usec']:
                assert last['gateway_cpu_control'][key] >= first['gateway_cpu_control'][key]
    for sample in native:
        process = sample['processes']['gateway']
        assert process['executable']['sha256'] == report['server_sha256']
        assert process['executable']['signature'][:2] == [process['pid'],process['start_ticks']]
    assert len({(s['processes']['gateway']['pid'],s['processes']['gateway']['start_ticks']) for s in native}) == 1
    names = ['nat-baseline','nat-erp-abuse','nat-shop-abuse','nat-both-abuse','nat-shared-abuse'] if endurance else ['reference','strict-separate','strict-shared','nat-candidate']
    assert [p['name'] for p in report['phases']] == names
    if endurance:
        assert report['budgets'] == dict(navigation_p95_ms=5000,wave_p95_ms=20000,file_p95_ms=10000,cpu_percent=80)
    accepted = []
    file_flows = []
    phase_requests = 0
    sessions = 0
    cache_hits = 0
    for phase in report['phases']:
        selected = [row for row in rows if row['label'] == phase['name']]
        assert len(selected) == phase['requests']
        assert Counter(str(row['status']) for row in selected) == phase['statuses']
        assert phase['after']['summary']['requests']-phase['before']['summary']['requests'] == len(selected)
        phase_requests += len(selected)
        assert phase['proxy_errors'] == 0
        measured = None
        try:
            measured = resources(raw.decode(),phase['guest_begin'],phase['guest_end'],4)
        except AssertionError:
            assert endurance
        assert phase['resources'] == measured
        observation = phase['seconds'] if endurance else 30
        assert phase['minimum_observation_seconds'] == observation and phase['elapsed_seconds'] >= observation
        browser_path = out/phase['browser_result']
        assert sha(browser_path.read_bytes()) == phase['browser_result_sha256']
        browser = json.loads(browser_path.read_text())
        assert browser['profile'] == phase['name'] and browser['browser_version']
        assert len(browser['waves']) == phase['waves']
        schedule_version = browser.get('schedule_version',1)
        assert schedule_version in [1,2]
        if schedule_version == 2:
            assert browser['interval_ms'] == 15000
            previous_end = 0
            for index,wave in enumerate(browser['waves']):
                assert wave['wave'] == index
                assert wave['scheduled_start_ms'] == index*browser['interval_ms']
                assert wave['started_ms'] >= previous_end
                assert wave['started_ms'] >= wave['scheduled_start_ms']
                assert wave['start_delay_ms'] == max(0,wave['started_ms']-wave['scheduled_start_ms'])
                previous_end = wave['started_ms']+wave['elapsed_ms']
            assert previous_end <= browser['work_elapsed_ms'] <= phase['browser_active_seconds']*1000
        flows = browser['initial_uploads'][:]
        expected_users = {'lab-admin','lab-reader','customer@example.invalid'}
        browser_sessions = []
        for wave in browser['waves']:
            users = wave['sessions']
            assert len(users) == 4 and len({s['user'] for s in users}) == 4
            assert expected_users < {s['user'] for s in users}
            assert {s['app'] for s in users} == {'dolibarr','prestashop'}
            for session in users:
                assert session['wave'] == wave['wave']
                flows.extend(session['uploads'])
                if session['passed']:
                    assert session['cookie_fingerprints']
                    if session['app'] == 'prestashop':
                        assert session['authenticated_email'] == session['user']
                    else:
                        assert session['authenticated_id'] > 0
                browser_sessions.append(session)
                cache_hits += session['cache_hits']
        sessions += len(browser_sessions)
        passed = all(s['passed'] for s in browser_sessions) and all(r['status'] < 400 for r in browser['responses']) and not browser['failures'] and all(f['exact'] for f in browser['initial_uploads'])
        assert browser['passed'] == phase['browser_passed'] == passed
        if phase['name'] == 'reference':
            assert passed
        if passed:
            assert all(row['valid'] and 200 <= row['status'] < 400 for row in selected if row['role']=='browser')
            assert all(session['cache_hits'] > 0 for session in browser_sessions)
            accepted.append(phase['name'])
        if phase['shared_nat']:
            assert {row['peer'] for row in selected if row['role']=='browser'} == {'127.0.0.2'}
        else:
            assert {row['peer'] for row in selected} == set(peers.values())
        for app in phase['policy']['applications']:
            original = next(a for a in report['original_policy']['applications'] if a['application_id']==app['application_id'])
            assert app['policy'] == original['policy']
            controls = app['traffic_controls']
            buffer_mib = report.get('nat_limits',{}).get('max_client_buffer_mib',12)
            assert buffer_mib in [12,24]
            expected = (32,0,30,96,buffer_mib) if endurance else {'reference':(32,0,0,0,0),'strict-separate':(4,3,2,4,5),
                        'strict-shared':(4,3,2,4,5),'nat-candidate':(32,0,30,96,12)}[phase['name']]
            assert tuple(controls.get(key,0) for key in ['max_concurrent','max_client_concurrent','client_requests_per_second','client_burst','max_client_buffer_mib']) == expected
            assert controls['admission_wait_ms'] == 1000
            if endurance:
                body_rate = report.get('nat_limits',{}).get('client_body_kib_per_second',0)
                body_burst = report.get('nat_limits',{}).get('client_body_burst_kib',0)
                assert (body_rate,body_burst) in [(0,0),(160,2048),(160,3072),(160,4096)]
                assert controls.get('client_body_kib_per_second',0) == body_rate
                assert controls.get('client_body_burst_kib',0) == body_burst
        if endurance:
            assert phase['shared_nat'] and not phase['sequential'] and phase['waves']*15 == phase['seconds']
            assert 60 <= phase['seconds'] <= 300
            target_map = {'nat-baseline':[],'nat-erp-abuse':['dolibarr'],
                          'nat-shop-abuse':['prestashop'],'nat-both-abuse':['dolibarr','prestashop'],
                          'nat-shared-abuse':['dolibarr','prestashop']}
            assert phase['targets'] == target_map[phase['name']]
            heavy = [row for row in selected if row['role']=='abuse']
            assert {row['app'] for row in heavy} == set(phase['targets'])
            assert phase['abuse_requests'] == len(heavy)
            assert phase['browser_requests'] == len(selected)-len(heavy)
            assert phase['workers_per_target'] == 4
            lane = 'upload' if phase['name']=='nat-shared-abuse' else 'attacker'
            assert phase['attack_lane'] == lane
            assert all(row['lane']==lane and row['peer']==peers[lane] for row in heavy)
            body = json.dumps({'payload':'a'*((900<<10)-16)+'é'},ensure_ascii=False,separators=(',',':')).encode()
            assert len(body) == phase['abuse_body_bytes'] == 900 << 10
            assert sha(body) == phase['abuse_body_sha256']
            assert all(row['request_bytes']==len(body) and row['request_sha256']==sha(body) for row in heavy)
            assert Counter(str(row['status']) for row in heavy) == phase['abuse_statuses']
            for app in phase['targets']:
                for worker in range(4):
                    prefix = app+'-burn-'+str(worker)+'-'
                    indices = [int(row['sequence'][len(prefix):]) for row in heavy if row['sequence'].startswith(prefix)]
                    assert indices and sorted(indices)==list(range(len(indices))) and len(indices)<=phase['seconds']+1
            latency = dict(navigation_p95_ms=p95([n['elapsed_ms'] for s in browser_sessions for n in s['navigations']]),
                           wave_p95_ms=p95([w['elapsed_ms'] for w in browser['waves']]),
                           file_p95_ms=p95([flow['elapsed_ms'] for flow in flows]))
            assert latency == phase['latency']
            responsive = (passed and latency['navigation_p95_ms'] <= 5000 and
                          latency['wave_p95_ms'] <= 20000 and latency['file_p95_ms'] <= 10000 and
                          all(w['elapsed_ms'] <= 20000 for w in browser['waves']) and
                          all(f['elapsed_ms'] <= 10000 for f in flows))
            assert phase['responsiveness_passed'] == responsive
            assert phase['coverage_passed'] == (phase['browser_active_seconds'] <= phase['seconds']+5)
            windows = []
            for offset in range(0,phase['seconds'],60):
                sample = None
                try:
                    sample = resources(raw.decode(),dict(monotonic=phase['guest_begin']['monotonic']+offset),
                        dict(monotonic=phase['guest_begin']['monotonic']+min(phase['seconds'],offset+60)),4)
                except AssertionError:
                    pass
                windows.append(dict(offset_seconds=offset,seconds=min(60,phase['seconds']-offset),resources=sample))
            assert windows == phase['resource_windows']
            resource_valid = measured is not None and all(w['resources'] is not None for w in windows)
            assert phase['resource_evidence_passed'] == resource_valid
            assert phase['resource_budget_passed'] == (resource_valid and measured['observed_cpu_percent'] <= 80 and
                all(w['resources']['observed_cpu_percent'] <= 80 for w in windows))
            assert phase['integrity_passed'] == (not phase['errors'] and all(row['valid'] for row in heavy))
        file_flows.extend(flows)
    assert files == file_flows and len({f['name'] for f in files}) == len(files)
    content = (out/'upload-content.bin').read_bytes()
    assert len(content) == 700 << 10
    upload_rows = [row for row in rows if row.get('path') == '/api/index.php/documents/upload']
    assert len(upload_rows) == len(files)
    for flow in files:
        assert flow['bytes'] == len(content) and flow['sha256'] == sha(content)
        body = json.dumps(dict(filename=flow['name'],modulepart='invoice',ref=flow['ref'],
                              filecontent=base64.b64encode(content).decode(),fileencoding='base64',overwriteifexists=0),separators=(',',':')).encode()
        matching = [row for row in upload_rows if row['request_sha256'] == sha(body)]
        assert len(matching) == 1 and matching[0]['status'] == flow['upload_status']
        assert flow['committed'] == (flow['upload_status'] == 200)
        if flow['exact']:
            assert flow['committed'] and flow['download_status'] == 200
        if flow['committed']:
            assert flow['download_status'] in [200,403,429,503]
    probe = report['files_verified']
    committed = verify_files(files,probe)
    prior_files = []
    for artifact, digest in report['prior_file_manifests'].items():
        manifest = None
        for name in ['files.json','recovered-files.json']:
            candidate = out.parent/artifact/name
            if candidate.is_file() and sha(candidate.read_bytes()) == digest:
                manifest = candidate
                break
        assert manifest is not None and manifest.parent.parent == out.parent
        prior_files.extend(json.loads(manifest.read_text()))
    if prior_files:
        verify_files(prior_files,report['prior_files_verified'])
    status = report['final_status']
    assert len(rows) == phase_requests+1 == status['summary']['requests']
    assert status['summary']['event_persistence_errors'] == 0
    assert status['resources']['active'] == status['resources']['reserved_buffer_bytes'] == status['resources']['pending_admissions'] == 0
    assert status['resources']['max_concurrent'] == 64 and status['resources']['max_connections'] == 128
    storage = status['storage']
    assert storage['healthy'] and storage['export']['healthy']
    assert all(storage[key] == 0 for key in ['pending_writes','queue_dropped','write_failed','ingest_timeouts'])
    assert storage['export']['pending_records'] == 0
    assert sha((out/'databases.tar').read_bytes()) == report['capture']['sha256']
    with tarfile.open(out/'databases.tar') as archive:
        assert {m.name for m in archive} == {'events.db','collector.db'}
        databases = {}
        for member in archive:
            assert member.isfile() and member.size <= 128 << 20
            db = sqlite3.connect(':memory:')
            db.deserialize(archive.extractfile(member).read())
            assert db.execute('PRAGMA integrity_check').fetchone()[0] == 'ok'
            databases[member.name] = db
    sender, receiver = databases['events.db'], databases['collector.db']
    local = dict(sender.execute('SELECT id,data FROM events'))
    assert local == dict(receiver.execute('SELECT id,data FROM collected_events'))
    actual, wildcards, totals = Counter(), Counter(), Counter()
    for data in local.values():
        event = json.loads(data)
        count = max(1,event.get('occurrences',1))
        app, code, peer = event['application_id'], event['status'], event['ip']
        totals[(app,code)] += count
        if peer == '*':
            assert event.get('aggregated') and count > 1
            wildcards[(app,code)] += count
        else:
            assert peer in peers.values() and event.get('peer_ip',peer) == peer
            actual[(app,peer,code)] += count
    expected = Counter((row['app'],row['peer'],row['status']) for row in rows if row['status'] in [403,429,503])
    assert totals == Counter((row['app'],row['status']) for row in rows if row['status'] in [403,429,503])
    residual = Counter()
    assert all(count <= expected[key] for key,count in actual.items())
    for (app,peer,code),count in expected.items():
        residual[(app,code)] += count-actual[(app,peer,code)]
    assert +residual == +wildcards
    occurrences = sum(totals.values())
    assert receiver.execute('SELECT records,occurrences FROM collector_totals').fetchone() == (len(local),occurrences)
    assert sender.execute('SELECT count(*) FROM export_outbox').fetchone()[0] == 0
    assert storage['stored'] == storage['export']['acked_records'] == len(local)
    assert storage['committed_occurrences'] == storage['export']['acked_occurrences'] == occurrences
    for db in databases.values():
        db.close()
    assert report['candidate_browser_passed'] == (len(accepted)==len(names) if endurance else 'nat-candidate' in accepted)
    qualified = False
    external_qualified = False
    if endurance:
        qualified = all(p['browser_passed'] and p['integrity_passed'] and p['responsiveness_passed'] and
                        p['coverage_passed'] and p['resource_budget_passed'] for p in report['phases'])
        assert report['abuse_profile_qualified'] == qualified
        assert report['passed'] == all(p['resource_evidence_passed'] for p in report['phases'])
        external_qualified = all(p['browser_passed'] and p['integrity_passed'] and p['responsiveness_passed'] and
                        p['coverage_passed'] and p['resource_budget_passed'] for p in report['phases'][:4])
        assert report['external_source_profile_qualified'] == external_qualified
    return dict(evidence_verified=True,candidate_browser_passed=report['candidate_browser_passed'],
                accepted_phases=accepted,requests=len(rows),sessions=sessions,cache_hits=cache_hits,
                files=len(committed),bytes=probe['bytes'],records=len(local),occurrences=occurrences,
                checker_sha256=sha(Path(__file__).read_bytes()),business_pilot_started=False,
                abuse_profile_qualified=qualified,
                external_source_profile_qualified=external_qualified,
                endurance_profile_qualified=external_qualified and min(p.get('seconds',0) for p in report['phases'][1:4])>=300,
                scope='synthetic Chromium/API screen on one four-vCPU Linux amd64 lab')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('report',type=Path)
    parser.add_argument('--package',type=Path,required=True)
    args = parser.parse_args()
    result = check(args.report,args.package)
    (args.report.parent/'verification.json').write_text(json.dumps(result,indent=2)+'\n')
    print(json.dumps(result))
