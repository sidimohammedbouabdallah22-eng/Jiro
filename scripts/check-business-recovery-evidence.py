"""Independently check the owned coordinated business recovery capture."""
import argparse
from collections import Counter
import copy
import hashlib
import json
from pathlib import Path
import sqlite3
import tarfile

from m4_business_recovery_guest import APPS, digest, member_path, volume_inventory


def hash_stream(stream):
    value = hashlib.sha256()
    for block in iter(lambda: stream.read(1 << 20), b''):
        value.update(block)
    return value.hexdigest()


def validate_claims(report):
    assert report['passed'] and report['completed'] and report['functional_only']
    assert not report['capacity_qualification'] and not report['business_pilot_started']
    assert report['lab_environment'] == 'wsl2' and report['lab_stopped']
    assert not report.get('lab_shutdown_forced', False)
    assert report['cleanup']['restored'] and report['lanes_cleanup']['stopped']
    assert 'business_cleanup_error' not in report
    cleanup = report['business_cleanup']
    assert cleanup['source_units_restored'] and cleanup['source_containers_running']
    restored = report['restoration']
    assert restored['source_containers_stopped'] and restored['server_sha256'] == report['server_sha256']
    clones = set()
    for app in APPS:
        before, after = report['checkpoint']['applications'][app], restored['applications'][app]
        assert before['source_image'] != before['snapshot_image'] == after['image']
        assert before['data_sha256'] == after['data_sha256']
        assert before['schema_sha256'] == after['schema_sha256']
        expected = [{k:v[k] for k in ['path', 'inventory_sha256', 'entries', 'bytes']} for v in before['volumes']]
        assert after['volumes'] == expected
        assert set(after['containers']) == {'app', 'db'}
        clones.update(after['containers'].values())
    assert len(clones) == 4 and set(cleanup['clones_stopped']) == clones
    assert report['checkpoint']['images_evicted']
    before = report['source_files']
    assert before['passed'] and before['refused_files_absent'] == 0
    assert report['restored_existing_files'] == before
    after = report['restored_all_files']
    assert after['passed'] and after['files'] == before['files'] + 4 and after['refused_files_absent'] == 0
    isolation = report['source_isolation']
    assert isolation['passed'] and isolation['files'] == isolation['refused_files_absent'] == 4
    for key in ['source_status', 'restored_status']:
        status = report[key]
        assert status['resources']['active'] == status['resources']['reserved_buffer_bytes'] == 0
        assert status['resources']['max_concurrent'] == 64 and status['resources']['max_connections'] == 128
        storage = status['storage']
        assert storage['healthy'] and storage['export']['healthy']
        assert all(storage[k] == 0 for k in ['queue_dropped', 'write_failed', 'ingest_timeouts', 'pending_writes'])
        assert storage['export']['pending_records'] == storage['export']['failures'] == 0


def check(path, package):
    out = path.parent
    report = json.loads(path.read_text())
    validate_claims(report)
    assert report['host_disk_free_before_bytes'] >= 15 << 30
    assert digest(package) == report['package_sha256']
    with tarfile.open(package) as archive:
        expected_server = hash_stream(archive.extractfile('usr/lib/openwaf/waf-server'))
        expected_collector = hash_stream(archive.extractfile('usr/lib/openwaf/event-collector'))
    assert expected_server == report['server_sha256']
    for name, expected in report['sources'].items():
        assert digest(out / 'source' / name) == expected
    assert digest(out / 'source/browser-nat.cjs') == report['browser_source_sha256']
    rows = json.loads((out / 'requests.json').read_text())
    files = []
    for key, label in [('source_browser', 'before-recovery'), ('restored_browser', 'after-recovery')]:
        facts = report[key]
        assert digest(out / facts['result']) == facts['sha256']
        browser = json.loads((out / facts['result']).read_text())
        assert browser['passed'] and browser['profile'] == label and len(browser['waves']) == 1
        assert len(browser['waves'][0]['sessions']) == 4 and not browser['failures']
        for session in browser['waves'][0]['sessions']:
            assert session['passed'] and session['cache_hits'] > 0 and session['cookie_fingerprints']
            if session['app'] == 'prestashop':
                assert session['authenticated_email'] == session['user']
            else:
                assert session['app'] == 'dolibarr' and session['authenticated_id'] > 0
        actual_files = browser['initial_uploads'][:]
        for session in browser['waves'][0]['sessions']:
            actual_files.extend(session['uploads'])
        assert actual_files == facts['files'] and len(actual_files) == 4
        assert all(f['committed'] and f['exact'] and f['bytes'] == 716800 for f in actual_files)
        selected = [r for r in rows if r['label'] == label]
        assert len(selected) == facts['requests'] and all(r['valid'] and 200 <= r['status'] < 400 for r in selected)
        files.extend(actual_files)
    assert files == json.loads((out / 'files.json').read_text())
    attacks = [r for r in rows if r['label'].endswith('-attack')]
    assert Counter((r['app'], r['label']) for r in attacks) == Counter(
        (app, phase + '-attack') for app in APPS for phase in ['before-recovery', 'after-recovery'])
    assert all(r['status'] == 403 and r['valid'] for r in attacks)
    bundle = out / 'business-recovery.private.tar'
    assert bundle.stat().st_size == report['recovery_capture']['bytes'] < 8 << 30
    assert digest(bundle) == report['recovery_capture']['sha256']
    with tarfile.open(bundle) as archive:
        members = archive.getmembers()
        assert len(members) < 5000 and len({m.name for m in members}) == len(members)
        assert all((m.isfile() or m.isdir()) and member_path(m.name) == m.name for m in members)

        def read(name, limit=128 << 20):
            member = archive.getmember(name)
            assert member.isfile() and member.size <= limit
            return archive.extractfile(member).read()

        raw_manifest = read('checkpoint/manifest.private.json', 1 << 20)
        assert hashlib.sha256(raw_manifest).hexdigest() == report['checkpoint']['manifest_sha256']
        manifest = json.loads(raw_manifest)
        actual_members = {m.name.removeprefix('checkpoint/') for m in members
                          if m.isfile() and m.name.startswith('checkpoint/')}
        assert actual_members == set(manifest['files']) | {'manifest.private.json'}
        assert json.loads(read('restored/result.json', 1 << 20)) == report['restoration']
        for name, facts in manifest['files'].items():
            member_path(name)
            member = archive.getmember('checkpoint/' + name)
            assert member.isfile() and member.size == facts['bytes']
            assert hash_stream(archive.extractfile(member)) == facts['sha256']
        assert report['checkpoint']['files'] == len(manifest['files'])
        assert report['checkpoint']['bytes'] == sum(f['bytes'] for f in manifest['files'].values())
        for app in APPS:
            before = manifest['apps'][app]
            after = report['restoration']['applications'][app]
            assert report['checkpoint']['applications'][app] == {k:v for k,v in before.items() if k != 'source'}
            assert set(before['source'].values()).isdisjoint(after['containers'].values())
            for kind in ['data', 'schema']:
                original, restored = read('checkpoint/' + app + '.' + kind + '.sql'), read('restored/' + app + '.' + kind + '.sql')
                assert original == restored
                assert hashlib.sha256(restored).hexdigest() == before[kind + '_sha256'] == after[kind + '_sha256']
            for volume in before['volumes']:
                original = volume_inventory(archive.extractfile('checkpoint/' + volume['archive']))
                restored = volume_inventory(archive.extractfile('restored/' + volume['archive'] + '.restored.tar'))
                assert original == restored and original['sha256'] == volume['inventory_sha256']
        waf = json.loads(read('checkpoint/waf/manifest.json', 1 << 20))
        assert waf['scope'] == 'coordinated'
        for member in waf['files']:
            data = read('checkpoint/waf/' + member['path'], 256 << 20)
            assert len(data) == member['size'] and hashlib.sha256(data).hexdigest() == member['sha256']
            if member['role'] in ['policy', 'history', 'accounts']:
                assert read('restored/waf-state/' + member['path'].removeprefix('state/')) == data
            if member['role'] == 'audit':
                assert read('restored/waf-state/policy.json.audit.jsonl').startswith(data)
        policy = read('restored/waf-state/policy.json')
        assert json.loads(policy) == report['checkpoint_policy']
        assert hashlib.sha256(policy).hexdigest() == report['restoration']['policy_sha256']
        assert hashlib.sha256(read('restored/runtime/waf-server')).hexdigest() == expected_server
        assert hashlib.sha256(read('restored/runtime/event-collector')).hexdigest() == expected_collector
        for name, expected in manifest['deployment'].items():
            assert hashlib.sha256(read('restored/deployment/' + name)).hexdigest() == expected
        tag = out.name.rsplit('-', 1)[1]
        root = '/var/lib/owaf-joint-' + tag
        assert report['restoration']['running_executable'] == root + '/recovered-waf/bin/waf-server'
        for kind in ['gateway', 'collector']:
            unit = read('restored/' + kind + '.service').decode()
            assert root + '/recovered-waf/state/' in unit
            assert root + '/recovered-deployment/event-token' in unit
        original_events = None
        for label, directory, expected_count in [('source', 'checkpoint/waf/state/', 2), ('restored', 'restored/waf-state/', 4)]:
            sender, receiver = sqlite3.connect(':memory:'), sqlite3.connect(':memory:')
            try:
                sender.deserialize(read(directory + 'events.db'))
                receiver.deserialize(read(directory + 'collector.db'))
                assert sender.execute('PRAGMA integrity_check').fetchone() == ('ok',)
                assert receiver.execute('PRAGMA integrity_check').fetchone() == ('ok',)
                events = dict(sender.execute('SELECT id,data FROM events'))
                assert len(events) == expected_count and events == dict(receiver.execute('SELECT id,data FROM collected_events'))
                assert sender.execute('SELECT count(*) FROM export_outbox').fetchone() == (0,)
                assert receiver.execute('SELECT records,occurrences FROM collector_totals').fetchone() == (expected_count, expected_count)
                if original_events is None:
                    original_events = events
                else:
                    assert all(events.get(key) == data for key, data in original_events.items())
            finally:
                sender.close()
                receiver.close()
    return dict(evidence_verified=True, browser_sessions=8, new_files=8, requests=len(rows),
                recovered_prior_files=report['restored_existing_files']['files'],
                source_events=2, final_events=4, databases=len(APPS),
                application_volumes=sum(len(app['volumes']) for app in report['checkpoint']['applications'].values()),
                database_volumes=len(APPS),
                scope='replacement containers and WAF directories in the same owned WSL2 lab',
                business_pilot_started=False)


def reject_mutations(report):
    cases = {
        'completion':lambda r:r.__setitem__('completed', False),
        'cleanup':lambda r:r['business_cleanup'].__setitem__('source_units_restored', False),
        'image':lambda r:r['restoration']['applications']['dolibarr'].__setitem__('image', 'sha256:' + '0' * 64),
        'schema':lambda r:r['restoration']['applications']['prestashop'].__setitem__('schema_sha256', '0' * 64),
        'data':lambda r:r['restoration']['applications']['dolibarr'].__setitem__('data_sha256', '0' * 64),
        'volume':lambda r:r['restoration']['applications']['dolibarr']['volumes'][0].__setitem__('inventory_sha256', '0' * 64),
        'file':lambda r:r['restored_all_files'].__setitem__('files', 0),
        'isolation':lambda r:r['source_isolation'].__setitem__('refused_files_absent', 0),
        'delivery':lambda r:r['restored_status']['storage']['export'].__setitem__('pending_records', 1),
        'pilot':lambda r:r.__setitem__('business_pilot_started', True),
    }
    for mutate in cases.values():
        changed = copy.deepcopy(report)
        mutate(changed)
        try:
            validate_claims(changed)
        except AssertionError:
            continue
        raise AssertionError('fabricated recovery claim accepted')
    return len(cases)


if __name__ == '__main__':
    if not __debug__:
        raise RuntimeError('verification requires assertions')
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('report', type=Path)
    parser.add_argument('--package', type=Path, required=True)
    args = parser.parse_args()
    result = check(args.report, args.package)
    result['negative_claims_rejected'] = reject_mutations(json.loads(args.report.read_text()))
    result['checker_sha256'] = digest(Path(__file__))
    (args.report.parent / 'verification.json').write_text(json.dumps(result, indent=2) + '\n')
    print(json.dumps(result))
