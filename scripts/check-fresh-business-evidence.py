"""Verify fresh-host business recovery against checkpoint and captured database bytes."""
import argparse
import copy
import hashlib
import json
from pathlib import Path
import sqlite3
import tarfile

from m4_business_recovery_guest import APPS, digest, member_path, volume_inventory


def claims(report):
    assert report['passed'] and report['completed'] and report['vm_powered_off']
    assert report['functional_only'] and not report['capacity_qualification']
    assert not report['business_pilot_started'] and not report.get('cleanup_error')
    before = report['preconditions']
    assert before['clean_os'] and before['empty_docker']
    assert before['machine_id'] != before['source_machine_id'] == report['donor_off']['machine_id']
    assert report['donor_off']['containers_stopped'] and report['donor_off']['powered_off']
    assert before['checkpoint_sha256'] == report['checkpoint']['manifest_sha256']
    restored = report['activation']['restoration']
    assert restored['source_containers_absent'] and not restored['source_containers_stopped']
    assert restored['server_sha256'] == report['server_sha256']
    containers = set()
    for app in APPS:
        old, new = report['checkpoint']['applications'][app], restored['applications'][app]
        assert old['snapshot_image'] == new['image'] != old['source_image']
        assert old['data_sha256'] == new['data_sha256'] and old['schema_sha256'] == new['schema_sha256']
        assert new['volumes'] == [{key:volume[key] for key in ['path', 'inventory_sha256', 'entries', 'bytes']}
                                  for volume in old['volumes']]
        containers.update(new['containers'].values())
    assert len(containers) == 4 and set(report['cleanup']['containers']) == containers
    assert report['cleanup']['stopped']
    assert report['existing_files']['passed'] and report['existing_files']['files'] > 0
    assert report['all_files']['passed'] and report['all_files']['files'] == report['existing_files']['files'] + 4
    assert report['all_files']['bytes'] == report['existing_files']['bytes'] + 4 * 716800
    assert report['all_files']['refused_files_absent'] == 0
    status = report['status']
    assert status['resources']['active'] == status['resources']['reserved_buffer_bytes'] == 0
    assert status['resources']['max_concurrent'] == 64 and status['resources']['max_connections'] == 128
    storage = status['storage']
    assert storage['healthy'] and storage['export']['healthy']
    assert all(storage[name] == 0 for name in ['queue_dropped', 'write_failed', 'ingest_timeouts', 'pending_writes'])
    assert storage['export']['pending_records'] == storage['export']['failures'] == 0


def hash_stream(stream):
    value = hashlib.sha256()
    for block in iter(lambda: stream.read(1 << 20), b''):
        value.update(block)
    return value.hexdigest()


def database(data):
    connection = sqlite3.connect(':memory:')
    connection.deserialize(data)
    assert connection.execute('PRAGMA integrity_check').fetchone() == ('ok',)
    return connection


def check(path, package):
    report = json.loads(path.read_text())
    out = path.parent
    claims(report)
    donor = Path(report['donor_report'])
    assert digest(donor) == report['donor_report_sha256']
    original = json.loads(donor.read_text())
    assert original['passed'] and original['checkpoint'] == report['checkpoint']
    assert original['recovery_capture']['sha256'] == report['donor_bundle_sha256']
    assert report['existing_files'] == original['source_files']
    prior = Path(__file__).resolve().parents[1] / 'artifacts' / original['prior_manifest']['directory'] / 'files.json'
    assert digest(prior) == original['prior_manifest']['sha256']
    assert digest(package) == report['package_sha256'] == Path(str(package) + '.sha256').read_text().split()[0]
    for name, expected in report['sources'].items():
        assert digest(out / 'source' / name) == expected
    assert digest(out / 'source/browser-nat.cjs') == report['browser_source_sha256']
    preparation = json.loads((out / 'source/target-preparation.json').read_text())
    assert preparation['vm'] == report['vm'] and preparation['prepared'] and not preparation['qualification_performed']
    assert preparation['package_sha256'] == report['package_sha256']
    assert preparation['cpus'] == 1 and preparation['memory_mib'] == 4096 and preparation['disk_gib'] == 32
    vm = Path(__file__).resolve().parents[1] / 'artifacts/m2-vms' / report['vm']
    assert json.loads((vm / 'result.json').read_text()) == preparation
    assert digest(vm / 'provisioner.py') == preparation['provisioner_sha256']
    browser = json.loads((out / report['browser']['result']).read_text())
    assert digest(out / report['browser']['result']) == report['browser']['sha256']
    assert browser['passed'] and not browser['failures'] and len(browser['waves']) == 1
    sessions = browser['waves'][0]['sessions']
    assert len(sessions) == 4
    for session in sessions:
        assert session['passed'] and session['cookie_fingerprints'] and session['cache_hits'] > 0
        assert (session['authenticated_email'] == session['user'] if session['app'] == 'prestashop'
                else session['app'] == 'dolibarr' and session['authenticated_id'] > 0)
    files = browser['initial_uploads'] + [f for session in sessions for f in session['uploads']]
    assert files == report['browser']['files'] == json.loads((out / 'files.json').read_text())
    assert len(files) == 4 and all(f['committed'] and f['exact'] and f['bytes'] == 716800 for f in files)
    requests = json.loads((out / 'requests.json').read_text())
    attacks = [r for r in requests if r['label'] == 'fresh-recovery-attack']
    assert len(attacks) == 2 and {r['app'] for r in attacks} == set(APPS)
    assert all(r['valid'] and r['status'] == 403 for r in attacks)
    ordinary = [r for r in requests if r['label'] == 'fresh-recovery']
    assert len(ordinary) == report['browser']['requests'] and all(r['valid'] and 200 <= r['status'] < 400 for r in ordinary)
    capture = out / 'business-recovery.private.tar'
    assert capture.stat().st_size == report['capture']['bytes'] < 8 << 30
    assert digest(capture) == report['capture']['sha256']
    with tarfile.open(package) as archive:
        server = hash_stream(archive.extractfile('usr/lib/openwaf/waf-server'))
        collector = hash_stream(archive.extractfile('usr/lib/openwaf/event-collector'))
    with tarfile.open(capture) as archive:
        members = archive.getmembers()
        assert len(members) < 5000 and len({m.name for m in members}) == len(members)
        assert all((m.isfile() or m.isdir()) and member_path(m.name) == m.name for m in members)
        def read(name):
            member = archive.getmember(name)
            assert member.isfile() and member.size < 256 << 20
            return archive.extractfile(member).read()
        manifest_bytes = read('checkpoint/manifest.private.json')
        assert hashlib.sha256(manifest_bytes).hexdigest() == report['checkpoint']['manifest_sha256']
        manifest = json.loads(manifest_bytes)
        assert {m.name.removeprefix('checkpoint/') for m in members if m.isfile() and m.name.startswith('checkpoint/')} == set(manifest['files']) | {'manifest.private.json'}
        for name, facts in manifest['files'].items():
            member = archive.getmember('checkpoint/' + name)
            assert member.size == facts['bytes'] and hash_stream(archive.extractfile(member)) == facts['sha256']
        assert json.loads(read('restored/result.json')) == report['activation']['restoration']
        for app in APPS:
            assert report['checkpoint']['applications'][app] == {key:value for key,value in manifest['apps'][app].items() if key != 'source'}
            for kind in ['schema', 'data']:
                assert read('checkpoint/' + app + '.' + kind + '.sql') == read('restored/' + app + '.' + kind + '.sql')
            for volume in manifest['apps'][app]['volumes']:
                inventory = volume_inventory(archive.extractfile('checkpoint/' + volume['archive']))
                assert inventory['sha256'] == volume['inventory_sha256']
                assert inventory == volume_inventory(archive.extractfile('restored/' + volume['archive'] + '.restored.tar'))
        assert hashlib.sha256(read('restored/runtime/waf-server')).hexdigest() == server == report['server_sha256']
        assert hashlib.sha256(read('restored/runtime/event-collector')).hexdigest() == collector
        waf = json.loads(read('checkpoint/waf/manifest.json'))
        for member in waf['files']:
            data = read('checkpoint/waf/' + member['path'])
            assert hashlib.sha256(data).hexdigest() == member['sha256'] and len(data) == member['size']
            if member['role'] in ['policy', 'history', 'accounts']:
                assert read('restored/waf-state/' + member['path'].removeprefix('state/')) == data
            elif member['role'] == 'audit':
                assert read('restored/waf-state/policy.json.audit.jsonl').startswith(data)
        assert json.loads(read('restored/waf-state/policy.json')) == report['checkpoint_policy']
        for name, expected in manifest['deployment'].items():
            assert hashlib.sha256(read('restored/deployment/' + name)).hexdigest() == expected
        original_events = None
        for prefix, count in [('checkpoint/waf/state/', 2), ('restored/waf-state/', 4)]:
            sender, receiver = database(read(prefix + 'events.db')), database(read(prefix + 'collector.db'))
            try:
                events = dict(sender.execute('SELECT id,data FROM events'))
                assert len(events) == count and events == dict(receiver.execute('SELECT id,data FROM collected_events'))
                assert sender.execute('SELECT count(*) FROM export_outbox').fetchone() == (0,)
                assert receiver.execute('SELECT records,occurrences FROM collector_totals').fetchone() == (count, count)
                if original_events is not None:
                    assert all(events.get(key) == value for key, value in original_events.items())
                original_events = events
            finally:
                sender.close()
                receiver.close()
        root = '/var/lib/owaf-joint-' + out.name.rsplit('-', 1)[1]
        assert report['activation']['restoration']['running_executable'] == root + '/recovered-waf/bin/waf-server'
        for kind in ['gateway', 'collector']:
            unit = read('restored/' + kind + '.service').decode()
            assert root + '/recovered-waf/state/' in unit and root + '/recovered-deployment/event-token' in unit
    mutations = [lambda r:r.update(completed=False), lambda r:r.update(vm_powered_off=False),
        lambda r:r['preconditions'].update(empty_docker=False),
        lambda r:r['preconditions'].update(machine_id=r['preconditions']['source_machine_id']),
        lambda r:r['donor_off'].update(powered_off=False),
        lambda r:r['activation']['restoration'].update(source_containers_absent=False),
        lambda r:r['activation']['restoration']['applications']['prestashop'].update(data_sha256='0'*64),
        lambda r:r['all_files'].update(files=0), lambda r:r['status']['storage']['export'].update(pending_records=1),
        lambda r:r.update(business_pilot_started=True)]
    for mutate in mutations:
        changed = copy.deepcopy(report)
        mutate(changed)
        try:
            claims(changed)
        except AssertionError:
            continue
        raise AssertionError('invalid fresh-host qualification accepted')
    return dict(passed=True, checker_sha256=digest(Path(__file__)), databases=2,
        application_volumes=sum(len(v['volumes']) for v in manifest['apps'].values()),
        existing_files=report['existing_files']['files'], new_files=4, browser_sessions=4,
        requests=len(requests), source_events=2, final_events=4, negative_claims_rejected=len(mutations),
        fresh_os_business_recovery_qualified=True, business_pilot_started=False)


if __name__ == '__main__':
    if not __debug__:
        raise RuntimeError('verification requires assertions; do not use -O')
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('report', type=Path)
    parser.add_argument('--package', type=Path, required=True)
    args = parser.parse_args()
    result = check(args.report, args.package)
    (args.report.parent / 'verification.json').write_text(json.dumps(result, indent=2) + '\n')
    (args.report.parent / 'source/check-fresh-business-evidence.py').write_bytes(Path(__file__).read_bytes())
    print(json.dumps(result, indent=2))
