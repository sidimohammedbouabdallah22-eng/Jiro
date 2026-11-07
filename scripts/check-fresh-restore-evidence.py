"""Check fresh-host proof against retained private checkpoint/database bytes."""
import argparse
import copy
import hashlib
import json
from pathlib import Path
import sqlite3
import tarfile


def sha(data):
    return hashlib.sha256(data).hexdigest()


def read_archive(path):
    with tarfile.open(path) as archive:
        members = archive.getmembers()
        names = [member.name for member in members]
        assert len(names) == len(set(names))
        assert sum(member.size for member in members) < 4 << 30
        for member in members:
            assert member.isfile() or member.isdir()
            assert not Path(member.name).is_absolute() and '..' not in Path(member.name).parts
        return {member.name: archive.extractfile(member).read() for member in members if member.isfile()}


def database(data):
    db = sqlite3.connect(':memory:')
    db.deserialize(data)
    assert db.execute('PRAGMA quick_check').fetchone()[0] == 'ok'
    return db


def received(db):
    rows = list(db.execute('SELECT source_id,id,sequence,occurrences,data,digest FROM collected_events ORDER BY source_id,id'))
    totals = db.execute('SELECT records,occurrences FROM collector_totals WHERE singleton=1').fetchone()
    assert totals == (len(rows), sum(row[3] for row in rows))
    assert all(sha(row[4] + b'\x00' + str(row[3]).encode()) == row[5] for row in rows)
    return {(row[0], row[1]): row for row in rows}


def proof(report, package_sha, server_sha):
    assert report['passed'] and report['both_vms_powered_off'] and not report.get('cleanup_errors')
    assert report['donor'] != report['target'] and report['donor_off_before_target_activation']
    assert report['package_sha256'] == package_sha and report['server_sha256'] == server_sha
    exported, restored = report['export'], report['restore']
    assert exported['passed'] and exported['stopped_source']
    assert restored['passed'] and restored['clean_os_preconditions'] and restored['independent_machine_id']
    assert restored['source_machine_id'] == exported['source_machine_id'] != restored['target_machine_id']
    assert restored['restored_binary_sha256'] == server_sha
    assert restored['pre_activation_members_verified'] and restored['fresh_credential_replaced'] and restored['current_audit_receipts_migrated']
    assert restored['definitions_preserved'] == 6
    assert set(restored['assets']) == {'admin-token', 'event-token', 'audit-token', 'tls/cert.pem', 'tls/key.pem', 'authentication.json'}
    for name, item in restored['assets'].items():
        assert item['mode'] == ('0o640' if name.startswith('tls/') or name == 'authentication.json' else '0o600')
        assert len(item['sha256']) == 64
    auth = report['authentication']
    assert auth['passkey'] and auth['totp'] and auth['strong_authentication']
    assert auth['restored_counter'] > auth['source_counter'] > 0
    traffic = report['traffic_and_delivery']
    assert traffic['passed'] and traffic['password_login'] and traffic['tls_certificate_preserved']
    assert traffic['scoped_token'] and traffic['assignment_isolated']
    if traffic.get('restored_token_expired_and_rejected'):
        assert traffic['newly_issued_token'] and traffic['new_token_revocation_verified']
    assert traffic['new_security_events'] == 2 and traffic['security_pending'] == traffic['audit_pending'] == 0
    cases = traffic['requests']
    assert len(cases) == 6
    for host in ['application.test', 'portal.test']:
        assert sorted((case['attack'], case['status']) for case in cases if case['host'] == host) == [(False, 200), (False, 200), (True, 403)]
    assert report['captured']['stopped']


def check(path, package):
    report = json.loads(path.read_text())
    package_sha = sha(package.read_bytes())
    assert package_sha == Path(str(package) + '.sha256').read_text().split()[0]
    with tarfile.open(package) as archive:
        server_sha = sha(archive.extractfile('usr/lib/openwaf/waf-server').read())
    proof(report, package_sha, server_sha)
    out = path.parent
    for name, expected in report['sources'].items():
        assert sha((out / 'source' / name).read_bytes()) == expected
    preparation = json.loads((out / 'source/target-preparation.json').read_text())
    assert preparation['vm'] == report['target'] and preparation['prepared'] and not preparation['qualification_performed']
    assert preparation['package_sha256'] == package_sha
    vm_dir = Path(__file__).resolve().parents[1] / 'artifacts/m2-vms' / report['target']
    assert json.loads((vm_dir / 'result.json').read_text()) == preparation
    assert sha((vm_dir / 'provisioner.py').read_bytes()) == preparation['provisioner_sha256']
    original_path = out / 'recovery.private.tar.gz'
    captured_path = out / 'captured.private.tar.gz'
    assert sha(original_path.read_bytes()) == report['export']['archive_sha256']
    assert sha(captured_path.read_bytes()) == report['captured']['sha256']
    original, captured = read_archive(original_path), read_archive(captured_path)
    inventory = json.loads(original['inventory.json'])
    assert {name.removeprefix('transfer/'):sha(data) for name, data in original.items() if name.startswith('transfer/')} == inventory == report['export']['members']
    manifest = json.loads(original['transfer/checkpoint/manifest.json'])
    assert sha(original['transfer/checkpoint/manifest.json']) == report['export']['checkpoint_manifest_sha256']
    for member in manifest['files']:
        data = original['transfer/checkpoint/' + member['path']]
        assert sha(data) == member['sha256'] and len(data) == member['size']
    assert sha(original['transfer/checkpoint/bin/waf-server']) == server_sha
    for name, metadata in report['restore']['assets'].items():
        assert original['transfer/deployment/' + name] == captured['deployment/' + name]
        assert sha(captured['deployment/' + name]) == metadata['sha256']
    baseline = json.loads(captured['baseline.private.json'])
    final = json.loads(captured['final-snapshot.private.json'])
    assert baseline['accounts_sha256'] == sha(original['transfer/checkpoint/state/policy.json.accounts.json'])
    before_accounts = json.loads(original['transfer/checkpoint/state/policy.json.accounts.json'])
    after_accounts = json.loads(captured['restored/state/policy.json.accounts.json'])
    assert after_accounts['revision'] >= before_accounts['revision']
    after_accounts['revision'] = before_accounts['revision']
    old_users = {user['username']:user for user in before_accounts['accounts']}
    new_users = {user['username']:user for user in after_accounts['accounts']}
    old_counter = old_users['qa-admin']['passkeys'][0]['credential']['authenticator']['signCount']
    authenticator = new_users['qa-admin']['passkeys'][0]['credential']['authenticator']
    assert authenticator['signCount'] == report['authentication']['restored_counter'] > old_counter
    authenticator['signCount'] = old_counter
    assert new_users['qa-otp']['mfa_last_step'] > old_users['qa-otp']['mfa_last_step']
    new_users['qa-otp']['mfa_last_step'] = old_users['qa-otp']['mfa_last_step']
    assert before_accounts == after_accounts, 'unexpected identity/authorization changes during recovery'
    # All immutable policy/history bytes must survive; factor counters and audit
    # export cursors legitimately advance during post-restore authentication.
    for name, data in original.items():
        relative = name.removeprefix('transfer/checkpoint/')
        if relative.startswith('state/') and (relative == 'state/policy.json' or '.history/' in relative):
            assert captured['restored/' + relative] == data
    initial_events = database(original['transfer/checkpoint/state/events.db'])
    events = database(captured['restored/state/events.db'])
    receiver = database(captured['restored/state/collector.db'])
    old_audit = database(original['transfer/audit-current.db'])
    audit = database(captured['audit/events.db'])
    old_rows = dict(initial_events.execute('SELECT id,data FROM events'))
    new_rows = dict(events.execute('SELECT id,data FROM events'))
    for key, value in old_rows.items():
        assert new_rows[key] == value
    assert len(new_rows) - len(old_rows) == 2
    assert len(old_rows) == report['restore']['verification']['verified_events']
    assert len(new_rows) == report['traffic_and_delivery']['delivered_security_events']
    source = final['status']['storage']['export']['source_id']
    received_events = received(receiver)
    assert {(key[1], value[4]) for key,value in received_events.items() if key[0] == source} == set(new_rows.items())
    original_audit_rows = received(old_audit)
    final_audit_rows = received(audit)
    assert sha('\n'.join(old_audit.iterdump()).encode()) == report['export']['current_audit_receiver_sha256']
    assert all(final_audit_rows[key] == row for key,row in original_audit_rows.items())
    old_lines = original['transfer/checkpoint/state/policy.json.audit.jsonl'].splitlines()
    new_lines = captured['restored/state/policy.json.audit.jsonl'].splitlines()
    assert new_lines[:len(old_lines)] == old_lines
    records = [json.loads(line) for line in new_lines]
    live_count = report['traffic_and_delivery']['delivered_audit_records']
    assert records[:live_count] == final['audit'] and len(records) == live_count + 1
    assert records[-1]['operation'] == 'service.stopping' and records[-1]['outcome'] == 'intent'
    audit_source = records[0]['hash'][:32]
    for record in records:
        assert json.loads(final_audit_rows[audit_source, record['id']][4]) == record
    assert final['status']['storage']['export']['pending_records'] == final['status']['audit_export']['pending_records'] == 0
    for db in [initial_events, events, receiver, old_audit, audit]:
        db.close()
    mutations = [
        lambda r:r.update(passed=False),
        lambda r:r.update(target=r['donor']),
        lambda r:r.update(donor_off_before_target_activation=False),
        lambda r:r.update(both_vms_powered_off=False),
        lambda r:r['restore'].update(target_machine_id=r['restore']['source_machine_id']),
        lambda r:r['restore'].update(restored_binary_sha256='0'*64),
        lambda r:r['restore'].update(current_audit_receipts_migrated=False),
        lambda r:r['restore']['assets']['tls/key.pem'].update(mode='0o777'),
        lambda r:r['authentication'].update(strong_authentication=False),
        lambda r:r['authentication'].update(restored_counter=r['authentication']['source_counter']),
        lambda r:r['traffic_and_delivery'].update(security_pending=1),
        lambda r:r['traffic_and_delivery'].update(requests=[]),
    ]
    for mutate in mutations:
        changed = copy.deepcopy(report)
        mutate(changed)
        try:
            proof(changed, package_sha, server_sha)
        except AssertionError:
            continue
        raise AssertionError('invalid recovery proof accepted')
    return dict(passed=True, report=str(path), checker_sha256=sha(Path(__file__).read_bytes()),
                fresh_host_scope='Ubuntu 24.04 amd64 controlled-backend fixture',
                preserved_security_events=len(old_rows), new_security_events=2, delivered_security_events=len(new_rows),
                preserved_current_audit_receiver_records=len(original_audit_rows),
                delivered_audit_records=len(records), shutdown_audit_records_verified=1, negative_proofs_rejected=len(mutations),
                identity_and_authorization_preserved=True,
                business_database_recovery_qualified=False, business_pilot_started=False)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('report', type=Path)
    parser.add_argument('--package', type=Path, required=True)
    args = parser.parse_args()
    result = check(args.report, args.package)
    (args.report.parent / 'verification.json').write_text(json.dumps(result, indent=2) + '\n')
    (args.report.parent / 'source/check-fresh-restore-evidence.py').write_bytes(Path(__file__).read_bytes())
    print(json.dumps(result, indent=2))
