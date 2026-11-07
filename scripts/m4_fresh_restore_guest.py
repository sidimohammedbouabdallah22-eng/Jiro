"""Fresh-OS recovery drill. Private transfer material stays in owned lab paths.

The WAF checkpoint and current independent audit receiver are separate inputs.
This restores a controlled backend fixture, not business-application databases.
"""
import argparse
import hashlib
import http.client
import http.cookiejar
import importlib.util
import json
import os
from pathlib import Path
import pwd
import re
import shutil
import sqlite3
import ssl
import subprocess
import tarfile
import urllib.error
import urllib.request


def command(args):
    return subprocess.check_output([str(x) for x in args], stderr=subprocess.STDOUT, text=True)


def digest(path):
    with Path(path).open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def write(path, value):
    path.write_text(json.dumps(value, indent=2) + '\n')
    path.chmod(0o600)


def inventory(root):
    result = {}
    for path in sorted(root.rglob('*')):
        if path.is_symlink():
            raise RuntimeError('symlink in recovery inputs')
        if path.is_file():
            result[str(path.relative_to(root))] = digest(path)
    return result


def receiver_rows(path):
    with sqlite3.connect(f'file:{path}?mode=ro', uri=True) as db:
        assert db.execute('PRAGMA quick_check').fetchone()[0] == 'ok'
        # Includes current delivery receipts and cursors, not just event count.
        return hashlib.sha256('\n'.join(db.iterdump()).encode()).hexdigest()


def load_helper(path):
    spec = importlib.util.spec_from_file_location('recovery_fixture', path)
    helper = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(helper)
    return helper


def export(args):
    source = args.source
    assert re.fullmatch(r'/var/lib/owaf-m2-[a-f0-9]{8}', str(source))
    fixture = json.loads((source / 'fixture.json').read_text())
    assert all(re.fullmatch(r'openwaf-m2-(backend|events|audit)-[a-f0-9]{8}\.service', unit) for unit in fixture['units'])
    command(['systemctl', 'stop', 'openwaf.service', *fixture['units']])
    for unit in ['openwaf.service', *fixture['units']]:
        assert command(['systemctl', 'show', unit, '-p', 'ActiveState', '--value']).strip() == 'inactive'
    args.root.mkdir(mode=0o700)
    transfer = args.root / 'transfer'
    transfer.mkdir(mode=0o700)
    checkpoint = source / 'post-upgrade'
    command([source / 'bin/current/waf-admin', 'verify', '-backup', checkpoint])
    assert digest(checkpoint / 'bin/waf-server') == args.server_sha256
    shutil.copytree(checkpoint, transfer / 'checkpoint')
    shutil.copytree(source / 'replacement/deployment', transfer / 'deployment')
    shutil.copytree(source / 'replacement/service-definitions', transfer / 'service-definitions')
    shutil.copyfile(source / 'backend.py', transfer / 'backend.py')
    shutil.copyfile(source / 'fixture.json', transfer / 'fixture.json')
    shutil.copyfile(args.helper, transfer / 'helper.py')
    with sqlite3.connect(f"file:{fixture['audit_receiver']}?mode=ro", uri=True) as src, sqlite3.connect(transfer / 'audit-current.db') as dst:
        src.backup(dst)
    assert receiver_rows(fixture['audit_receiver']) == receiver_rows(transfer / 'audit-current.db')
    members = inventory(transfer)
    write(args.root / 'inventory.json', members)
    archive = args.root / 'recovery.private.tar.gz'
    with tarfile.open(archive, 'w:gz') as tar:
        tar.add(transfer, arcname='transfer')
        tar.add(args.root / 'inventory.json', arcname='inventory.json')
    archive.chmod(0o600)
    os.chown(archive, pwd.getpwnam('qualifier').pw_uid, pwd.getpwnam('qualifier').pw_gid)
    # Only the archive is made readable to the transfer account.
    args.root.chmod(0o711)
    report = dict(passed=True, stopped_source=True, archive_sha256=digest(archive), members=members,
                  checkpoint_manifest_sha256=digest(checkpoint / 'manifest.json'),
                  current_audit_receiver_sha256=receiver_rows(transfer / 'audit-current.db'),
                  source_machine_id=digest('/etc/machine-id'))
    write(args.root / 'export-report.json', report)
    return report


def restore(args):
    assert digest(args.archive) == args.archive_sha256
    assert digest(args.package) == args.package_sha256
    assert shutil.disk_usage('/var/lib').free >= 2 << 30, 'insufficient restore storage'
    for path in ['/etc/openwaf', '/var/lib/openwaf', '/usr/lib/openwaf', str(args.root)]:
        assert not os.path.lexists(path), 'target already initialized: ' + path
    for kind in ['passwd', 'group']:
        assert subprocess.run(['getent', kind, 'openwaf'], stdout=subprocess.DEVNULL).returncode != 0
    assert subprocess.run(['systemctl', 'cat', 'openwaf.service'], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL).returncode != 0
    args.root.mkdir(mode=0o755)
    incoming = args.root / 'incoming'
    incoming.mkdir(mode=0o700)
    with tarfile.open(args.archive) as tar:
        # No links, devices, duplicates, traversal or unbounded extraction.
        names = set()
        total = 0
        for member in tar.getmembers():
            assert member.name not in names
            names.add(member.name)
            path = Path(member.name)
            assert not path.is_absolute() and '..' not in path.parts
            assert path.parts[0] in ['transfer', 'inventory.json']
            assert member.isfile() or member.isdir()
            total += member.size
        assert total < 4 << 30 and len(names) < 10000
        tar.extractall(incoming, filter='data')
    transfer = incoming / 'transfer'
    expected = json.loads((incoming / 'inventory.json').read_text())
    assert inventory(transfer) == expected
    fixture = json.loads((transfer / 'fixture.json').read_text())
    source_id = args.source_machine_id
    assert digest('/etc/machine-id') != source_id, 'same OS identity as donor'
    package_root = args.root / 'package'
    package_root.mkdir()
    # Package hash is trusted by host and checked again before installing.
    with tarfile.open(args.package) as tar:
        tar.extractall(package_root, filter='data')
    command(['sh', package_root / 'install.sh'])
    fresh_token_hash = digest('/etc/openwaf/admin-token')
    restored = args.root / 'restored'
    command(['/usr/lib/openwaf/waf-admin', 'restore', '-backup', transfer / 'checkpoint', '-out', restored])
    assert digest(restored / 'bin/waf-server') == args.server_sha256
    assert digest('/usr/lib/openwaf/waf-server') == args.server_sha256
    assert fresh_token_hash != digest(transfer / 'deployment/admin-token')
    shutil.copytree(transfer / 'deployment', args.root / 'deployment')
    shutil.copyfile(transfer / 'backend.py', args.root / 'backend.py')
    shutil.copyfile(transfer / 'helper.py', args.root / 'helper.py')
    (args.root / 'bin/current').mkdir(parents=True)
    for name in ['waf-admin', 'event-collector']:
        shutil.copyfile(Path('/usr/lib/openwaf') / name, args.root / 'bin/current' / name)
    shutil.copyfile(restored / 'bin/waf-server', args.root / 'bin/current/waf-server')
    for path in (args.root / 'bin/current').iterdir():
        path.chmod(0o755)
    (args.root / 'audit').mkdir(mode=0o700)
    shutil.copyfile(transfer / 'audit-current.db', args.root / 'audit/events.db')
    assert receiver_rows(args.root / 'audit/events.db') == receiver_rows(transfer / 'audit-current.db')
    identity = pwd.getpwnam('openwaf')
    # Restore deliberately returns a root-private directory. Grant the service
    # group traversal while keeping all restored state/credentials restricted.
    os.chown(restored, 0, identity.pw_gid)
    restored.chmod(0o750)
    for subtree in [restored / 'state', args.root / 'audit']:
        for path in [subtree, *subtree.rglob('*')]:
            os.chown(path, identity.pw_uid, identity.pw_gid)
    assets = args.root / 'deployment'
    for path in [assets, *assets.rglob('*')]:
        os.chown(path, 0, identity.pw_gid)
        relative = str(path.relative_to(assets))
        path.chmod(0o750 if path.is_dir() else 0o640 if relative.startswith('tls/') or relative == 'authentication.json' else 0o600)
    shutil.copyfile(assets / 'admin-token', '/etc/openwaf/admin-token')
    Path('/etc/openwaf/admin-token').chmod(0o600)
    tag = args.root.name.rsplit('-', 1)[1]
    fixture.update(deployment_assets=str(assets), binary_root=str(args.root / 'bin'),
                   audit_receiver=str(args.root / 'audit/events.db'))
    for kind in ['events', 'audit', 'backend']:
        fixture[kind + '_unit'] = f'openwaf-fresh-{kind}-{tag}.service'
    fixture['units'] = [fixture[kind + '_unit'] for kind in ['backend', 'events', 'audit']]
    Path('/etc/systemd/system/openwaf.service.d').mkdir()
    Path('/etc/systemd/system/' + fixture['backend_unit']).write_text(
        f'[Service]\nDynamicUser=yes\nExecStart=/usr/bin/python3 {args.root}/backend.py\nRestart=on-failure\n')
    helper = load_helper(args.root / 'helper.py')
    helper.set_services(args.root, fixture, 'current', restored / 'state', restored / 'state/collector.db')
    for readable in [restored / 'state/policy.json', assets / 'tls/key.pem', assets / 'authentication.json']:
        command(['runuser', '-u', 'openwaf', '--', 'test', '-r', readable])
    # Verify checkpoint members before the daemon can advance counters/journals.
    for name, checksum in expected.items():
        if name.startswith('checkpoint/') and name != 'checkpoint/manifest.json':
            assert digest(restored / name.removeprefix('checkpoint/')) == checksum
    audit = [json.loads(line) for line in (restored / 'state/policy.json.audit.jsonl').read_text().splitlines()]
    with sqlite3.connect(restored / 'state/events.db') as db:
        events = [dict(id=row[0], sha256=hashlib.sha256(row[1]).hexdigest()) for row in db.execute('SELECT id,data FROM events ORDER BY seq')]
    baseline = dict(policy=json.loads((restored / 'state/policy.json').read_text()), events=events, audit=audit,
                    accounts_sha256=digest(restored / 'state/policy.json.accounts.json'))
    write(args.root / 'baseline.private.json', baseline)
    command(['systemctl', 'start', *fixture['units'], 'openwaf.service'])
    helper.wait_ready(fixture, drain=True)
    verified = helper.verify(fixture, baseline)
    pid = command(['systemctl', 'show', 'openwaf.service', '-p', 'MainPID', '--value']).strip()
    assert digest(f'/proc/{pid}/exe') == args.server_sha256
    assert Path(os.readlink(f'/proc/{pid}/exe')) == args.root / 'bin/current/waf-server'
    report = dict(passed=True, clean_os_preconditions=True, independent_machine_id=True,
                  source_machine_id=source_id, target_machine_id=digest('/etc/machine-id'),
                  restored_binary_sha256=args.server_sha256, pre_activation_members_verified=True,
                  fresh_credential_replaced=True, current_audit_receipts_migrated=True,
                  verification=verified, definitions_preserved=len(list((transfer / 'service-definitions').iterdir())),
                  assets={str(p.relative_to(assets)):dict(sha256=digest(p), mode=oct(p.stat().st_mode & 0o777)) for p in assets.rglob('*') if p.is_file()},
                  origin=fixture['m3_origin'], admin=fixture['admin'], proxy=fixture['proxy'])
    write(args.root / 'restore-report.json', report)
    return report


def check(args):
    fixture = json.loads((args.root / 'fixture.json').read_text())
    helper = load_helper(args.root / 'helper.py')
    baseline = json.loads((args.root / 'baseline.private.json').read_text())
    restored = helper.verify(fixture, dict(baseline, accounts_sha256=helper.digest(Path(fixture['state']) / 'policy.json.accounts.json')))
    # Browser factor proof intentionally advances the account's replay counters.
    jar = http.cookiejar.CookieJar()
    opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(jar))
    request = urllib.request.Request(f"http://127.0.0.1:{fixture['admin']}/api/v1/login", data=json.dumps(dict(username='qa-viewer', password=fixture['password'])).encode(), headers={'Content-Type':'application/json'})
    with opener.open(request) as response:
        assert response.status == 200
    context = ssl.create_default_context(cafile=str(args.root / 'deployment/tls/cert.pem'))
    class TLSConnection(http.client.HTTPSConnection):
        def connect(self):
            import socket
            self.sock = context.wrap_socket(socket.create_connection(('127.0.0.1', fixture['proxy']), timeout=10), server_hostname=self.host)
    outcomes = []
    for host in ['application.test', 'portal.test']:
        for attack in [False, False, True]:
            connection = TLSConnection(host, fixture['proxy'], timeout=10)
            try:
                connection.request('GET', '/?fresh=restore&q=' + ('%3Cscript%3Ealert(1)%3C/script%3E' if attack else 'customer+invoice'), headers={'Host':host, 'User-Agent':'OpenWAF fresh-host recovery'})
                response = connection.getresponse()
                body = response.read()
                assert response.status == (403 if attack else 200)
                assert attack or body == b'backend-ok'
                cert = connection.sock.getpeercert(binary_form=True)
                expected_cert = ssl.PEM_cert_to_DER_cert((args.root / 'deployment/tls/cert.pem').read_text())
                assert cert == expected_cert
                outcomes.append(dict(host=host, attack=attack, status=response.status))
            finally:
                connection.close()
    # The restored automation credential may have expired during downtime. Never
    # extend its lifetime. Qualify a separately issued short-lived token too.
    try:
        scopes = helper.check_m3(fixture)
    except urllib.error.HTTPError as error:
        assert error.code == 401
        document = json.loads((Path(fixture['state']) / 'policy.json.accounts.json').read_text())
        from datetime import datetime, timezone
        tokens = document['tokens']
        assert len(tokens) == 1 and datetime.fromisoformat(tokens[0]['expires'].replace('Z', '+00:00')) < datetime.now(timezone.utc)
        scopes = dict(restored_token_expired_and_rejected=True)
        directory = helper.api(fixture, 'accounts')
        issued = helper.api(fixture, 'tokens', dict(revision=directory['revision'], owner='qa-viewer',
                            name='Fresh-host recovery reader', scopes=['policy:read'], lifetime_hours=1,
                            reason='Fresh-host scoped authorization verification'))
        fresh_fixture = dict(fixture, automation_token=issued['secret'])
        scopes.update(helper.check_m3(fresh_fixture), newly_issued_token=True)
        directory = helper.api(fixture, 'accounts')
        helper.api(fixture, 'tokens/' + issued['token']['id'] + '/revoke', dict(revision=directory['revision'], reason='End fresh-host recovery verification'))
        try:
            helper.api(fresh_fixture, 'config', credential=issued['secret'])
            raise AssertionError('revoked token accepted')
        except urllib.error.HTTPError as revoked:
            assert revoked.code == 401
        scopes['new_token_revocation_verified'] = True
    helper.wait_ready(fixture, drain=True)
    current = helper.snapshot(fixture)
    helper.verify(fixture, current)  # All post-restore security/audit bytes delivered.
    original_ids = {e['id'] for e in baseline['events']}
    fresh_ids = {e['id'] for e in current['events']} - original_ids
    assert len(fresh_ids) == 2
    status = current['status']
    assert status['storage']['export']['pending_records'] == status['audit_export']['pending_records'] == 0
    report = dict(passed=True, restored_records=restored, password_login=True, **scopes,
                  tls_certificate_preserved=True, requests=outcomes, new_security_events=len(fresh_ids),
                  delivered_security_events=len(current['events']), delivered_audit_records=len(current['audit']),
                  security_pending=0, audit_pending=0)
    write(args.root / 'check-report.json', report)
    write(args.root / 'final-snapshot.private.json', current)
    return report


def capture(args):
    fixture = json.loads((args.root / 'fixture.json').read_text())
    command(['systemctl', 'stop', 'openwaf.service', *fixture['units']])
    for unit in ['openwaf.service', *fixture['units']]:
        assert command(['systemctl', 'show', unit, '-p', 'ActiveState', '--value']).strip() == 'inactive'
    archive = args.root / 'captured.private.tar.gz'
    assert not archive.exists()
    with tarfile.open(archive, 'w:gz') as tar:
        for name in ['restored/state', 'audit', 'deployment', 'fixture.json', 'baseline.private.json',
                     'final-snapshot.private.json', 'restore-report.json', 'check-report.json']:
            tar.add(args.root / name, arcname=name)
    archive.chmod(0o600)
    identity = pwd.getpwnam('qualifier')
    os.chown(archive, identity.pw_uid, identity.pw_gid)
    return dict(stopped=True, sha256=digest(archive))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('operation', choices=['export', 'restore', 'check', 'capture', 'stop'])
    parser.add_argument('--root', type=Path, required=True)
    parser.add_argument('--source', type=Path)
    parser.add_argument('--helper', type=Path)
    parser.add_argument('--archive', type=Path)
    parser.add_argument('--archive-sha256')
    parser.add_argument('--source-machine-id')
    parser.add_argument('--package', type=Path)
    parser.add_argument('--package-sha256')
    parser.add_argument('--server-sha256')
    args = parser.parse_args()
    assert os.geteuid() == 0
    assert command(['systemd-detect-virt', '--vm']).strip() == 'oracle'
    assert re.fullmatch(r'/var/lib/owaf-fresh(-export)?-[a-f0-9]{8}', str(args.root))
    if args.operation == 'stop':
        fixture = json.loads((args.root / 'fixture.json').read_text())
        command(['systemctl', 'stop', 'openwaf.service', *fixture['units']])
        report = dict(stopped=True)
    else:
        report = globals()[args.operation](args)
    print(json.dumps(report))


if __name__ == '__main__':
    main()
