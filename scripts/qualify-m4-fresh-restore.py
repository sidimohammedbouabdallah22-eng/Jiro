"""Move a retained checkpoint to a separately prepared clean VirtualBox OS.

Requires two explicitly named owned lab VMs. Retains disks, failed fixtures,
source snapshots and private transfer inputs. Never clones the donor disk.
"""
import argparse
import hashlib
import importlib.util
import json
from pathlib import Path
import re
import shlex
import socket
import subprocess
import time
from urllib.parse import urlparse
import uuid


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--donor', required=True)
    parser.add_argument('--target', required=True)
    parser.add_argument('--source-fixture', required=True)
    parser.add_argument('--source-proof', type=Path, required=True)
    parser.add_argument('--package', type=Path, required=True)
    parser.add_argument('--disposable-vm', required=True, action='store_true')
    args = parser.parse_args()
    repo = Path(__file__).resolve().parents[1]
    assert args.donor != args.target
    assert re.fullmatch(r'/var/lib/owaf-m2-[a-f0-9]{8}', args.source_fixture)
    for name in [args.donor, args.target]:
        assert re.fullmatch(r'openwaf-m2-24\.04-[a-f0-9]{8}', name)
    package = args.package.resolve(strict=True)
    package_sha = sha(package)
    assert package_sha == Path(str(package) + '.sha256').read_text().split()[0]
    import tarfile
    with tarfile.open(package) as archive:
        server_sha = hashlib.sha256(archive.extractfile('usr/lib/openwaf/waf-server').read()).hexdigest()
    preparation = json.loads((repo / 'artifacts/m2-vms' / args.target / 'result.json').read_text())
    assert preparation['prepared'] and not preparation['qualification_performed']
    assert preparation['package_sha256'] == package_sha
    tag = uuid.uuid4().hex[:8]
    out = repo / 'artifacts' / ('m4-fresh-restore-' + tag)
    out.mkdir()
    spec = importlib.util.spec_from_file_location('permissions', repo / 'scripts/qualify-applications.py')
    permissions = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(permissions)
    permissions.restrict_artifacts(out)
    source_dir = out / 'source'
    source_dir.mkdir()
    sources = {}
    for name in ['qualify-m4-fresh-restore.py', 'm4_fresh_restore_guest.py', 'm2_guest.py']:
        data = (repo / 'scripts' / name).read_bytes()
        (source_dir / name).write_bytes(data)
        sources[name] = hashlib.sha256(data).hexdigest()
    (source_dir / 'native-auth.cjs').write_bytes((repo / 'tools/ui-check/native-auth.cjs').read_bytes())
    sources['native-auth.cjs'] = sha(source_dir / 'native-auth.cjs')
    (source_dir / 'target-preparation.json').write_text(json.dumps(preparation, indent=2))
    report = dict(passed=False, donor=args.donor, target=args.target, package_sha256=package_sha,
                  server_sha256=server_sha, sources=sources, scope='Ubuntu 24.04 amd64 fresh-OS WAF recovery with controlled backends; not business-database DR')
    vbox = r'C:\Program Files\Oracle\VirtualBox\VBoxManage.exe'
    tunnel = None
    root = '/var/lib/owaf-fresh-' + tag
    export_root = '/var/lib/owaf-fresh-export-' + tag

    def run(argv, timeout=300, check=True, data=None):
        result = subprocess.run([str(x) for x in argv], input=data, text=True, capture_output=True, timeout=timeout)
        if check and result.returncode:
            # Output can contain credentials. Save privately, expose only location.
            (out / 'last-failure.private.txt').write_text(result.stdout + result.stderr)
            raise RuntimeError(f'{Path(str(argv[0])).name} failed; private detail: {out / "last-failure.private.txt"}')
        return result

    def vm_info(name):
        deadline = time.monotonic() + 90
        while time.monotonic() < deadline:
            result = run([vbox, 'showvminfo', name, '--machinereadable'], check=False)
            if result.returncode == 0:
                return result.stdout
            time.sleep(1)  # VirtualBox briefly locks metadata during shutdown.
        raise RuntimeError('VM metadata unavailable: ' + name)

    connections = {}
    for name in [args.donor, args.target]:
        info = vm_info(name)
        port = re.search(r'Forwarding\(0\)="ssh,tcp,127\.0\.0\.1,(\d+),,22"', info)[1]
        vm_dir = repo / 'artifacts/m2-vms' / name
        options = ['-i', vm_dir / 'identity', '-o', 'BatchMode=yes', '-o', 'ConnectTimeout=5', '-o', 'ServerAliveInterval=5', '-o', 'ServerAliveCountMax=3', '-o', 'StrictHostKeyChecking=yes', '-o', f'UserKnownHostsFile={vm_dir / "known_hosts"}']
        connections[name] = dict(ssh=['ssh', *options, '-p', port, 'qualifier@127.0.0.1'], scp=['scp', *options, '-P', port], options=options, port=port)

    def ssh(name, argv, **kwargs):
        return run([*connections[name]['ssh'], shlex.join([str(x) for x in argv])], **kwargs)

    def guest(name, operation, guest_root, **values):
        argv = ['sudo', 'python3', '/tmp/m4_fresh_restore_guest.py', operation, '--root', guest_root]
        for key, value in values.items():
            argv.extend(['--' + key.replace('_', '-'), str(value)])
        return json.loads(ssh(name, argv, timeout=600).stdout)

    def save():
        (out / 'result.json').write_text(json.dumps(report, indent=2) + '\n')

    def poweroff(name):
        ssh(name, ['sudo', 'poweroff'], check=False, timeout=20)
        deadline = time.monotonic() + 60
        while time.monotonic() < deadline:
            if 'VMState="poweroff"' in vm_info(name):
                return
            time.sleep(1)
        raise RuntimeError('VM did not power off: ' + name)

    try:
        for name in [args.donor, args.target]:
            info = vm_info(name)
            if 'VMState="poweroff"' in info:
                run([vbox, 'startvm', name, '--type', 'headless'])
            deadline = time.monotonic() + 180
            while time.monotonic() < deadline:
                if ssh(name, ['true'], check=False).returncode == 0:
                    break
                time.sleep(2)
            else:
                raise RuntimeError('SSH unavailable')
            run([*connections[name]['scp'], source_dir / 'm4_fresh_restore_guest.py', source_dir / 'm2_guest.py', 'qualifier@127.0.0.1:/tmp/'])
        print('Exporting stopped donor checkpoint and current audit receipts', flush=True)
        exported = guest(args.donor, 'export', export_root, source=args.source_fixture, helper='/tmp/m2_guest.py', server_sha256=server_sha)
        report['export'] = exported
        save()
        archive = out / 'recovery.private.tar.gz'
        run([*connections[args.donor]['scp'], f'qualifier@127.0.0.1:{export_root}/recovery.private.tar.gz', archive])
        assert sha(archive) == exported['archive_sha256']
        poweroff(args.donor)
        report['donor_off_before_target_activation'] = True
        print('Donor off; restoring into clean target OS', flush=True)
        run([*connections[args.target]['scp'], archive, 'qualifier@127.0.0.1:/tmp/'])
        remote_package = '/tmp/owaf-fresh-' + tag + '-package.tar.gz'
        run([*connections[args.target]['scp'], package, 'qualifier@127.0.0.1:' + remote_package])
        restored = guest(args.target, 'restore', root, archive='/tmp/recovery.private.tar.gz', archive_sha256=sha(archive),
                         source_machine_id=exported['source_machine_id'], package=remote_package,
                         package_sha256=package_sha, server_sha256=server_sha)
        report['restore'] = restored
        save()
        print('Restored bytes, policies, events and audit history verified; testing enrolled factors', flush=True)
        origin = restored['origin']
        parsed = urlparse(origin)
        assert parsed.scheme == 'http' and parsed.hostname == 'localhost' and parsed.port
        with socket.socket() as probe:
            probe.bind(('127.0.0.1', parsed.port))
        connection = connections[args.target]
        tunnel = subprocess.Popen(['ssh', *connection['options'], '-p', connection['port'], '-N', '-o', 'ExitOnForwardFailure=yes', '-L', f'127.0.0.1:{parsed.port}:127.0.0.1:{restored["admin"]}', 'qualifier@127.0.0.1'], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        time.sleep(1)
        assert tunnel.poll() is None
        original = json.loads(args.source_proof.read_text())
        private = dict(original, origin=origin)
        proof_result = run(['node', repo / 'tools/ui-check/native-auth.cjs'], data=json.dumps(private), timeout=180)
        proof = json.loads(proof_result.stdout)
        assert proof['credential']['signCount'] > original['credential']['signCount']
        (out / 'passkey-credential.private.json').write_text(json.dumps(dict(credential=proof['credential'], totp=proof['totp'])))
        report['authentication'] = dict(passkey=True, totp=True, strong_authentication=proof['identity']['strong_authentication'],
                                        source_counter=original['credential']['signCount'], restored_counter=proof['credential']['signCount'])
        report['traffic_and_delivery'] = guest(args.target, 'check', root)
        report['captured'] = guest(args.target, 'capture', root)
        captured = out / 'captured.private.tar.gz'
        run([*connections[args.target]['scp'], f'qualifier@127.0.0.1:{root}/captured.private.tar.gz', captured])
        assert sha(captured) == report['captured']['sha256']
        assert sha(package) == package_sha
        for name in sources:
            path = repo / ('tools/ui-check/native-auth.cjs' if name == 'native-auth.cjs' else 'scripts/' + name)
            assert sha(path) == sources[name], 'qualification source changed during drill'
        report['passed'] = True
        save()
        print('Fresh-host restoration, authentication, traffic and delivery passed', flush=True)
    finally:
        if tunnel:
            tunnel.terminate()
            tunnel.wait(timeout=20)
        for name in [args.target, args.donor]:
            try:
                if 'VMState="running"' in vm_info(name):
                    try:
                        if name == args.target and report.get('restore'):
                            guest(name, 'stop', root)
                    finally:
                        poweroff(name)
            except Exception as error:
                report.setdefault('cleanup_errors', []).append(type(error).__name__ + ': ' + name)
                report['passed'] = False
        report['both_vms_powered_off'] = all('VMState="poweroff"' in vm_info(name) for name in [args.donor, args.target])
        save()
        print(out / 'result.json', flush=True)


if __name__ == '__main__':
    main()
