"""Restore the owned cold business checkpoint on a separately prepared OS."""
import argparse
import json
import os
from pathlib import Path
import re
import shutil
import sys
import tarfile

import m4_business_recovery_guest as recovery


def prepare(root, payload):
    assert not root.exists() and shutil.disk_usage('/var/lib').free >= 24 << 30
    for path in ['/etc/openwaf', '/var/lib/openwaf', '/usr/lib/openwaf', '/var/lib/docker']:
        assert not os.path.lexists(path), 'target is already initialized'
    assert recovery.run(['getent', 'passwd', 'openwaf'], check=False).returncode != 0
    assert recovery.run(['systemctl', 'cat', 'openwaf.service'], check=False).returncode != 0
    machine_id = recovery.digest('/etc/machine-id')
    assert machine_id != payload['source_machine_id']
    root.mkdir(mode=0o755)
    root.chmod(0o755)
    preconditions = dict(clean_os=True, machine_id=machine_id,
        source_machine_id=payload['source_machine_id'], checkpoint_sha256=payload['checkpoint_sha256'])
    recovery.run(['apt-get', 'update'], timeout=600)
    recovery.run(['apt-get', 'install', '-y', '--no-install-recommends', 'docker.io', 'socat'], timeout=900)
    recovery.run(['systemctl', 'start', 'docker'])
    assert not recovery.run(['docker', 'image', 'ls', '-q']).stdout.strip()
    assert not recovery.run(['docker', 'ps', '-aq']).stdout.strip()
    assert not recovery.run(['docker', 'volume', 'ls', '-q']).stdout.strip()
    preconditions['empty_docker'] = True
    preconditions['versions'] = recovery.run(['dpkg-query', '-W', 'docker.io', 'socat']).stdout
    recovery.save(root / 'fresh-host-preconditions.json', preconditions)
    return preconditions


def restore(root, payload):
    bundle = Path(payload['bundle'])
    package = Path(payload['package'])
    assert recovery.digest(bundle) == payload['bundle_sha256']
    assert recovery.digest(package) == payload['package_sha256']
    assert not (root / 'business-checkpoint').exists()
    # Extract only the checkpoint. The previous machine's restored outputs
    # cannot satisfy any post-restore checks on this machine.
    with tarfile.open(bundle) as archive:
        members = archive.getmembers()
        assert len(members) < 5000 and len({m.name for m in members}) == len(members)
        assert sum(m.size for m in members) < 8 << 30
        assert all((m.isfile() or m.isdir()) and recovery.member_path(m.name) == m.name for m in members)
        chosen = [m for m in members if m.name == 'checkpoint' or m.name.startswith('checkpoint/')]
        assert chosen
        incoming = root / 'incoming'
        incoming.mkdir(mode=0o700)
        archive.extractall(incoming, members=chosen, filter='data')
    (incoming / 'checkpoint').rename(root / 'business-checkpoint')
    backup, manifest = recovery.verify_checkpoint(root, payload['checkpoint_sha256'])
    with tarfile.open(package) as archive:
        destination = root / 'package'
        archive.extractall(destination, filter='data')
    recovery.run(['sh', destination / 'install.sh'])
    recovery.run(['systemctl', 'stop', 'openwaf.service'], check=False)
    assert recovery.digest('/usr/lib/openwaf/waf-server') == payload['server_sha256']
    fixture = json.loads((backup / 'fixture.private.json').read_text())
    old_tag = payload['source_tag']
    assert re.fullmatch(r'[a-f0-9]{8}', old_tag)
    fixture.update(lab_environment='virtualbox', recovery_source_root='/var/lib/owaf-joint-' + old_tag,
        recovery_source_tag=old_tag)
    fixture['units'] = {kind:'owaf-joint-' + root.name.rsplit('-', 1)[1] + '-' + kind + '.service'
                        for kind in ['gateway', 'collector', 'monitor']}
    assert fixture['server_sha256'] == payload['server_sha256']
    recovery.save(root / 'fixture.private.json', fixture)
    shutil.copyfile('/usr/lib/openwaf/waf-admin', root / 'waf-admin')
    (root / 'waf-admin').chmod(0o755)
    # Retain the checkpoint's bounded service slice without implying a sizing
    # result. This VM has one physical allocation of one vCPU and four GiB.
    Path('/etc/systemd/system/jiro-m4.slice').write_text('[Slice]\nMemoryMax=4G\nTasksMax=2048\n')
    recovery.run(['systemctl', 'daemon-reload'])
    result = recovery.restore(root, fixture, payload['checkpoint_sha256'], fresh_host=True)
    recovery.save(root / 'fresh-restoration.json', result)
    return dict(restoration=result, ports=fixture['ports'])


def stop(root):
    fixture = json.loads((root / 'fixture.private.json').read_text())
    recovery.run(['systemctl', 'stop', fixture['units']['gateway'], fixture['units']['collector']], check=False)
    containers = []
    for app in recovery.APPS:
        recovery.run(['systemctl', 'stop', fixture[app]['units']['relay']], check=False)
        for kind in ['app', 'db']:
            name = recovery.prefix(root) + '-' + app + '-' + kind
            if recovery.run(['docker', 'inspect', name], check=False).returncode == 0:
                assert recovery.inspect(name)['Config']['Labels']['jiro.recovery'] == recovery.prefix(root)
                recovery.run(['docker', 'stop', name])
                containers.append(name)
    assert not recovery.run(['docker', 'ps', '-q']).stdout.strip()
    return dict(stopped=True, containers=containers)


def main():
    if not __debug__:
        raise RuntimeError('qualification requires assertions; do not use -O')
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('operation', choices=['prepare', 'restore', 'files', 'capture', 'stop'])
    parser.add_argument('--root', type=Path, required=True)
    args = parser.parse_args()
    root = args.root
    assert __debug__ and os.geteuid() == 0
    assert re.fullmatch(r'/var/lib/owaf-joint-[a-f0-9]{8}', str(root)) and root.resolve() == root
    assert recovery.run(['systemd-detect-virt', '--vm']).stdout.strip() == 'oracle'
    os.umask(0o077)
    if args.operation in ['prepare', 'restore']:
        result = globals()[args.operation](root, json.load(sys.stdin))
    elif args.operation in ['files', 'capture']:
        fixture = json.loads((root / 'fixture.private.json').read_text())
        result = recovery.files(root, fixture, json.load(sys.stdin)) if args.operation == 'files' else recovery.capture(root, fixture)
    else:
        result = stop(root)
    print(json.dumps(result))


if __name__ == '__main__':
    main()
