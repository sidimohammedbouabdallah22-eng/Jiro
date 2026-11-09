"""Coordinated cold recovery drill for the explicitly owned M4 business lab."""
import argparse
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import shutil
import subprocess
import sys
import tarfile
import time

import owned_lab_environment


APPS = ('dolibarr', 'prestashop')
MAX_VOLUME_BYTES = 3 << 30


def digest(path):
    value = hashlib.sha256()
    with Path(path).open('rb') as stream:
        for block in iter(lambda: stream.read(1 << 20), b''):
            value.update(block)
    return value.hexdigest()


def save(path, value):
    path.write_text(json.dumps(value, indent=2) + '\n')
    path.chmod(0o600)


def run(args, check=True, timeout=600):
    result = subprocess.run([str(v) for v in args], capture_output=True, text=True, timeout=timeout)
    if check and result.returncode:
        raise RuntimeError('owned recovery command failed: ' + str(args[0]))
    return result


def inspect(name):
    return json.loads(run(['docker', 'inspect', name]).stdout)[0]


def member_path(name):
    path = PurePosixPath(name)
    if path.is_absolute() or '..' in path.parts or '\\' in name:
        raise ValueError('unsafe recovery archive member')
    return str(path)


def volume_inventory(path):
    entries = {}
    total = 0
    options = dict(fileobj=path) if hasattr(path, 'read') else dict(name=path)
    with tarfile.open(mode='r|*', **options) as archive:
        for member in archive:
            name = member_path(member.name)
            if name in entries or len(entries) >= 100000:
                raise ValueError('duplicate or oversized recovery inventory')
            item = dict(mode=member.mode, uid=member.uid, gid=member.gid)
            if member.isfile():
                total += member.size
                if total > MAX_VOLUME_BYTES:
                    raise ValueError('recovery volume exceeds byte bound')
                value = hashlib.sha256()
                stream = archive.extractfile(member)
                for block in iter(lambda: stream.read(1 << 20), b''):
                    value.update(block)
                item.update(kind='file', bytes=member.size, sha256=value.hexdigest())
            elif member.isdir():
                item['kind'] = 'directory'
            elif member.issym() or member.islnk():
                target = member_path(member.linkname)
                item.update(kind='symlink' if member.issym() else 'hardlink', target=target)
            else:
                raise ValueError('unsupported recovery archive member')
            entries[name] = item
    encoded = json.dumps(entries, sort_keys=True, separators=(',', ':')).encode()
    return dict(entries=entries, bytes=total, sha256=hashlib.sha256(encoded).hexdigest())


def transfer(args, path, reading=False, errors_path=None):
    errors_path = errors_path or Path(str(path) + '.stderr.private.log')
    with path.open('rb' if reading else 'wb') as stream, errors_path.open('wb') as errors:
        options = dict(stdin=stream, stdout=subprocess.DEVNULL) if reading else dict(stdout=stream)
        result = subprocess.run([str(v) for v in args], stderr=errors, timeout=900, **options)
    if not reading:
        path.chmod(0o600)
    if result.returncode:
        raise RuntimeError('owned recovery transfer failed')


def database_dump(container, path, kind='full'):
    options = '--skip-comments --skip-extended-insert --order-by-primary --hex-blob'
    options += {'full':' --routines --events --triggers --add-drop-database --databases',
                'data':' --compact --no-create-info --skip-triggers',
                'schema':' --no-data --routines --events --triggers --databases'}[kind]
    shell = 'exec mariadb-dump -uroot -p"$MARIADB_ROOT_PASSWORD" ' + options + ' business'
    transfer(['docker', 'exec', container, 'sh', '-c', shell], path)


def await_database(container):
    for _ in range(120):
        result = run(['docker', 'exec', container, 'sh', '-c',
                      'mariadb --protocol=tcp --host=127.0.0.1 -uroot -p"$MARIADB_ROOT_PASSWORD" -e "SELECT 1"'], check=False)
        if result.returncode == 0:
            return
        time.sleep(1)
    raise RuntimeError('restored database readiness deadline exceeded')


def restore_volume(image, volume, archive, label, errors_path):
    transfer(['docker', 'run', '--rm', '-i', '--user', '0:0', '--network', 'none', '--read-only',
              '--security-opt', 'no-new-privileges', '--label', 'jiro.recovery=' + label,
              '--cgroup-parent', 'jiro-m4.slice', '--memory', '128m', '--pids-limit', '32',
              '--mount', 'type=volume,source=' + volume + ',target=/recovery,volume-nocopy',
              '--entrypoint', 'tar', image, '-xpf', '-', '-C', '/recovery', '--numeric-owner'],
             archive, reading=True, errors_path=errors_path)


def await_executable(unit, expected, expected_sha256):
    deadline = time.monotonic() + 60
    while time.monotonic() < deadline:
        pid = int(run(['systemctl', 'show', unit, '-p', 'MainPID', '--value'], timeout=10).stdout)
        if pid:
            executable = Path(f'/proc/{pid}/exe')
            try:
                if executable.resolve(strict=True) == expected and digest(executable) == expected_sha256:
                    return pid
            except FileNotFoundError:
                pass
        if run(['systemctl', 'is-failed', unit], check=False, timeout=10).stdout.strip() == 'failed':
            raise RuntimeError('restored service failed before executable readiness')
        time.sleep(0.1)
    raise RuntimeError('restored executable identity did not settle')


def environment_file(path, values):
    if any('\n' in value or '\r' in value for value in values):
        raise ValueError('multiline container environment requires explicit recovery handling')
    path.write_text('\n'.join(values) + '\n')
    path.chmod(0o600)


def prefix(root):
    return 'owaf-recovery-' + root.name.rsplit('-', 1)[1]


def relay(unit, port, address):
    run(['systemctl', 'stop', unit], check=False)
    run(['systemd-run', '--collect', '--unit=' + unit,
         '--property=DynamicUser=yes', '--property=Slice=jiro-m4.slice',
         '/usr/bin/socat', f'TCP-LISTEN:{port},bind=127.0.0.1,reuseaddr,fork,max-children=32',
         'TCP:' + address + ':80'])


def checkpoint(root, fixture):
    target, stage = root / 'business-checkpoint', root / 'business-checkpoint.incomplete'
    if target.exists() or stage.exists() or shutil.disk_usage(root).free < 15 << 30:
        raise RuntimeError('requires a new checkpoint and fifteen GiB free space')
    stage.mkdir(mode=0o700)
    definitions = root / 'recovery-original-units'
    definitions.mkdir(mode=0o700)
    (stage / 'services').mkdir(mode=0o700)
    for kind in ('gateway', 'collector'):
        shutil.copyfile(Path('/etc/systemd/system') / fixture['units'][kind], definitions / kind)
        shutil.copyfile(definitions / kind, stage / 'services' / kind)
    shutil.copyfile(root / 'fixture.private.json', stage / 'fixture.private.json')
    (stage / 'runtime').mkdir(mode=0o700)
    shutil.copyfile(root / 'event-collector', stage / 'runtime/event-collector')
    run(['systemctl', 'stop', fixture['units']['monitor']], check=False)
    run(['systemctl', 'stop', fixture['units']['gateway'], fixture['units']['collector']])
    for app in APPS:
        run(['systemctl', 'stop', fixture[app]['units']['relay']])
        run(['docker', 'stop', fixture[app]['containers']['app']])
    manifest = dict(format=1, apps={}, files={}, deployment={})
    with tarfile.open(fixture['package']) as archive:
        administrator = root / 'waf-admin'
        administrator.write_bytes(archive.extractfile('usr/lib/openwaf/waf-admin').read())
        administrator.chmod(0o755)
    backup = run([administrator, 'backup', '-config', root / 'state/policy.json',
                  '-event-db', root / 'state/events.db', '-collector-db', root / 'state/collector.db',
                  '-binary', root / 'waf-server', '-admin-token-file', root / 'admin-token',
                  '-out', stage / 'waf']).stdout
    (stage / 'waf-backup-report.json').write_text(backup)
    run([administrator, 'verify', '-backup', stage / 'waf'])
    for name in ('admin-token', 'event-token'):
        shutil.copyfile(root / name, stage / name)
        (stage / name).chmod(0o600)
        manifest['deployment'][name] = digest(stage / name)
    images = []
    for app in APPS:
        source = fixture[app]['containers']
        db, application = inspect(source['db']), inspect(source['app'])
        assert application['State']['Running'] is False
        assert db['Config']['Labels']['openwaf.qualification'] == fixture[app]['tag']
        assert application['Config']['Labels']['openwaf.qualification'] == fixture[app]['tag']
        database_dump(source['db'], stage / (app + '.sql'))
        database_dump(source['db'], stage / (app + '.data.sql'), 'data')
        database_dump(source['db'], stage / (app + '.schema.sql'), 'schema')
        run(['docker', 'stop', source['db']])
        image_tag = prefix(root) + '-' + app + ':checkpoint'
        assert run(['docker', 'image', 'inspect', image_tag], check=False).returncode != 0
        snapshot_image = run(['docker', 'commit', source['app'], image_tag]).stdout.strip()
        assert snapshot_image != application['Image'] and re.fullmatch(r'sha256:[a-f0-9]{64}', snapshot_image)
        images.extend([image_tag, db['Image']])
        environment_file(stage / (app + '-app.env'), application['Config']['Env'])
        environment_file(stage / (app + '-db.env'), db['Config']['Env'])
        volumes = []
        for index, mount in enumerate(application['Mounts']):
            assert mount['Type'] == 'volume' and mount['RW']
            destination = mount['Destination']
            assert destination in ['/var/www/documents', '/var/www/html/custom']
            name = app + '-volume-' + str(index) + '.tar'
            transfer(['docker', 'cp', '-a', source['app'] + ':' + destination + '/.', '-'], stage / name)
            inventory = volume_inventory(stage / name)
            save(stage / (name + '.inventory.json'), inventory)
            volumes.append(dict(path=destination, archive=name, inventory_sha256=inventory['sha256'],
                                bytes=inventory['bytes'], entries=len(inventory['entries'])))
        manifest['apps'][app] = dict(source=source, source_image=application['Image'],
            snapshot_image=snapshot_image, snapshot_tag=image_tag, database_image=db['Image'],
            data_sha256=digest(stage / (app + '.data.sql')),
            schema_sha256=digest(stage / (app + '.schema.sql')), volumes=volumes)
    run(['docker', 'image', 'save', '--output', stage / 'images.private.tar', *dict.fromkeys(images)], timeout=900)
    (stage / 'images.private.tar').chmod(0o600)
    for app in APPS:
        run(['docker', 'image', 'rm', manifest['apps'][app]['snapshot_tag']])
        assert run(['docker', 'image', 'inspect', manifest['apps'][app]['snapshot_image']], check=False).returncode != 0
    for path in sorted(stage.rglob('*')):
        if path.is_file():
            path.chmod(0o600)
            manifest['files'][path.relative_to(stage).as_posix()] = dict(sha256=digest(path), bytes=path.stat().st_size)
    save(stage / 'manifest.private.json', manifest)
    stage.rename(target)
    return dict(manifest_sha256=digest(target / 'manifest.private.json'),
                files=len(manifest['files']), bytes=sum(v['bytes'] for v in manifest['files'].values()),
                images_evicted=True, applications={app:{k:v for k,v in value.items() if k != 'source'}
                                                 for app,value in manifest['apps'].items()})


def verify_checkpoint(root, expected):
    checkpoint = root / 'business-checkpoint'
    assert re.fullmatch(r'[a-f0-9]{64}', expected)
    assert digest(checkpoint / 'manifest.private.json') == expected
    manifest = json.loads((checkpoint / 'manifest.private.json').read_text())
    assert manifest['format'] == 1 and set(manifest['apps']) == set(APPS)
    for name, facts in manifest['files'].items():
        member_path(name)
        path = checkpoint / name
        assert path.resolve().is_relative_to(checkpoint.resolve()) and path.is_file() and not path.is_symlink()
        assert path.stat().st_size == facts['bytes'] and digest(path) == facts['sha256']
    return checkpoint, manifest


def restore(root, fixture, expected, fresh_host=False):
    import pwd
    from m4_business_guest import wait
    backup, manifest = verify_checkpoint(root, expected)
    if fresh_host:
        preconditions = json.loads((root / 'fresh-host-preconditions.json').read_text())
        assert preconditions['clean_os'] and preconditions['empty_docker']
        assert preconditions['machine_id'] == digest('/etc/machine-id')
        assert preconditions['machine_id'] != preconditions['source_machine_id']
        assert preconditions['checkpoint_sha256'] == expected
    restored = root / 'recovered-waf'
    if restored.exists():
        raise RuntimeError('recovery destination already exists')
    for app in APPS:
        for kind in ('app', 'db'):
            assert run(['docker', 'inspect', prefix(root) + '-' + app + '-' + kind], check=False).returncode != 0
    run(['docker', 'image', 'load', '--input', backup / 'images.private.tar'], timeout=900)
    result = dict(applications={}, source_containers_stopped=not fresh_host,
                  source_containers_absent=fresh_host)
    for app in APPS:
        spec = manifest['apps'][app]
        assert json.loads(run(['docker', 'image', 'inspect', spec['snapshot_image']]).stdout)[0]['Id'] == spec['snapshot_image']
        if fresh_host:
            assert all(run(['docker', 'inspect', name], check=False).returncode != 0
                       for name in spec['source'].values())
        else:
            assert all(not inspect(name)['State']['Running'] for name in spec['source'].values())
        network = prefix(root) + '-' + app + '-net'
        run(['docker', 'network', 'create', '--internal', '--label', 'jiro.recovery=' + prefix(root), network])
        names = {kind:prefix(root) + '-' + app + '-' + kind for kind in ('db', 'app')}
        common = ['--label', 'jiro.recovery=' + prefix(root), '--network', network,
                  '--security-opt', 'no-new-privileges', '--pids-limit', '256', '--cgroup-parent', 'jiro-m4.slice']
        volume = names['db'] + '-data'
        run(['docker', 'volume', 'create', '--label', 'jiro.recovery=' + prefix(root), volume])
        run(['docker', 'create', '--name', names['db'], *common, '--network-alias', 'db',
             '--memory', '512m', '--env-file', backup / (app + '-db.env'),
             '--mount', 'type=volume,source=' + volume + ',target=/var/lib/mysql,volume-nocopy', spec['database_image']])
        run(['docker', 'start', names['db']])
        await_database(names['db'])
        transfer(['docker', 'exec', '-i', names['db'], 'sh', '-c',
                  'exec mariadb -uroot -p"$MARIADB_ROOT_PASSWORD"'], backup / (app + '.sql'), reading=True,
                  errors_path=root / (app + '-restore-db.stderr.private.log'))
        database_dump(names['db'], root / (app + '-restored.data.sql'), 'data')
        database_dump(names['db'], root / (app + '-restored.schema.sql'), 'schema')
        assert digest(root / (app + '-restored.data.sql')) == spec['data_sha256'], 'restored business rows differ'
        assert digest(root / (app + '-restored.schema.sql')) == spec['schema_sha256'], 'restored business schema differs'
        mounts = []
        for index, mount in enumerate(spec['volumes']):
            name = names['app'] + '-volume-' + str(index)
            run(['docker', 'volume', 'create', '--label', 'jiro.recovery=' + prefix(root), name])
            mounts.extend(['--mount', 'type=volume,source=' + name + ',target=' + mount['path'] + ',volume-nocopy'])
        origin = ('http://erp.joint.test:' if app == 'dolibarr' else 'shop.joint.test:') + str(fixture['ports']['proxy'])
        origin_variable = 'DOLI_URL_ROOT' if app == 'dolibarr' else 'PS_DOMAIN'
        run(['docker', 'create', '--name', names['app'], *common, '--network-alias', 'app',
             '--memory', '1024m', '--env-file', backup / (app + '-app.env'),
             '--env', origin_variable + '=' + origin, *mounts, spec['snapshot_image']])
        volumes = []
        for index, mount in enumerate(spec['volumes']):
            volume = names['app'] + '-volume-' + str(index)
            restore_volume(spec['snapshot_image'], volume, backup / mount['archive'], prefix(root),
                           root / (mount['archive'] + '-restore.stderr.private.log'))
            path = root / (mount['archive'] + '.restored.tar')
            transfer(['docker', 'cp', '-a', names['app'] + ':' + mount['path'] + '/.', '-'], path)
            inventory = volume_inventory(path)
            assert inventory['sha256'] == mount['inventory_sha256'], 'restored volume differs'
            save(root / (mount['archive'] + '.restored.inventory.json'), inventory)
            volumes.append(dict(path=mount['path'], inventory_sha256=inventory['sha256'],
                                entries=len(inventory['entries']), bytes=inventory['bytes']))
        run(['docker', 'start', names['app']])
        info = inspect(names['app'])
        assert set(info['NetworkSettings']['Networks']) == {network} and not info['HostConfig']['PortBindings']
        address = info['NetworkSettings']['Networks'][network]['IPAddress']
        relay(fixture[app]['units']['relay'], fixture[app]['ports']['app'], address)
        wait('http://127.0.0.1:' + str(fixture[app]['ports']['app']) + '/', 300, names['app'])
        result['applications'][app] = dict(containers=names, network=network,
            image=info['Image'], data_sha256=spec['data_sha256'],
            schema_sha256=spec['schema_sha256'], volumes=volumes)
    run([root / 'waf-admin', 'restore', '-backup', backup / 'waf', '-out', restored])
    restored.chmod(0o755)
    identity = pwd.getpwnam('openwaf')
    os.chown(restored, 0, identity.pw_gid)
    restored.chmod(0o750)
    os.chown(restored / 'bin', 0, identity.pw_gid)
    (restored / 'bin').chmod(0o750)
    os.chown(restored / 'bin/waf-server', 0, identity.pw_gid)
    (restored / 'bin/waf-server').chmod(0o750)
    for path in [restored / 'state', *(restored / 'state').rglob('*')]:
        os.chown(path, identity.pw_uid, identity.pw_gid)
    deployment = root / 'recovered-deployment'
    deployment.mkdir(mode=0o700)
    for name in ('admin-token', 'event-token'):
        shutil.copyfile(backup / name, deployment / name)
        (deployment / name).chmod(0o600)
        assert digest(deployment / name) == manifest['deployment'][name]
    shutil.copyfile(backup / 'runtime/event-collector', restored / 'event-collector')
    os.chown(restored / 'event-collector', 0, identity.pw_gid)
    (restored / 'event-collector').chmod(0o750)
    assert digest(restored / 'bin/waf-server') == fixture['server_sha256']
    run(['runuser', '-u', 'openwaf', '--', 'test', '-x', restored / 'bin/waf-server'])
    run(['runuser', '-u', 'openwaf', '--', 'test', '-r', restored / 'state/policy.json'])
    for kind in ('gateway', 'collector'):
        text = (backup / 'services' / kind).read_text()
        if fresh_host:
            text = text.replace(fixture['recovery_source_root'], str(root))
            text = text.replace(fixture['recovery_source_tag'], root.name.rsplit('-', 1)[1])
        text = text.replace(str(root / 'state'), str(restored / 'state'))
        text = text.replace(str(root / 'waf-server'), str(restored / 'bin/waf-server'))
        text = text.replace(str(root / 'event-collector'), str(restored / 'event-collector'))
        for name in ('admin-token', 'event-token'):
            text = text.replace(str(root / name), str(deployment / name))
        Path('/etc/systemd/system', fixture['units'][kind]).write_text(text)
    run(['systemctl', 'daemon-reload'])
    run(['systemctl', 'start', fixture['units']['collector'], fixture['units']['gateway']])
    pid = await_executable(fixture['units']['gateway'], restored / 'bin/waf-server', fixture['server_sha256'])
    result.update(server_sha256=digest(restored / 'bin/waf-server'),
                  running_executable=str(Path(f'/proc/{pid}/exe').resolve()),
                  policy_sha256=digest(restored / 'state/policy.json'))
    save(root / 'business-restoration.json', result)
    return result


def files(root, fixture, payload):
    restored = json.loads((root / 'business-restoration.json').read_text())
    app = restored['applications']['dolibarr']['containers']['app']
    assert inspect(app)['Config']['Labels']['jiro.recovery'] == prefix(root)
    helper = Path(payload['sources']) / 'm4_joint_files.php'
    assert helper.parent == Path('/tmp', root.name)
    run(['docker', 'cp', helper, app + ':/tmp/openwaf-joint-files.php'])
    result = subprocess.run(['docker', 'exec', '-i', '-u', 'www-data', app, 'php', '/tmp/openwaf-joint-files.php'],
                            input=json.dumps(dict(files=payload['files'])), capture_output=True, text=True, timeout=120)
    assert result.returncode == 0
    return json.loads(result.stdout.split('OPENWAF_FILES:')[1])


def capture(root, fixture):
    import pwd
    run(['systemctl', 'stop', fixture['units']['gateway'], fixture['units']['collector']])
    restored = root / 'recovered-waf/state'
    target = root / 'business-recovery.private.tar'
    assert not target.exists()
    with tarfile.open(target, 'w') as archive:
        archive.add(root / 'business-checkpoint', arcname='checkpoint')
        archive.add(restored, arcname='restored/waf-state')
        archive.add(root / 'recovered-deployment', arcname='restored/deployment')
        archive.add(root / 'recovered-waf/bin/waf-server', arcname='restored/runtime/waf-server')
        archive.add(root / 'recovered-waf/event-collector', arcname='restored/runtime/event-collector')
        for kind in ('gateway', 'collector'):
            archive.add(Path('/etc/systemd/system', fixture['units'][kind]), arcname='restored/' + kind + '.service')
        for app in APPS:
            archive.add(root / (app + '-restored.data.sql'), arcname='restored/' + app + '.data.sql')
            archive.add(root / (app + '-restored.schema.sql'), arcname='restored/' + app + '.schema.sql')
        for path in root.glob('*.restored.inventory.json'):
            archive.add(path, arcname='restored/' + path.name)
        for path in root.glob('*.restored.tar'):
            archive.add(path, arcname='restored/' + path.name)
        archive.add(root / 'business-restoration.json', arcname='restored/result.json')
    target.chmod(0o600)
    identity = pwd.getpwnam('qualifier')
    os.chown(target, identity.pw_uid, identity.pw_gid)
    return dict(sha256=digest(target), bytes=target.stat().st_size)


def cleanup(root, fixture):
    run(['systemctl', 'stop', fixture['units']['gateway'], fixture['units']['collector']])
    stopped = []
    for app in APPS:
        for kind in ('app', 'db'):
            name = prefix(root) + '-' + app + '-' + kind
            if run(['docker', 'inspect', name], check=False).returncode == 0:
                assert inspect(name)['Config']['Labels']['jiro.recovery'] == prefix(root)
                run(['docker', 'stop', name])
                stopped.append(name)
        run(['docker', 'start', fixture[app]['containers']['db']])
        await_database(fixture[app]['containers']['db'])
        run(['docker', 'start', fixture[app]['containers']['app']])
        info = inspect(fixture[app]['containers']['app'])
        address = info['NetworkSettings']['Networks'][fixture[app]['tag'] + '-internal']['IPAddress']
        relay(fixture[app]['units']['relay'], fixture[app]['ports']['app'], address)
    for kind in ('gateway', 'collector'):
        original = root / 'recovery-original-units' / kind
        if original.exists():
            shutil.copyfile(original, Path('/etc/systemd/system', fixture['units'][kind]))
    run(['systemctl', 'daemon-reload'])
    return dict(clones_stopped=stopped, source_units_restored=True,
                source_containers_running=all(inspect(name)['State']['Running']
                    for app in APPS for name in fixture[app]['containers'].values()))


def main():
    if not __debug__:
        raise RuntimeError('recovery qualification requires assertions')
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('operation', choices=['checkpoint', 'restore', 'files', 'capture', 'cleanup'])
    parser.add_argument('--root', type=Path, required=True)
    args = parser.parse_args()
    root = args.root
    assert os.geteuid() == 0 and re.fullmatch(r'/var/lib/owaf-joint-[a-f0-9]{8}', str(root))
    assert root.resolve() == root
    fixture = json.loads((root / 'fixture.private.json').read_text())
    assert owned_lab_environment.environment(fixture) == 'wsl2'
    owned_lab_environment.allocation()
    os.umask(0o077)
    payload = json.load(sys.stdin) if args.operation in ['restore', 'files'] else None
    if args.operation == 'restore':
        value = restore(root, fixture, payload['manifest_sha256'])
    elif args.operation == 'files':
        value = files(root, fixture, payload)
    else:
        value = globals()[args.operation](root, fixture)
    print(json.dumps(value))


if __name__ == '__main__':
    main()
