"""Run pinned DVWA, WordPress and Keycloak qualification in an owned VM."""

import argparse
import csv
import hashlib
import io
import json
import os
from pathlib import Path
import re
import secrets
import shlex
import socket
import subprocess
import tarfile
import uuid


def restrict_artifacts(path):
    """Restrict lab credentials before creating files in the artifact directory."""
    if os.name == 'nt':
        identity = subprocess.run(['whoami', '/user', '/fo', 'csv', '/nh'],
                                  check=True, capture_output=True, text=True).stdout
        sid = next(csv.reader(io.StringIO(identity)))[1]
        subprocess.run(['icacls', str(path), '/inheritance:r', '/grant:r',
                        '*' + sid + ':(OI)(CI)F', '*S-1-5-18:(OI)(CI)F'],
                       check=True, capture_output=True)
    else:
        path.chmod(0o700)


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--vm-dir',type=Path)
    parser.add_argument('--package',type=Path)
    parser.add_argument('--fixture',type=Path,help='Reuse a prepared private lab fixture')
    parser.add_argument('--prepare-only',action='store_true')
    parser.add_argument('--disposable-vm',action='store_true',required=True)
    args=parser.parse_args()
    if args.fixture and args.package:
        parser.error('a reused fixture keeps its original binary; use a fresh fixture for another package')
    repo=Path(__file__).resolve().parents[1]
    if args.fixture:
        private=args.fixture.resolve(strict=True)
        if (repo/'artifacts').resolve() not in private.parents:
            raise ValueError('fixture must be a private qualification artifact')
        fixture=json.loads(private.read_text())
        vm=Path(fixture['vm_dir']).resolve(strict=True)
        out=private.parent
    else:
        if not args.vm_dir or not args.package:
            parser.error('supply --vm-dir and --package, or --fixture')
        vm=args.vm_dir.resolve(strict=True)
        tag=uuid.uuid4().hex[:8]
        out=repo/'artifacts'/('m4-lab-'+tag)
        out.mkdir()
        private=out/'fixture.private.json'
        listeners=[socket.socket() for _ in range(5)]
        for listener in listeners:
            listener.bind(('127.0.0.1',0))
        ports=dict(zip(['admin','proxy','dvwa','wordpress','keycloak'],[s.getsockname()[1] for s in listeners]))
        for listener in listeners:
            listener.close()
        fixture=dict(tag='owaf-m4-'+tag,root='/var/lib/owaf-m4-'+tag,ports=ports,
            vm_dir=str(vm),token=secrets.token_hex(32),password=secrets.token_urlsafe(24),
            db_password=secrets.token_hex(24),otp_secret=secrets.token_urlsafe(15),subject=str(uuid.uuid4()),
            images={name:entry['image'] for name,entry in json.loads((repo/'tools/application-check/images.lock.json').read_text()).items()})
        fixture.update(admin_origin=f"http://localhost:{ports['admin']}",
            wordpress_origin=f"http://localhost:{ports['proxy']}",dvwa_origin=f"http://127.0.0.1:{ports['proxy']}",
            idp_origin=f"http://localhost:{ports['keycloak']}")
    if vm.parent!=(repo/'artifacts/m2-vms').resolve() or not re.fullmatch(r'openwaf-m2-24\.04-[a-f0-9]{8}',vm.name):
        raise ValueError('requires an owned Ubuntu 24.04 qualification VM')
    if not json.loads((vm/'result.json').read_text())['passed']:
        raise ValueError('VM has no passing baseline')
    if not re.fullmatch(r'owaf-m4-[a-f0-9]{8}',fixture['tag']):
        raise ValueError('invalid fixture namespace')
    restrict_artifacts(out)
    if args.fixture and not args.prepare_only and (out/'results.json').exists():
        raise ValueError('preserve the existing report; create a fresh fixture for qualification')
    sources=['tools/application-check/check.cjs','tools/application-check/images.lock.json',
        'scripts/m4_guest.py','scripts/m4_idp.py','scripts/qualify-applications.py','scripts/pilot.py']
    source_hashes={name:hashlib.sha256((repo/name).read_bytes()).hexdigest() for name in sources}
    if not args.fixture:
        for name in sources:
            target=out/'source'/name;target.parent.mkdir(parents=True,exist_ok=True);target.write_bytes((repo/name).read_bytes())
    def verify_sources():
        if any(hashlib.sha256((repo/name).read_bytes()).hexdigest()!=digest for name,digest in source_hashes.items()):
            raise RuntimeError('qualification source changed during this run')
    log=(out/'commands.log').open('a',encoding='utf-8')
    def execute(arguments,data=None,check=True,timeout=900):
        result=subprocess.run([str(value) for value in arguments],input=data,capture_output=True,
            text=True,encoding='utf-8',errors='replace',timeout=timeout)
        if result.stderr:
            log.write(result.stderr)
            log.flush()
        if check and result.returncode:
            raise RuntimeError(f'{Path(arguments[0]).name} failed, inspect commands.log')
        return result.stdout
    vbox=r'C:\Program Files\Oracle\VirtualBox\VBoxManage.exe'
    info=execute([vbox,'showvminfo',vm.name,'--machinereadable'])
    if 'VMState="running"' not in info:
        raise ValueError('start the owned guest before qualification')
    ssh_port=int(re.search(r'Forwarding\(0\)="ssh,tcp,127\.0\.0\.1,(\d+),,22"',info)[1])
    options=['-i',str(vm/'identity'),'-o','BatchMode=yes','-o','ConnectTimeout=5','-o',f'UserKnownHostsFile={vm / "known_hosts"}']
    ssh=['ssh',*options,'-p',str(ssh_port),'qualifier@127.0.0.1']
    tunnel=None
    prepared=bool(args.fixture)
    setup_started=False
    completed=False
    try:
        if not args.fixture:
            package=args.package.resolve(strict=True)
            expected=Path(str(package)+'.sha256').read_text().split()[0]
            if hashlib.sha256(package.read_bytes()).hexdigest()!=expected:
                raise ValueError('package checksum mismatch')
            with tarfile.open(package) as archive:
                member=archive.getmember('usr/lib/openwaf/waf-server')
                if not member.isfile() or member.size>256<<20: raise ValueError('invalid server archive member')
                expected_server=hashlib.sha256(archive.extractfile(member).read()).hexdigest()
            execute(['scp',*options,'-P',str(ssh_port),repo/'scripts/m4_guest.py',package,'qualifier@127.0.0.1:/tmp/'])
            command=['sudo','python3','/tmp/m4_guest.py','setup','--root',fixture['root'],'--package','/tmp/'+package.name]
            fixture['package_sha256']=expected
            private.write_text(json.dumps(fixture,indent=2)+'\n')
            private.chmod(0o600)
            setup_started=True
            fixture=json.loads(execute([*ssh,shlex.join(command)],json.dumps(fixture)))
            if fixture['server_sha256']!=expected_server:
                raise ValueError('guest server differs from selected host archive')
            fixture['package_sha256']=expected
            private.write_text(json.dumps(fixture,indent=2)+'\n')
            private.chmod(0o600)
            prepared=True
        else:
            execute([*ssh,shlex.join(['sudo','python3',fixture['root']+'/guest.py','start','--root',fixture['root']])])
        # The same loopback ports are used in guest and host for issuer/origin identity.
        forwarding=[]
        for port in fixture['ports'].values():
            forwarding.extend(['-L',f'127.0.0.1:{port}:127.0.0.1:{port}'])
        tunnel=subprocess.Popen([*ssh[:-1],'-N','-o','ExitOnForwardFailure=yes',*forwarding,ssh[-1]],stdout=log,stderr=log)
        if not args.prepare_only:
            print('Running real-product browser and API qualification',flush=True)
            verify_sources()
            output=execute(['node',repo/'tools/application-check/check.cjs',private],timeout=1200)
            verify_sources()
            log.write(output)
        print(private,flush=True)
        completed=True
    finally:
        try:
            if (prepared or setup_started) and not (args.prepare_only and completed):
                helper=fixture['root']+'/guest.py' if prepared else '/tmp/m4_guest.py'
                execute([*ssh,shlex.join(['sudo','python3',helper,'stop','--root',fixture['root']])],check=False,timeout=90)
        finally:
            if tunnel and tunnel.poll() is None:
                tunnel.terminate()
                tunnel.wait(timeout=15)
            log.close()


if __name__=='__main__':
    main()
