"""Run bounded deployed fault/alert drills in an explicitly owned VirtualBox VM."""
import argparse
import hashlib
import importlib.util
import json
from pathlib import Path
import re
import shlex
import subprocess
import tarfile
import time
import uuid


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--vm',required=True)
    parser.add_argument('--package',type=Path,required=True)
    parser.add_argument('--disposable-vm',required=True,action='store_true')
    args=parser.parse_args();repo=Path(__file__).resolve().parents[1]
    assert re.fullmatch(r'openwaf-m2-24\.04-[a-f0-9]{8}',args.vm)
    package=args.package.resolve(strict=True);package_sha=hashlib.sha256(package.read_bytes()).hexdigest()
    assert package_sha==Path(str(package)+'.sha256').read_text().split()[0]
    with tarfile.open(package) as tar: server_sha=hashlib.sha256(tar.extractfile('usr/lib/openwaf/waf-server').read()).hexdigest()
    tag=uuid.uuid4().hex[:8];out=repo/'artifacts'/('m4-alerts-'+tag);out.mkdir()
    spec=importlib.util.spec_from_file_location('permissions',repo/'scripts/qualify-applications.py')
    permissions=importlib.util.module_from_spec(spec);spec.loader.exec_module(permissions);permissions.restrict_artifacts(out)
    source=out/'source';source.mkdir();hashes={}
    for relative in ['scripts/qualify-m4-alerts.py','scripts/m4_alert_drill_guest.py','scripts/m4_alert_receiver.py','scripts/m2_guest.py','scripts/pilot.py','scripts/pilot_alerts.py','deploy/linux/openwaf-pilot.service','deploy/linux/openwaf-pilot-alerts.service']:
        path=repo/relative;data=path.read_bytes();(source/path.name).write_bytes(data);hashes[relative]=hashlib.sha256(data).hexdigest()
    report=dict(passed=False,vm=args.vm,package_sha256=package_sha,server_sha256=server_sha,sources=hashes)
    vbox=r'C:\Program Files\Oracle\VirtualBox\VBoxManage.exe'
    def run(argv,timeout=120,check=True):
        result=subprocess.run([str(x) for x in argv],capture_output=True,text=True,timeout=timeout)
        if check and result.returncode:
            (out/'failure.private.txt').write_text(result.stdout+result.stderr)
            raise RuntimeError('Qualification command failed; private details retained at '+str(out))
        return result
    def info():
        for attempt in range(60):
            result=run([vbox,'showvminfo',args.vm,'--machinereadable'],check=False)
            if result.returncode==0:return result.stdout
            time.sleep(1)
        raise RuntimeError('VM metadata unavailable')
    vm_dir=repo/'artifacts/m2-vms'/args.vm
    port=re.search(r'Forwarding\(0\)="ssh,tcp,127\.0\.0\.1,(\d+),,22"',info())[1]
    options=['-i',vm_dir/'identity','-o','BatchMode=yes','-o','ConnectTimeout=5','-o','ServerAliveInterval=5','-o','ServerAliveCountMax=3','-o','StrictHostKeyChecking=yes','-o',f'UserKnownHostsFile={vm_dir/"known_hosts"}']
    ssh=['ssh',*options,'-p',port,'qualifier@127.0.0.1'];scp=['scp',*options,'-P',port]
    root='/var/lib/owaf-m2-'+tag
    try:
        if 'VMState="poweroff"' in info():run([vbox,'startvm',args.vm,'--type','headless'])
        for attempt in range(90):
            if run([*ssh,'true'],check=False).returncode==0:break
            time.sleep(2)
        else:raise RuntimeError('SSH unavailable')
        remote_sources='/tmp/owaf-alert-sources-'+tag
        run([*ssh,'mkdir -m 700 '+remote_sources])
        run([*scp,*source.iterdir(),'qualifier@127.0.0.1:'+remote_sources+'/'])
        remote='/tmp/owaf-alert-'+tag+'.tar.gz';run([*scp,package,'qualifier@127.0.0.1:'+remote])
        print('Running deployed certificate/export/storage/monitoring fault drills',flush=True)
        result=run([*ssh,shlex.join(['sudo','python3',remote_sources+'/m4_alert_drill_guest.py','--sources',remote_sources,'--root',root,'--package',remote,'--package-sha256',package_sha,'--server-sha256',server_sha])],timeout=1000,check=False)
        (out/'guest.private.log').write_text(result.stdout+result.stderr)
        # Retrieve failure evidence too, without replacing earlier attempts.
        run([*scp,f'qualifier@127.0.0.1:{root}/fault-evidence.private.tar.gz',out/'fault-evidence.private.tar.gz'],check=False)
        assert result.returncode==0,'Guest drill failed; see private guest log'
        report['drill']=json.loads(result.stdout);assert report['drill']['passed']
        assert hashlib.sha256((out/'fault-evidence.private.tar.gz').read_bytes()).hexdigest()==report['drill']['capture_sha256']
        for relative,expected in hashes.items():assert hashlib.sha256((repo/relative).read_bytes()).hexdigest()==expected
        report['passed']=True
    finally:
        if 'VMState="running"' in info():
            run([*ssh,'sudo poweroff'],check=False)
            for attempt in range(60):
                if 'VMState="poweroff"' in info():break
                time.sleep(1)
        report['vm_powered_off']='VMState="poweroff"' in info()
        (out/'result.json').write_text(json.dumps(report,indent=2)+'\n')
        print(out/'result.json',flush=True)


if __name__=='__main__':main()
