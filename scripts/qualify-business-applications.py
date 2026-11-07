"""Qualify pinned business products in the owned M4 VM, one product at a time."""
import argparse
import hashlib
import importlib.util
import json
from pathlib import Path
import re
import secrets
import shlex
import socket
import subprocess
import time
import uuid

REPO=Path(__file__).resolve().parents[1]
VBOX=r'C:\Program Files\Oracle\VirtualBox\VBoxManage.exe'


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--vm-dir',type=Path); p.add_argument('--package',type=Path)
    p.add_argument('--app',choices=['dolibarr','prestashop']); p.add_argument('--fixture',type=Path)
    p.add_argument('--disposable-vm',required=True,action='store_true')
    args=p.parse_args()
    if args.fixture:
        private=args.fixture.resolve(strict=True)
        if (REPO/'artifacts').resolve() not in private.parents: raise ValueError('unowned fixture')
        f=json.loads(private.read_text()); vm=Path(f['vm_dir']); out=private.parent
    else:
        if not all([args.vm_dir,args.package,args.app]): p.error('supply VM, package and app')
        vm=args.vm_dir.resolve(strict=True); tag=uuid.uuid4().hex[:8]
        out=REPO/'artifacts'/('m4-business-'+tag); out.mkdir()
        spec=importlib.util.spec_from_file_location('app_helpers',REPO/'scripts/qualify-applications.py')
        module=importlib.util.module_from_spec(spec); spec.loader.exec_module(module); module.restrict_artifacts(out)
        listeners=[socket.socket() for _ in range(4)]
        for s in listeners: s.bind(('127.0.0.1',0))
        ports=dict(zip(['admin','proxy','app','collector'],[s.getsockname()[1] for s in listeners]))
        for s in listeners: s.close()
        package=args.package.resolve(strict=True); digest=hashlib.sha256(package.read_bytes()).hexdigest()
        if digest!=Path(str(package)+'.sha256').read_text().split()[0]: raise ValueError('package checksum differs')
        f=dict(tag='owaf-business-'+tag,root='/var/lib/owaf-business-'+tag,app=args.app,vm_dir=str(vm),
            ports=ports,origin='http://localhost:'+str(ports['proxy']),package='/tmp/'+package.name,package_sha256=digest,
            token=secrets.token_hex(32),collector_token=secrets.token_hex(32),password=secrets.token_urlsafe(24),
            db_password=secrets.token_hex(24),api_key=secrets.token_hex(32),
            image=json.loads((REPO/'tools/application-check/business-images.lock.json').read_text())[args.app],
            db_image=json.loads((REPO/'tools/application-check/images.lock.json').read_text())['db']['image'])
        private=out/'fixture.private.json'; private.write_text(json.dumps(f)); private.chmod(0o600)
    vm=vm.resolve(strict=True)
    if vm.parent!=(REPO/'artifacts/m2-vms').resolve() or not re.fullmatch(r'openwaf-m2-24\.04-[a-f0-9]{8}',vm.name) or not json.loads((vm/'result.json').read_text())['passed']:
        raise ValueError('requires owned passing Ubuntu 24.04 VM')
    log=(out/'commands.log').open('a',encoding='utf-8')
    def execute(argv,data=None,timeout=900,check=True):
        r=subprocess.run([str(v) for v in argv],input=data,capture_output=True,text=True,encoding='utf-8',errors='replace',timeout=timeout)
        if r.stderr: log.write(r.stderr); log.flush()
        if check and r.returncode: raise RuntimeError(str(argv[0])+' failed; inspect private commands.log')
        return r.stdout
    info=execute([VBOX,'showvminfo',vm.name,'--machinereadable'])
    was_off='VMState="poweroff"' in info
    port=re.search(r'Forwarding\(0\)="ssh,tcp,127\.0\.0\.1,(\d+),,22"',info)[1]
    options=['-i',vm/'identity','-o','BatchMode=yes','-o','ConnectTimeout=5','-o','StrictHostKeyChecking=yes','-o','UserKnownHostsFile='+str(vm/'known_hosts')]
    ssh=['ssh',*options,'-p',port,'qualifier@127.0.0.1']
    tunnel=None; attempted=False
    attempt=1
    while (out/f'results-{attempt}.json').exists(): attempt+=1
    result_path=out/f'results-{attempt}.json'
    report=dict(passed=False,app=f['app'],package_sha256=f['package_sha256'],image=f['image'],cases=[],attempt=attempt)
    report['runtime_vm_allocation']=dict(vcpus=int(re.search(r'^cpus=(\d+)$',info,re.M)[1]),
                                         memory_mib=int(re.search(r'^memory=(\d+)$',info,re.M)[1]))
    source=out/f'source-{attempt}'; source.mkdir()
    source_inputs={}
    for name in ['scripts/qualify-business-applications.py','scripts/m4_business_guest.py','tools/application-check/business.cjs',
                 'tools/application-check/business-images.lock.json','tools/application-check/prestashop.cjs','scripts/m4_prestashop_seed.php',
                 'tools/application-check/dolibarr-access.cjs','tools/application-check/dolibarr-workflows.cjs','tools/application-check/event-oracle.cjs']:
        data=(REPO/name).read_bytes(); (source/Path(name).name).write_bytes(data)
        report.setdefault('source_sha256',{})[Path(name).name]=hashlib.sha256(data).hexdigest()
        source_inputs[name]=hashlib.sha256(data).hexdigest()
    def verify_sources():
        if any(hashlib.sha256((REPO/name).read_bytes()).hexdigest()!=digest for name,digest in source_inputs.items()):
            raise RuntimeError('qualification source changed while this run was active')
    def guest(op,data=None):
        return json.loads(execute([*ssh,shlex.join(['sudo','python3','/tmp/m4_business_guest.py',op,'--root',f['root']])],data))
    try:
        if was_off: execute([VBOX,'startvm',vm.name,'--type','headless'])
        deadline=time.monotonic()+180
        while time.monotonic()<deadline:
            if subprocess.run([str(v) for v in [*ssh,'true']],capture_output=True,timeout=10).returncode==0: break
            time.sleep(1)
        else: raise RuntimeError('SSH startup deadline exceeded')
        execute(['scp',*options,'-P',port,REPO/'scripts/m4_business_guest.py',REPO/'scripts/m4_prestashop_seed.php','qualifier@127.0.0.1:/tmp/'])
        attempted=True
        if not args.fixture:
            execute(['scp',*options,'-P',port,package,'qualifier@127.0.0.1:/tmp/'])
            print('Preparing isolated '+f['app']+' fixture',flush=True)
            f=guest('setup',json.dumps(f))
        else:
            if args.package:
                package=args.package.resolve(strict=True); digest=hashlib.sha256(package.read_bytes()).hexdigest()
                if digest!=Path(str(package)+'.sha256').read_text().split()[0]: raise ValueError('package checksum differs')
                remote='/tmp/openwaf-business-'+digest[:16]+'.tar.gz'
                execute(['scp',*options,'-P',port,package,'qualifier@127.0.0.1:'+remote])
                f=guest('activate',json.dumps(dict(package=remote,package_sha256=digest)))
                private.write_text(json.dumps(f)); private.chmod(0o600)
            guest('start')
        print('Seeding application and checking installed version',flush=True)
        seeded=guest('seed'); f['installed_version']=seeded['version']
        for key in ['product_id','customer_id','routes','reader_api_key','reader_id']:
            if key in seeded: f[key]=seeded[key]
        private.write_text(json.dumps(f)); private.chmod(0o600)
        forwarding=[]
        for v in f['ports'].values(): forwarding+=['-L',f'127.0.0.1:{v}:127.0.0.1:{v}']
        tunnel=subprocess.Popen([str(v) for v in [*ssh[:-1],'-N','-o','ExitOnForwardFailure=yes',*forwarding,ssh[-1]]],stdout=log,stderr=log)
        time.sleep(1)
        print('Testing authenticated workflows through enforcing CRS',flush=True)
        verify_sources()
        execute(['node',REPO/'tools/application-check/business.cjs',private,result_path],timeout=900)
        verify_sources()
        allocation=report['runtime_vm_allocation']
        report=json.loads(result_path.read_text()); report.update(environment=f['environment'],image_metadata=f['image_metadata'],installed_version=f['installed_version'],runtime_vm_allocation=allocation)
        for key in ['installation_network','translation_assets']:
            if key in f: report[key]=f[key]
        evidence=guest('report'); report['delivery']=evidence
        if not evidence['identical_ids_and_payloads']: raise RuntimeError('event delivery differs')
        report['passed']=True
    except Exception as error:
        if result_path.exists(): report.update(json.loads(result_path.read_text()))
        report['passed']=False; report['error']=type(error).__name__+': '+str(error)
        raise
    finally:
        report['attempt']=attempt
        report.setdefault('source_sha256',{})
        for file in source.iterdir(): report['source_sha256'][file.name]=hashlib.sha256(file.read_bytes()).hexdigest()
        result_path.write_text(json.dumps(report,indent=2))
        if attempted:
            try: report['cleanup']=guest('stop')
            except Exception: report['cleanup']=dict(stopped=False)
        if report.get('passed') and report.get('cleanup',{}).get('stopped'):
            capture=subprocess.run([str(v) for v in [*ssh,shlex.join(['sudo','tar','-C',f['root']+'/state','-cf','-','events.db','collector.db'])]],
                capture_output=True,timeout=60)
            if capture.returncode or not capture.stdout or len(capture.stdout)>300<<20:
                report['passed']=False; report['capture_error']='database capture failed or exceeded bound'
            else:
                archive=out/f'databases-{attempt}.tar'; archive.write_bytes(capture.stdout)
                report['database_archive']=dict(file=archive.name,sha256=hashlib.sha256(capture.stdout).hexdigest())
        if tunnel: tunnel.terminate(); tunnel.wait(timeout=15)
        if was_off: execute([*ssh,'sudo poweroff'],timeout=20,check=False)
        result_path.write_text(json.dumps(report,indent=2)); log.close()
        print(result_path,flush=True)
    if not report['passed'] or not report.get('cleanup',{}).get('stopped'):
        raise RuntimeError('qualification or cleanup failed; inspect retained report')


if __name__=='__main__': main()
