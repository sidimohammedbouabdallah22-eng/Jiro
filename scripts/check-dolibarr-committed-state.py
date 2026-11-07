"""Independently read business rows/files after stopped capacity measurements."""
import argparse
import hashlib
import json
from pathlib import Path
import re
import shlex
import subprocess
import time


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--fixture',type=Path,required=True);parser.add_argument('--workflow-report',type=Path,required=True)
    parser.add_argument('--capacity-report',type=Path,required=True);parser.add_argument('--disposable-vm',required=True,action='store_true')
    parser.add_argument('--keep-vm-running',action='store_true')
    args=parser.parse_args();repo=Path(__file__).resolve().parents[1]
    f=json.loads(args.fixture.read_text());workflow=json.loads(args.workflow_report.read_text());capacity=json.loads(args.capacity_report.read_text())
    assert f['app']=='dolibarr' and workflow['passed'] and capacity['passed']
    assert re.fullmatch(r'owaf-business-[a-f0-9]{8}',f['tag'])
    assert f['containers']=={name:f['tag']+'-'+name for name in ['db','app']}
    tag=re.fullmatch(r'm4-business-capacity-([a-f0-9]{8})',args.capacity_report.parent.name)[1]
    cases={case['name']:case for case in workflow['cases']}
    spec=dict(customer=cases['create, read and edit Unicode customer']['customer_id'],
              invoice=cases['create, price and validate invoice']['invoice_id'],
              contact=cases['contact creation persists Unicode fields and reader cannot create contacts']['contact_id'],
              order=cases['sales order lines and validation persist correct totals']['order_id'],
              imported=cases['native CSV multipart import simulates without commit then imports exact customer']['customer_id'],
              attachment_bytes=cases['native customer multipart attachment round trips exact bytes']['bytes'],
              attachment_sha256=cases['native customer multipart attachment round trips exact bytes']['sha256'],capacity_tag=tag)
    vm=Path(f['vm_dir']);assert vm.parent.resolve()==(repo/'artifacts/m2-vms').resolve()
    vbox=r'C:\Program Files\Oracle\VirtualBox\VBoxManage.exe'
    def run(argv,data=None,check=True):
        result=subprocess.run([str(x) for x in argv],input=data,capture_output=True,text=True,timeout=180)
        if check and result.returncode:raise RuntimeError('read-only business verification failed')
        return result
    info=run([vbox,'showvminfo',vm.name,'--machinereadable']).stdout
    port=re.search(r'Forwarding\(0\)="ssh,tcp,127\.0\.0\.1,(\d+),,22"',info)[1]
    opts=['-i',vm/'identity','-o','BatchMode=yes','-o','ConnectTimeout=5','-o','ServerAliveInterval=5','-o','ServerAliveCountMax=3','-o','UserKnownHostsFile='+str(vm/'known_hosts')]
    ssh=['ssh',*opts,'-p',port,'qualifier@127.0.0.1'];source=repo/'scripts/m4_verify_dolibarr_state.php'
    report=dict(passed=False)
    try:
        if 'VMState="poweroff"' in info:run([vbox,'startvm',vm.name,'--type','headless'])
        for _ in range(90):
            if run([*ssh,'true'],check=False).returncode==0:break
            time.sleep(2)
        else:raise RuntimeError('SSH unavailable')
        run([*ssh,"sudo systemctl stop openwaf.service $(systemctl show openwaf.service -p Requires --value | tr ' ' '\n' | sed -n '/^openwaf-m2-.*[.]service$/p')"])
        run([*ssh,shlex.join(['sudo','docker','start',*f['containers'].values()])])
        run(['scp',*opts,'-P',port,source,'qualifier@127.0.0.1:/tmp/m4_verify_dolibarr_state.php'])
        run([*ssh,shlex.join(['sudo','docker','cp','/tmp/m4_verify_dolibarr_state.php',f['containers']['app']+':/tmp/openwaf-verify-state.php'])])
        # Readiness is established through the DB, not a fixed startup delay.
        for _ in range(60):
            ready=run([*ssh,shlex.join(['sudo','docker','exec',f['containers']['db'],'sh','-c','mariadb -uroot -p"$MARIADB_ROOT_PASSWORD" -e "SELECT 1"'])],check=False)
            if ready.returncode==0:break
            time.sleep(1)
        result=run([*ssh,shlex.join(['sudo','docker','exec','-i','-u','www-data',f['containers']['app'],'php','/tmp/openwaf-verify-state.php'])],json.dumps(spec)).stdout
        report=json.loads(result.split('OPENWAF_STATE_RESULT:')[1]);assert report['passed'] and report['version']==f['image']['version']
        report.update(workflow_sha256=hashlib.sha256(args.workflow_report.read_bytes()).hexdigest(),capacity_report_sha256=hashlib.sha256(args.capacity_report.read_bytes()).hexdigest(),php_sha256=hashlib.sha256(source.read_bytes()).hexdigest())
    finally:
        run([*ssh,shlex.join(['sudo','docker','stop',*f['containers'].values()])],check=False)
        if not args.keep_vm_running:run([*ssh,'sudo poweroff'],check=False)
        out=args.capacity_report.parent
        attempt=1
        while (out/f'committed-business-state-{attempt}.json').exists():attempt+=1
        (out/f'committed-business-state-{attempt}.json').write_text(json.dumps(report,indent=2)+'\n')
        (out/'source/m4_verify_dolibarr_state.php').write_bytes(source.read_bytes())
        (out/'source/check-dolibarr-committed-state.py').write_bytes(Path(__file__).read_bytes())
    print(json.dumps(report,indent=2))


if __name__=='__main__':main()
