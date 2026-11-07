"""Owned source-bound relays; no forwarded-header trust is enabled."""
import argparse
import json
from pathlib import Path
import re
import subprocess


def command(args,check=True):
    p=subprocess.run([str(x) for x in args],capture_output=True,text=True,timeout=60)
    if check and p.returncode:raise RuntimeError('owned fair-lab command failed: '+str(args[0]))
    return p.stdout.strip()


def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('operation',choices=['setup','stop'])
    p.add_argument('--root',type=Path,required=True);a=p.parse_args();root=a.root
    assert re.fullmatch(r'/var/lib/owaf-joint-[a-f0-9]{8}',str(root))
    assert command(['systemd-detect-virt','--vm'])=='oracle'
    f=json.loads((root/'fixture.private.json').read_text());path=root/'fair-lanes.json'
    if a.operation=='stop':
        if path.exists():
            for lane in json.loads(path.read_text()).values():command(['systemctl','stop',lane['unit']],False)
        print(json.dumps(dict(stopped=True)));return
    lanes=json.load(__import__('sys').stdin)
    expected={'upload':'127.0.0.2','storefront':'127.0.0.3','attacker':'127.0.0.10','second-attacker':'127.0.0.11'}
    assert set(lanes)==set(expected) and not path.exists()
    assert len({v['port'] for v in lanes.values()})==len(lanes)
    for name,lane in lanes.items():
        assert lane['peer']==expected[name] and 1024<=lane['port']<=65535
        assert lane['port'] not in f['ports'].values()
        assert lane.get('max_children',16) in [16,64]
        lane['unit']='owaf-fair-'+root.name.rsplit('-',1)[1]+'-'+name+'.service'
    path.write_text(json.dumps(lanes));path.chmod(0o600)
    for lane in lanes.values():
        children=lane.get('max_children',16)
        command(['systemd-run','--collect','--unit='+lane['unit'],'--property=DynamicUser=yes',
                 '--property=MemoryMax='+str(64 if children==16 else 128)+'M','--property=TasksMax=256','/usr/bin/socat',
                 'TCP-LISTEN:'+str(lane['port'])+',bind=127.0.0.1,reuseaddr,fork,max-children='+str(children),
                 'TCP:127.0.0.1:'+str(f['ports']['proxy'])+',bind='+lane['peer']])
    # Account all relay children through their service cgroups. The legacy
    # "containers" sample map also carries these explicitly named auxiliaries.
    command(['systemctl','stop',f['units']['monitor']])
    measurement=root/'measurement.json';m=json.loads(measurement.read_text())
    for name,lane in lanes.items():
        group=command(['systemctl','show',lane['unit'],'-p','ControlGroup','--value'])
        assert group.startswith('/system.slice/owaf-fair-')
        m['cgroups']['source-relay-'+name]='/sys/fs/cgroup'+group
    measurement.write_text(json.dumps(m));measurement.chmod(0o600)
    command(['systemd-run','--collect','--unit='+f['units']['monitor'],'--property=MemoryMax=128M',
             '/usr/bin/python3',root.__str__().replace('/var/lib/owaf-joint-','/tmp/owaf-joint-')+'/m4_joint_business_guest.py',
             'monitor','--root',root,'--sources',str(root).replace('/var/lib/','/tmp/')])
    print(json.dumps(lanes))


if __name__=='__main__':main()
