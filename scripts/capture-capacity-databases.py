"""Copy stopped owned capacity databases into a private, reviewable evidence tar."""

import argparse
import hashlib
import json
from pathlib import Path
import re
import shlex
import subprocess


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--base-fixture",type=Path,required=True)
    parser.add_argument("--capacity-fixture",type=Path,required=True)
    args=parser.parse_args()
    repo=Path(__file__).resolve().parents[1]
    for path in (args.base_fixture,args.capacity_fixture):
        if (repo/"artifacts").resolve() not in path.resolve(strict=True).parents:
            raise ValueError("requires private qualification artifacts")
    base=json.loads(args.base_fixture.read_text())
    capacity=json.loads(args.capacity_fixture.read_text())
    root=capacity["root"]
    if not re.fullmatch(re.escape(base["root"])+r"/capacity-[a-f0-9]{8}",root):
        raise ValueError("capacity namespace mismatch")
    vm=Path(base["vm_dir"]).resolve(strict=True)
    if vm.parent!=(repo/"artifacts/m2-vms").resolve() or not re.fullmatch(r"openwaf-m2-24\.04-[a-f0-9]{8}",vm.name):
        raise ValueError("requires an owned VM")
    info=subprocess.check_output([r"C:\Program Files\Oracle\VirtualBox\VBoxManage.exe","showvminfo",vm.name,"--machinereadable"],text=True)
    if 'VMState="running"' not in info:
        raise ValueError("start the owned guest before read-only capture")
    port=re.search(r'Forwarding\(0\)="ssh,tcp,127\.0\.0\.1,(\d+),,22"',info)[1]
    # stdin carries code, not secrets. The helper refuses an active database writer.
    code="""
import json,subprocess,sys,tarfile
from pathlib import Path
root=Path(sys.argv[1])
fixture=json.loads((root/'fixture.json').read_text())
for name in ['gateway','collector']:
 state=subprocess.check_output(['systemctl','show','--property=ActiveState','--value',fixture['units'][name]],text=True).strip()
 if state!='inactive': raise RuntimeError('stop the owned writers before capture')
for name in ['events.db','collector.db']:
 if (root/'state'/name).stat().st_size>256<<20: raise RuntimeError('database exceeds profile bound')
with tarfile.open(fileobj=sys.stdout.buffer,mode='w|') as archive:
 for name in ['events.db','collector.db']:
  archive.add(root/'state'/name,arcname=name,recursive=False)
"""
    target=args.capacity_fixture.parent/"databases.tar"
    if target.exists():
        raise ValueError("capture already exists; preserve prior evidence")
    command=["ssh","-i",str(vm/"identity"),"-o","BatchMode=yes","-o","ConnectTimeout=5",
        "-o","UserKnownHostsFile="+str(vm/"known_hosts"),"-p",port,"qualifier@127.0.0.1",
        shlex.join(["sudo","python3","-",root])]
    with target.open("xb") as stream:
        result=subprocess.run(command,input=code.encode(),stdout=stream,stderr=subprocess.PIPE,timeout=90)
    if result.returncode:
        raise RuntimeError("stopped database capture failed; partial file retained")
    print(json.dumps(dict(captured=True,bytes=target.stat().st_size,sha256=hashlib.sha256(target.read_bytes()).hexdigest()),indent=2))


if __name__=="__main__":
    main()
