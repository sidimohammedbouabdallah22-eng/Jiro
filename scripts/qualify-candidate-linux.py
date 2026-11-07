"""Linux-native unit/vet/CRS qualification of an immutable packaged candidate.

Invoke inside WSL with the pinned Linux Go toolchain on PATH.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess
import tarfile
import time


def main():
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('candidate',type=Path);args=parser.parse_args()
    stage=args.candidate.resolve(strict=True);source=stage/'source';assert stage.name.startswith('rule-candidate-')
    base=json.loads((stage/'result.json').read_text());assert base['passed']
    package=stage/'openwaf-rule-candidate-linux-amd64.tar.gz'
    assert hashlib.sha256(package.read_bytes()).hexdigest()==Path(str(package)+'.sha256').read_text().split()[0]
    out=stage/'linux-native';out.mkdir();report=dict(passed=False,phases=[],package_sha256=hashlib.sha256(package.read_bytes()).hexdigest())
    env=os.environ.copy();env.update(CGO_ENABLED='0',GOOS='linux',GOARCH='amd64')
    with tarfile.open(package) as tar:
        for name in ['waf-server','waf-admin','event-collector']:
            path=out/name;path.write_bytes(tar.extractfile('usr/lib/openwaf/'+name).read());path.chmod(0o755)
    report['server_sha256']=hashlib.sha256((out/'waf-server').read_bytes()).hexdigest()
    def run(name,argv,cwd):
        begin=time.monotonic()
        with (out/(name+'.log')).open('w') as stream:result=subprocess.run(argv,cwd=cwd,env=env,stdout=stream,stderr=subprocess.STDOUT,timeout=1800)
        report['phases'].append(dict(name=name,exit_code=result.returncode,seconds=time.monotonic()-begin));assert result.returncode==0,name
    try:
        run('legacy-build',['go','build','-trimpath','-o',str(out/'schema1-fixture'),'.'],source/'tools/recoverycheck')
        env.update(OPENWAF_RECOVERY_CANDIDATE=str(out/'waf-server'),OPENWAF_RECOVERY_ADMIN=str(out/'waf-admin'),OPENWAF_RECOVERY_LEGACY=str(out/'schema1-fixture'))
        run('unit-integration',['go','test','-p','1','./...'],source)
        run('vet',['go','vet','./...'],source)
        run('full-crs',['go','run','.','-out',str(out/'crs-regression.json')],source/'tools/crscheck')
        corpus=json.loads((out/'crs-regression.json').read_text());assert corpus['Total']==corpus['Passed'] and all(corpus[key]==0 for key in ['Failed','Errors','Skipped','Ignored'])
        report['corpus']={key:corpus[key] for key in ['Total','Passed','Failed','Errors','Skipped','Ignored']};report['passed']=True
    finally:
        (out/'result.json').write_text(json.dumps(report,indent=2)+'\n');print(out/'result.json',flush=True)


if __name__=='__main__':main()
