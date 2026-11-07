"""Native resource and stopped-database evidence for one owned business cohort."""
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import pwd
import re
import shutil
import sqlite3
import subprocess
import sys
import tarfile
import time


def command(args):return subprocess.check_output([str(x) for x in args],text=True,stderr=subprocess.DEVNULL,timeout=120).strip()


def helper(path):
    spec=importlib.util.spec_from_file_location('business',path);module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module);return module


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('operation',choices=['start','monitor','capture','stop','mark'])
    parser.add_argument('--root',type=Path,required=True);parser.add_argument('--tag',required=True)
    parser.add_argument('--server-sha256')
    args=parser.parse_args();root=args.root
    assert os.geteuid()==0 and re.fullmatch(r'/var/lib/owaf-business-[a-f0-9]{8}',str(root))
    assert re.fullmatch(r'[a-f0-9]{8}',args.tag) and command(['systemd-detect-virt','--vm'])=='oracle'
    f=json.loads((root/'fixture.json').read_text());target=root/('capacity-'+args.tag)
    control=helper(Path(__file__).with_name('m4_business_guest.py'))
    unit='owaf-business-monitor-'+args.tag+'.service'
    if args.operation=='mark':
        print(json.dumps(dict(time=time.time(),monotonic=time.monotonic())))
    elif args.operation=='start':
        assert not target.exists() and shutil.disk_usage(root).free>1<<30
        assert hashlib.sha256((root/'waf-server').read_bytes()).hexdigest()==args.server_sha256
        control.start(f)
        running=set(command(['docker','ps','--format','{{.Names}}']).split())
        assert running==set(f['containers'].values()),'unrelated containers invalidate colocated profile'
        target.mkdir(mode=0o700)
        spec=dict(units=f['units'],cgroups={},server_sha256=args.server_sha256)
        for name,container in f['containers'].items():
            pid=int(command(['docker','inspect','--format={{.State.Pid}}',container]))
            relative=Path(f'/proc/{pid}/cgroup').read_text().strip().split('::')[1]
            group=Path('/sys/fs/cgroup'+relative).resolve();assert Path('/sys/fs/cgroup') in group.parents
            spec['cgroups'][name]=str(group)
        (target/'spec.json').write_text(json.dumps(spec))
        command(['systemd-run','--collect','--unit='+unit,'--property=MemoryMax=128M','/usr/bin/python3',Path(__file__),'monitor','--root',root,'--tag',args.tag])
        print(json.dumps(dict(cpus=os.cpu_count(),memory_kib=int(re.search(r'MemTotal:\s+(\d+)',Path('/proc/meminfo').read_text())[1]),disk_free_bytes=shutil.disk_usage(root).free,containers=sorted(running))))
    elif args.operation=='monitor':
        spec=json.loads((target/'spec.json').read_text());ticks=os.sysconf('SC_CLK_TCK')
        os.umask(0o077)
        with (target/'resources.jsonl').open('a',buffering=1) as stream:
            for _ in range(4000):
                row=dict(time=time.time(),monotonic=time.monotonic(),processes={},containers={})
                for name in ['gateway','collector','relay']:
                    try:
                        pid=int(command(['systemctl','show',spec['units'][name],'-p','MainPID','--value']))
                        fields=Path(f'/proc/{pid}/stat').read_text().split(')',1)[1].split()
                        status=dict(line.split(':',1) for line in Path(f'/proc/{pid}/status').read_text().splitlines() if ':' in line)
                        row['processes'][name]=dict(pid=pid,cpu_seconds=(int(fields[11])+int(fields[12]))/ticks,rss_kib=int(status['VmRSS'].split()[0]))
                        if name=='gateway':assert hashlib.sha256(Path(f'/proc/{pid}/exe').read_bytes()).hexdigest()==spec['server_sha256']
                    except (OSError,ValueError,KeyError):row['processes'][name]=dict(unavailable=True)
                for name,group in spec['cgroups'].items():
                    try:
                        path=Path(group);cpu=dict(line.split() for line in (path/'cpu.stat').read_text().splitlines())
                        row['containers'][name]=dict(cpu_seconds=int(cpu['usage_usec'])/1e6,memory_bytes=int((path/'memory.current').read_text()))
                    except OSError:row['containers'][name]=dict(unavailable=True)
                row['host_cpu_ticks']=[int(x) for x in Path('/proc/stat').read_text().splitlines()[0].split()[1:]]
                row['host_available_kib']=int(re.search(r'MemAvailable:\s+(\d+)',Path('/proc/meminfo').read_text())[1])
                stream.write(json.dumps(row)+'\n');time.sleep(2)
    elif args.operation=='capture':
        command(['systemctl','stop',unit,f['units']['gateway'],f['units']['collector']])
        archive=target/'databases.tar'
        with tarfile.open(archive,'w') as tar:
            for name in ['events.db','collector.db']:tar.add(root/'state'/name,arcname=name)
        archive.chmod(0o600);identity=pwd.getpwnam('qualifier');os.chown(archive,identity.pw_uid,identity.pw_gid)
        resources=target/'resources.jsonl';resources.chmod(0o600);os.chown(resources,identity.pw_uid,identity.pw_gid)
        target.chmod(0o711)
        print(json.dumps(dict(sha256=hashlib.sha256(archive.read_bytes()).hexdigest(),resource_sha256=hashlib.sha256(resources.read_bytes()).hexdigest())))
    else:
        subprocess.run(['systemctl','stop',unit,*f['units'].values()],capture_output=True,timeout=90)
        active=command(['docker','ps','-q','--filter','label=openwaf.qualification='+f['tag']]).split()
        if active:command(['docker','stop',*active])
        assert not command(['docker','ps','-q','--filter','label=openwaf.qualification='+f['tag']])
        print(json.dumps(dict(stopped=True)))


if __name__=='__main__':main()
