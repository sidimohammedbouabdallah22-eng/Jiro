"""One gateway, two real owned PHP products, private URLs and reversible setup."""
import argparse
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import pwd
import re
import secrets
import shutil
import subprocess
import tarfile
import time

import owned_lab_environment


def command(args,data=None,check=True):
    p=subprocess.run([str(x) for x in args],input=data,capture_output=True,text=True,timeout=180)
    if check and p.returncode:raise RuntimeError('owned joint command failed: '+str(args[0]))
    return p.stdout.strip()


def save(path,value):path.write_text(json.dumps(value,indent=2));path.chmod(0o600)


def digest(path):return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def docker_file(container,path):
    p=subprocess.run(['docker','cp',container+':'+path,'-'],capture_output=True,timeout=60);assert p.returncode==0
    with tarfile.open(fileobj=io.BytesIO(p.stdout)) as tar:return tar.extractfile(next(m for m in tar if m.isfile())).read()


def restore(root,f):
    if (root/'dolibarr-conf.private.php').exists():
        data=(root/'dolibarr-conf.private.php').read_text()
        command(['docker','exec','-i',f['dolibarr']['containers']['app'],'php','-r',"file_put_contents('/var/www/html/conf/conf.php',stream_get_contents(STDIN));"],data)
        assert hashlib.sha256(docker_file(f['dolibarr']['containers']['app'],'/var/www/html/conf/conf.php')).hexdigest()==digest(root/'dolibarr-conf.private.php')
    if (root/'shop-original.private.json').exists():
        snap=json.loads((root/'shop-original.private.json').read_text())
        current=json.loads(command(['docker','exec','-i','-u','www-data',f['prestashop']['containers']['app'],'php','/tmp/openwaf-joint-domains.php'],json.dumps(dict(operation='restore',snapshot=snap))))
        assert current==snap,'shop URL restoration differs'
    return dict(restored=True)


def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('operation',choices=['setup','mark','monitor','capture','cleanup','files','spool']);p.add_argument('--root',type=Path,required=True);p.add_argument('--sources',type=Path,required=True)
    args=p.parse_args();root=args.root;tag=root.name.rsplit('-',1)[1]
    assert os.geteuid()==0 and re.fullmatch(r'/var/lib/owaf-joint-[a-f0-9]{8}',str(root))
    assert re.fullmatch(r'/tmp/owaf-joint-[a-f0-9]{8}',str(args.sources))
    environment_kind=owned_lab_environment.environment()
    if args.operation=='mark':print(json.dumps(dict(monotonic=time.monotonic(),time=time.time())));return
    if args.operation=='setup':
        f=json.load(__import__('sys').stdin);assert not root.exists() and shutil.disk_usage('/var/lib').free>2<<30
        assert owned_lab_environment.environment(f)==environment_kind
        if environment_kind=='wsl2':
            f['allocation_profile']=owned_lab_environment.allocation()
        resources=f.get('qualification_resources',dict(max_concurrent=16,max_connections=64))
        assert resources in [dict(max_concurrent=16,max_connections=64),dict(max_concurrent=64,max_connections=128)]
        quota=f.get('gateway_cpu_quota_percent',0);assert quota in [0,200]
        parallelism=f.get('gateway_gomaxprocs',0);assert parallelism in [0,2]
        root.mkdir(mode=0o755);save(root/'fixture.private.json',f)
        spec=importlib.util.spec_from_file_location('business',args.sources/'m4_business_guest.py');h=importlib.util.module_from_spec(spec);spec.loader.exec_module(h)
        for name in ['dolibarr','prestashop']:
            base=f[name];assert re.fullmatch(r'/var/lib/owaf-business-[a-f0-9]{8}',base['root'])
            assert base['containers']=={kind:base['tag']+'-'+kind for kind in ['db','app']}
            h.start(base,lab_slice='jiro-m4.slice' if environment_kind=='wsl2' else None);command(['systemctl','stop',base['units']['gateway'],base['units']['collector']])
        expected={container for name in ['dolibarr','prestashop'] for container in f[name]['containers'].values()}
        assert set(command(['docker','ps','--format','{{.Names}}']).split())==expected
        f['units']={name:'owaf-joint-'+tag+'-'+name+'.service' for name in ['gateway','collector','monitor']}
        f['sampler_version']=3
        f['guest_clocksource']=Path('/sys/devices/system/clocksource/clocksource0/current_clocksource').read_text().strip()
        f['guest_kernel']=os.uname().release
        f['original_images']={name:json.loads(command(['docker','inspect',f[name]['containers']['app']]))[0]['Image'] for name in ['dolibarr','prestashop']}
        # Retain only relevant public server directives, never environment or
        # application configuration containing credentials. This is a file
        # inventory, not a claim to have dumped Apache's effective config.
        f['backend_keepalive_directives']={name:command(['docker','exec',f[name]['containers']['app'],
            'sh','-c',"grep -hE '^[[:space:]]*(KeepAliveTimeout|KeepAlive|MaxKeepAliveRequests)[[:space:]]' /etc/apache2/apache2.conf /etc/apache2/conf-enabled/*.conf /etc/apache2/sites-enabled/*.conf || true"]).splitlines()
            for name in ['dolibarr','prestashop']}
        identity=pwd.getpwnam('openwaf');state=root/'state';state.mkdir(mode=0o700);os.chown(state,identity.pw_uid,identity.pw_gid)
        package=Path(f['package']);assert digest(package)==f['package_sha256']
        with tarfile.open(package) as tar:
            for name in ['waf-server','event-collector']:
                path=root/name;path.write_bytes(tar.extractfile('usr/lib/openwaf/'+name).read());path.chmod(0o755)
        assert digest(root/'waf-server')==f['server_sha256']
        for name in ['admin-token','event-token']:
            (root/name).write_text(secrets.token_hex(32));(root/name).chmod(0o600)
        f['token']=(root/'admin-token').read_text()
        original=docker_file(f['dolibarr']['containers']['app'],'/var/www/html/conf/conf.php')
        (root/'dolibarr-conf.private.php').write_bytes(original);(root/'dolibarr-conf.private.php').chmod(0o600)
        new,n=re.subn(r"^\$dolibarr_main_url_root\s*=.*?;",lambda _:"$dolibarr_main_url_root='http://erp.joint.test:"+str(f['ports']['proxy'])+"';",original.decode(),flags=re.M);assert n==1
        command(['docker','exec','-i',f['dolibarr']['containers']['app'],'php','-r',"file_put_contents('/var/www/html/conf/conf.php',stream_get_contents(STDIN));"],new)
        ps=f['prestashop']['containers']['app'];command(['docker','cp',args.sources/'m4_joint_domains.php',ps+':/tmp/openwaf-joint-domains.php'])
        snapshot=json.loads(command(['docker','exec','-i','-u','www-data',ps,'php','/tmp/openwaf-joint-domains.php'],json.dumps(dict(operation='snapshot'))));save(root/'shop-original.private.json',snapshot)
        command(['docker','exec','-i','-u','www-data',ps,'php','/tmp/openwaf-joint-domains.php'],json.dumps(dict(operation='set',domain='shop.joint.test:'+str(f['ports']['proxy']))))
        policies=[]
        for name,host in [('dolibarr','erp.joint.test'),('prestashop','shop.joint.test')]:
            old=json.loads((Path(f[name]['root'])/'state/policy.json').read_text())['applications'][0]
            old.update(hosts=[host],traffic_controls=dict(max_concurrent=8));policies.append(old)
        save(state/'policy.json',dict(schema_version=2,revision=1,applications=policies));os.chown(state/'policy.json',identity.pw_uid,identity.pw_gid)
        for name,argv,mem in [('collector',f"{root}/event-collector -listen=127.0.0.1:{f['ports']['collector']} -db={state}/collector.db -db-mib=128 -token-file=${{CREDENTIALS_DIRECTORY}}/event-token",192),('gateway',f"{root}/waf-server -config={state}/policy.json -event-db={state}/events.db -event-db-mib=128 -event-rows=10000 -event-export-rows=10000 -event-export-url=http://127.0.0.1:{f['ports']['collector']}/v1/events -event-export-token-file=${{CREDENTIALS_DIRECTORY}}/event-token -admin-token-file=${{CREDENTIALS_DIRECTORY}}/admin-token -listen=127.0.0.1:{f['ports']['proxy']} -admin=127.0.0.1:{f['ports']['admin']} -max-concurrent=16 -max-connections=64 -buffer-mib=64 -request-timeout=30s",512)]:
            if name=='gateway':
                argv=argv.replace('-max-concurrent=16 -max-connections=64',
                                  f"-max-concurrent={resources['max_concurrent']} -max-connections={resources['max_connections']}")
            cpu_limit='CPUQuota=200%\nCPUQuotaPeriodSec=100ms\n' if name=='gateway' and quota else ''
            if name=='gateway' and parallelism:
                cpu_limit+='Environment=GOMAXPROCS='+str(parallelism)+'\n'
            if environment_kind=='wsl2':
                cpu_limit+='Slice=jiro-m4.slice\n'
            Path('/etc/systemd/system/'+f['units'][name]).write_text(f'[Service]\nUser=openwaf\nGroup=openwaf\nLoadCredential=admin-token:{root}/admin-token\nLoadCredential=event-token:{root}/event-token\nExecStart={argv}\nProtectSystem=strict\nPrivateTmp=yes\nNoNewPrivileges=yes\nReadWritePaths={state}\nMemoryMax={mem}M\nTasksMax=256\n{cpu_limit}')
        save(root/'fixture.private.json',f);command(['systemctl','daemon-reload']);command(['systemctl','start',f['units']['collector'],f['units']['gateway']])
        measurement=dict(cgroups={},units={name:f['units'][name] for name in ['gateway','collector']})
        group=command(['systemctl','show',f['units']['gateway'],'-p','ControlGroup','--value'])
        measurement['gateway_cgroup']='/sys/fs/cgroup'+group
        f['gateway_cpu_control']=dict(quota_percent=quota,cpu_max=Path(measurement['gateway_cgroup']+'/cpu.max').read_text().strip())
        pid=int(command(['systemctl','show',f['units']['gateway'],'-p','MainPID','--value']))
        actual=[value for value in Path(f'/proc/{pid}/environ').read_bytes().split(b'\0') if value.startswith(b'GOMAXPROCS=')]
        assert actual==([b'GOMAXPROCS=2'] if parallelism else [])
        f['gateway_cpu_control']['gomaxprocs']=parallelism
        assert f['gateway_cpu_control']['cpu_max']==('200000 100000' if quota else 'max 100000')
        save(root/'fixture.private.json',f)
        for app in ['dolibarr','prestashop']:
            for kind,container in f[app]['containers'].items():
                pid=int(command(['docker','inspect','--format={{.State.Pid}}',container]));relative=Path(f'/proc/{pid}/cgroup').read_text().strip().split('::')[1]
                measurement['cgroups'][app+'-'+kind]='/sys/fs/cgroup'+relative
                if f.get('lab_environment')=='wsl2':
                    assert relative.startswith(str(owned_lab_environment.ALLOCATION).removeprefix('/sys/fs/cgroup')+'/')
        save(root/'measurement.json',measurement)
        slice_args=['--property=Slice=jiro-m4.slice'] if f.get('lab_environment')=='wsl2' else []
        command(['systemd-run','--collect','--unit='+f['units']['monitor'],'--property=MemoryMax=128M',*slice_args,'/usr/bin/python3',Path(__file__),'monitor','--root',root,'--sources',args.sources])
        print(json.dumps(f));return
    f=json.loads((root/'fixture.private.json').read_text())
    assert owned_lab_environment.environment(f)==environment_kind
    if args.operation=='spool':
        pid=int(command(['systemctl','show',f['units']['gateway'],'-p','MainPID','--value']));tmp=Path(f'/proc/{pid}/root/tmp')
        paths=[path for pattern in ['body*','crzmp*'] for path in tmp.glob(pattern) if path.is_file()]
        print(json.dumps(dict(files=len(paths),bytes=sum(p.stat().st_size for p in paths),open_fds=len(list(Path(f'/proc/{pid}/fd').iterdir())))))
    elif args.operation=='monitor':
        os.umask(0o077);m=json.loads((root/'measurement.json').read_text());ticks=os.sysconf('SC_CLK_TCK')
        pids={name:int(command(['systemctl','show',unit,'-p','MainPID','--value'])) for name,unit in m['units'].items()}
        image_key=None
        image_sha=None
        with (root/'resources.jsonl').open('a',buffering=1) as stream:
            for _ in range(4000):
                row=dict(time=time.time(),monotonic=time.monotonic(),cpus=len(os.sched_getaffinity(0)),host_cpus=os.cpu_count(),sampler_version=3,processes={},containers={})
                if environment_kind=='wsl2':
                    row['allocation']=owned_lab_environment.allocation_sample()
                row['clocksource']=Path('/sys/devices/system/clocksource/clocksource0/current_clocksource').read_text().strip()
                row['monitor_schedstat_ns']=[int(value) for value in Path('/proc/self/schedstat').read_text().split()]
                row['pressure']={name:Path('/proc/pressure/'+name).read_text() for name in ['cpu','io','memory']}
                for name,unit in m['units'].items():
                    try:
                        pid=pids[name]
                        fields=Path(f'/proc/{pid}/stat').read_text().split(')',1)[1].split()
                        status=Path(f'/proc/{pid}/status').read_text()
                        start_ticks=int(fields[19])
                        row['processes'][name]=dict(pid=pid,start_ticks=start_ticks,cpu_seconds=(int(fields[11])+int(fields[12]))/ticks,rss_kib=int(re.search(r'VmRSS:\s+(\d+)',status)[1]))
                        row['processes'][name]['schedstat_ns']=[int(value) for value in Path(f'/proc/{pid}/schedstat').read_text().split()]
                        if name=='gateway':
                            path=Path(f'/proc/{pid}/exe')
                            st=path.stat()
                            key=(pid,start_ticks,st.st_dev,st.st_ino,st.st_size,st.st_mtime_ns,st.st_ctime_ns)
                            recomputed=key!=image_key
                            if recomputed:
                                image_sha=digest(path)
                                assert image_sha==f['server_sha256']
                                image_key=key
                            row['processes'][name]['executable']=dict(signature=key,sha256=image_sha,recomputed=recomputed)
                    except (OSError,ValueError):row['processes'][name]=dict(unavailable=True)
                for name,group in m['cgroups'].items():
                    try:
                        path=Path(group);cpu=dict(line.split() for line in (path/'cpu.stat').read_text().splitlines());events=dict(line.split() for line in (path/'memory.events').read_text().splitlines())
                        row['containers'][name]=dict(cpu_seconds=int(cpu['usage_usec'])/1e6,memory_bytes=int((path/'memory.current').read_text()),oom_kill=int(events['oom_kill']))
                    except OSError:row['containers'][name]=dict(unavailable=True)
                row['host_cpu_ticks']=[int(x) for x in Path('/proc/stat').read_text().splitlines()[0].split()[1:]];row['host_available_kib']=int(re.search(r'MemAvailable:\s+(\d+)',Path('/proc/meminfo').read_text())[1])
                if 'gateway_cgroup' in m:
                    group=Path(m['gateway_cgroup'])
                    cpu=dict(line.split() for line in (group/'cpu.stat').read_text().splitlines())
                    row['gateway_cpu_control']=dict(cpu_max=(group/'cpu.max').read_text().strip(),
                        usage_usec=int(cpu['usage_usec']),nr_throttled=int(cpu.get('nr_throttled',0)),
                        throttled_usec=int(cpu.get('throttled_usec',0)))
                row['collection_ms']=(time.monotonic()-row['monotonic'])*1000
                stream.write(json.dumps(row)+'\n')
                time.sleep(max(0,row['monotonic']+1-time.monotonic()))
    elif args.operation=='files':
        app=f['dolibarr']['containers']['app'];command(['docker','cp',args.sources/'m4_joint_files.php',app+':/tmp/openwaf-joint-files.php'])
        output=command(['docker','exec','-i','-u','www-data',app,'php','/tmp/openwaf-joint-files.php'],__import__('sys').stdin.read())
        print(output.split('OPENWAF_FILES:')[1])
    elif args.operation=='capture':
        command(['systemctl','stop',f['units']['monitor'],f['units']['gateway'],f['units']['collector']])
        archive=root/'databases.tar';assert not archive.exists()
        with tarfile.open(archive,'w') as tar:
            for name in ['events.db','collector.db']:tar.add(root/'state'/name,arcname=name)
        identity=pwd.getpwnam('qualifier')
        for path in [archive,root/'resources.jsonl']:path.chmod(0o600);os.chown(path,identity.pw_uid,identity.pw_gid)
        print(json.dumps(dict(sha256=digest(archive),resources_sha256=digest(root/'resources.jsonl'))))
    else:
        for unit in f.get('units',{}).values():command(['systemctl','stop',unit],check=False)
        restored=restore(root,f)
        for app in ['dolibarr','prestashop']:
            for unit in f[app]['units'].values():command(['systemctl','stop',unit],check=False)
            command(['docker','stop',*f[app]['containers'].values()])
        save(root/'cleanup.json',restored);print(json.dumps(restored))


if __name__=='__main__':main()
