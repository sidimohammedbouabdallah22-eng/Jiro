"""Owned, isolated business-product qualification services; no public listeners."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import pwd
import re
import secrets
import shutil
import sqlite3
import subprocess
import sys
import tarfile
import time
import urllib.error
import urllib.request


def command(args, data=None, timeout=600):
    p = subprocess.run([str(x) for x in args], input=data, text=True, capture_output=True, timeout=timeout)
    if p.returncode:
        raise RuntimeError(f"{args[0]} failed: {p.stderr[-1500:]}")
    return p.stdout.strip()


def save(root, f):
    (root / 'fixture.json').write_text(json.dumps(f))
    (root / 'fixture.json').chmod(0o600)


def stop_packaged_fixture():
    requirements=command(['systemctl','show','openwaf.service','-p','Requires','--value']).split()
    owned=[name for name in requirements if re.fullmatch(r'openwaf-m2-(backend|events|audit)-[a-f0-9]{8}\.service',name)]
    command(['systemctl','stop','openwaf.service',*owned])
    return dict(stopped=['openwaf.service',*owned])


def wait(url, seconds=300, container=None):
    class NoRedirect(urllib.request.HTTPRedirectHandler):
        def redirect_request(self, *args, **kwargs): return None
    opener=urllib.request.build_opener(NoRedirect())
    end = time.monotonic() + seconds
    while time.monotonic() < end:
        if container:
            running=command(['docker','inspect','--format={{.State.Running}}',container])
            if running!='true': raise RuntimeError('application installer/container exited before readiness')
        try:
            with opener.open(url, timeout=5) as r:
                if r.status == 200:
                    return
        except urllib.error.HTTPError as e:
            # Canonical-host redirects indicate a live application; its WAF
            # origin is intentionally not started until after this preflight.
            if e.code in (301,302,303,307,308): return
        except (OSError, ValueError):
            pass
        time.sleep(1)
    raise RuntimeError('application readiness deadline exceeded')


def setup(root, f):
    disk = shutil.disk_usage(root.parent)
    if root.exists() or disk.free < 5 << 30:
        raise RuntimeError('requires new fixture and at least 5 GiB disk headroom')
    package = Path(f['package'])
    if hashlib.sha256(package.read_bytes()).hexdigest() != f['package_sha256']:
        raise RuntimeError('package checksum mismatch')
    root.mkdir(mode=0o755)
    (root / 'guest.py').write_bytes(Path(__file__).read_bytes())
    (root / 'guest.py').chmod(0o600)
    identity = pwd.getpwnam('openwaf')
    state = root / 'state'
    state.mkdir(mode=0o700)
    os.chown(state, identity.pw_uid, identity.pw_gid)
    f['environment'] = dict(kernel=command(['uname', '-sr']), cpus=os.cpu_count(),
        memory_kib=int(re.search(r'MemTotal:\s+(\d+)', Path('/proc/meminfo').read_text())[1]),
        disk_free_before_bytes=disk.free, minimum_disk_free_bytes=5 << 30)
    f['containers'] = {name:f['tag']+'-'+name for name in ['db', 'app']}
    f['units'] = {name:f['tag']+'-'+name+'.service' for name in ['relay','collector','gateway']}
    save(root, f)
    # This guest is dedicated to the owned lab; stop the prior packaged fixture.
    stop_packaged_fixture()
    network=f['tag']+'-internal'
    command(['docker','network','create','--internal','--label','openwaf.qualification='+f['tag'],network])
    def run(name, image, env, memory):
        path=root/(name+'.env')
        path.write_text('\n'.join(k+'='+str(v) for k,v in env.items())+'\n')
        path.chmod(0o600)
        command(['docker','create','--name',f['containers'][name], '--label','openwaf.qualification='+f['tag'],
            '--network',network,'--network-alias',name,'--security-opt','no-new-privileges',
            '--memory',memory,'--pids-limit','256','--env-file',path,image])
        if name=='app' and f['app']=='prestashop':
            # Official installer fetches its language packs unconditionally.
            # Outbound bootstrap only: no published container ports. Detach
            # before starting the WAF or running any qualification traffic.
            command(['docker','network','connect','bridge',f['containers'][name]])
        command(['docker','start',f['containers'][name]])
    run('db',f['db_image'],dict(MARIADB_ROOT_PASSWORD=f['db_password'], MARIADB_DATABASE='business',
        MARIADB_USER='business',MARIADB_PASSWORD=f['db_password']),'512m')
    end=time.monotonic()+120
    while time.monotonic()<end:
        try:
            command(['docker','exec',f['containers']['db'],'sh','-c',
                'mariadb -uroot -p"$MARIADB_ROOT_PASSWORD" -e "SELECT 1"'])
            break
        except RuntimeError:
            time.sleep(1)
    else:
        raise RuntimeError('database readiness failed')
    if f['app']=='dolibarr':
        env=dict(DOLI_DB_HOST='db',DOLI_DB_NAME='business',DOLI_DB_USER='business',
            DOLI_DB_PASSWORD=f['db_password'],DOLI_URL_ROOT=f['origin'],DOLI_ADMIN_LOGIN='lab-admin',
            DOLI_ADMIN_PASSWORD=f['password'],DOLI_INIT_DEMO='0',DOLI_CRON='0',DOLI_COMPANY_NAME='OpenWAF Lab')
    else:
        env=dict(DB_SERVER='db',DB_NAME='business',DB_USER='business',DB_PASSWD=f['db_password'],
            PS_INSTALL_AUTO='1',PS_DOMAIN='localhost:'+str(f['ports']['proxy']),PS_LANGUAGE='en',PS_COUNTRY='fr',
            ADMIN_MAIL='qualification@example.invalid',ADMIN_PASSWD=f['password'],PS_DEV_MODE='0',
            PS_FOLDER_ADMIN='admin-dev',PS_FOLDER_INSTALL='install-disabled',PS_ENABLE_SSL='0')
    run('app',f['image']['image'],env,'1024m')
    info=json.loads(command(['docker','inspect',f['containers']['app']]))[0]
    ip=info['NetworkSettings']['Networks'][network]['IPAddress']
    command(['systemd-run','--collect','--unit='+f['units']['relay'],'--property=DynamicUser=yes',
        '/usr/bin/socat',f"TCP-LISTEN:{f['ports']['app']},bind=127.0.0.1,reuseaddr,fork,max-children=32",f'TCP:{ip}:80'])
    f['image_metadata']={}
    for name,image in [('app',f['image']['image']),('db',f['db_image'])]:
        entry=json.loads(command(['docker','image','inspect',image]))[0]
        f['image_metadata'][name]=dict(id=entry['Id'],os=entry['Os'],architecture=entry['Architecture'],
            size_bytes=entry['Size'],labels=entry.get('Config',{}).get('Labels'))
    wait(f"http://127.0.0.1:{f['ports']['app']}/",600,f['containers']['app'])
    if f['app']=='prestashop':
        command(['docker','network','disconnect','bridge',f['containers']['app']])
        networks=json.loads(command(['docker','inspect',f['containers']['app']]))[0]['NetworkSettings']['Networks']
        if set(networks)!={network}: raise RuntimeError('unexpected runtime application network')
        f['installation_network']=dict(temporary_outbound_bridge=True,published_ports=False,runtime_networks=list(networks))
        php='foreach(glob("/var/www/html/translations/*.zip") as $p) {echo json_encode(["file"=>basename($p),"sha256"=>hash_file("sha256",$p)])."\\n";}'
        f['translation_assets']=[json.loads(line) for line in command(['docker','exec',f['containers']['app'],'php','-r',php]).splitlines()]
        if sorted(f['translation_assets'],key=lambda x:x['file'])!=sorted(f['image']['translation_assets'],key=lambda x:x['file']):
            raise RuntimeError('downloaded translation assets differ from the reviewed lock')
    with tarfile.open(package) as archive:
        for name in ['waf-server','event-collector']:
            target=root/name
            target.write_bytes(archive.extractfile('usr/lib/openwaf/'+name).read())
            target.chmod(0o755)
            f[name+'_sha256']=hashlib.sha256(target.read_bytes()).hexdigest()
    policy=dict(mode='enforcing',paranoia=1,inbound_threshold=5,outbound_threshold=4,
        request_limit=1048576,response_limit=2097152,inspect_response=False,exclusions=[],custom_rules='',scoped_exceptions=[])
    config=dict(schema_version=2,revision=1,applications=[dict(application_id=f['app'],name=f['app'],hosts=['localhost'],
        upstream=f"http://127.0.0.1:{f['ports']['app']}",policy=policy)])
    path=state/'policy.json'
    path.write_text(json.dumps(config)); path.chmod(0o600); os.chown(path,identity.pw_uid,identity.pw_gid)
    for name in ['token','collector_token']:
        (root/name).write_text(f[name]); (root/name).chmod(0o600)
    for name,args,memory in [('collector',f"{root}/event-collector -listen=127.0.0.1:{f['ports']['collector']} -db={state}/collector.db -db-mib=128 -token-file=${{CREDENTIALS_DIRECTORY}}/collector_token",192),
        ('gateway',f"{root}/waf-server -config={path} -event-db={state}/events.db -event-db-mib=128 -event-rows=10000 -event-export-rows=10000 -event-export-url=http://127.0.0.1:{f['ports']['collector']}/v1/events -event-export-token-file=${{CREDENTIALS_DIRECTORY}}/collector_token -admin-token-file=${{CREDENTIALS_DIRECTORY}}/token -listen=127.0.0.1:{f['ports']['proxy']} -admin=127.0.0.1:{f['ports']['admin']} -max-concurrent=16 -max-connections=64 -buffer-mib=64 -request-timeout=30s",512)]:
        unit=Path('/etc/systemd/system')/f['units'][name]
        unit.write_text(f"[Service]\nUser=openwaf\nGroup=openwaf\nLoadCredential=token:{root}/token\nLoadCredential=collector_token:{root}/collector_token\nExecStart={args}\nMemoryMax={memory}M\nTasksMax=128\nNoNewPrivileges=yes\nPrivateTmp=yes\nProtectSystem=strict\nReadWritePaths={state}\n")
    command(['systemctl','daemon-reload'])
    command(['systemctl','start',f['units']['collector'],f['units']['gateway']])
    save(root,f)
    return f


def seed(root,f):
    if f['app']=='prestashop':
        command(['docker','cp','/tmp/m4_prestashop_seed.php',f['containers']['app']+':/tmp/openwaf-seed.php'])
        # Earlier fixture seeding ran as root and created unwritable cache
        # members. Repair that owned cache, then always use the web identity.
        command(['docker','exec',f['containers']['app'],'chown','-R','www-data:www-data','/var/www/html/var/cache'])
        value=command(['docker','exec','-i','-u','www-data',f['containers']['app'],'php','/tmp/openwaf-seed.php'],json.dumps(dict(password=f['password'])))
        result=json.loads(value[value.index('{"version"'):])
        if result['version']!=f['image']['version']: raise RuntimeError('installed version differs from pin')
        f.update(installed_version=result['version'],product_id=result['product_id'],customer_id=result['customer_id'],routes=result['routes'])
        save(root,f); return result
    php="""<?php
define('NOLOGIN',1); define('NOCSRFCHECK',1); define('NOTOKENRENEWAL',1);
require '/var/www/html/main.inc.php'; require_once DOL_DOCUMENT_ROOT.'/core/lib/admin.lib.php';
$user->fetch('', 'lab-admin'); $user->getrights();
foreach(['modSociete','modPropale','modFacture','modCommande','modImport','modApi'] as $module) {
 $result=activateModule($module); if(!empty($result['errors'])) {fwrite(STDERR,'module activation failed'); exit(1);}
}
dolibarr_set_const($db,'MAIN_INFO_SOCIETE_NOM','OpenWAF Lab','chaine',0,'',1);
dolibarr_set_const($db,'MAIN_INFO_SOCIETE_COUNTRY','1:FR:France','chaine',0,'',1);
dolibarr_set_const($db,'MAIN_INFO_SOCIETE_DEVISE','EUR','chaine',0,'',1);
$user->api_key=API_KEY; if($user->update($user)<0) {exit(2);}
$reader=new User($db);
if($reader->fetch('', 'lab-reader')<=0) {
 $reader->login='lab-reader'; $reader->lastname='Qualification Reader'; $reader->admin=0;
 $reader->email='reader@example.invalid';
 if($reader->create($user)<=0) {fwrite(STDERR,'reader creation failed'); exit(3);}
}
$reader->admin=0; $reader->api_key=READER_KEY;
if($reader->update($user)<0 || $reader->setPassword($user,READER_PASSWORD)<0) {exit(4);}
if($reader->delrights(0,'all','all')<0 || $reader->addrights(121)<0) {exit(5);}
$reader->getrights();
if(!$reader->hasRight('societe','lire') || $reader->hasRight('societe','creer') || $reader->admin) {exit(6);}
echo json_encode(['version'=>DOL_VERSION,'admin_id'=>$user->id,'reader_id'=>$reader->id]);
"""
    f.setdefault('reader_api_key',secrets.token_hex(32))
    php=php.replace('API_KEY',repr(f['api_key'])).replace('READER_KEY',repr(f['reader_api_key'])).replace('READER_PASSWORD',repr(f['password']))
    value=command(['docker','exec','-i','-u','www-data',f['containers']['app'],'php'],php)
    # PHP may emit harmless installation warnings before the final JSON object.
    result=json.loads(value[value.rfind('{'):])
    if result['version']!=f['image']['version']:
        raise RuntimeError('installed application version differs from pin')
    f['installed_version']=result['version']; save(root,f)
    result['reader_api_key']=f['reader_api_key']
    return result


def report(root,f):
    state=root/'state'
    with sqlite3.connect(f'file:{state}/events.db?mode=ro',uri=True) as a, sqlite3.connect(f'file:{state}/collector.db?mode=ro',uri=True) as b:
        local={r[0]:r[1] for r in a.execute('SELECT id,data FROM events')}
        remote={r[0]:r[1] for r in b.execute('SELECT id,data FROM collected_events')}
        if local!=remote or not local:
            raise RuntimeError('security evidence is absent or differs from receiver')
        occurrences=sum(max(1,json.loads(x).get('occurrences',1)) for x in local.values())
        totals=b.execute('SELECT records,occurrences FROM collector_totals').fetchone()
        assert totals==(len(local),occurrences)
        integrity=[a.execute('PRAGMA integrity_check').fetchone()[0],b.execute('PRAGMA integrity_check').fetchone()[0]]
        assert integrity==['ok','ok']
    resources=[json.loads(line) for line in command(['docker','stats','--no-stream','--format','{{json .}}',*f['containers'].values()]).splitlines()]
    status=command(['systemctl','show',f['units']['gateway'],'-p','MemoryPeak','-p','CPUUsageNSec','-p','MainPID'])
    value = dict(identical_ids_and_payloads=True,records=len(local),occurrences=occurrences,integrity=integrity,
        statuses={str(code):sum(max(1,json.loads(v).get('occurrences',1)) for v in local.values() if json.loads(v).get('status')==code)
            for code in sorted({json.loads(v).get('status',0) for v in local.values()})},
        containers=resources,gateway_systemd=status,disk_free_after_bytes=shutil.disk_usage(root).free)
    if f['app']=='prestashop':
        data=command(['docker','exec','-i','-u','www-data',f['containers']['app'],'php','/tmp/openwaf-seed.php'],json.dumps(dict(report=True)))
        value['committed_order']=json.loads(data[data.rfind('{'):])
    return value


def start(f,lab_slice=None):
    assert lab_slice in [None,'jiro-m4.slice']
    stop_packaged_fixture()
    command(['docker','start',*f['containers'].values()])
    info=json.loads(command(['docker','inspect',f['containers']['app']]))[0]
    ip=info['NetworkSettings']['Networks'][f['tag']+'-internal']['IPAddress']
    subprocess.run(['systemctl','stop',f['units']['relay']],capture_output=True)
    slice_args=['--property=Slice='+lab_slice] if lab_slice else []
    command(['systemd-run','--collect','--unit='+f['units']['relay'],'--property=DynamicUser=yes',*slice_args,
        '/usr/bin/socat',f"TCP-LISTEN:{f['ports']['app']},bind=127.0.0.1,reuseaddr,fork,max-children=32",f'TCP:{ip}:80'])
    wait(f"http://127.0.0.1:{f['ports']['app']}/",300)
    command(['systemctl','start',f['units']['collector'],f['units']['gateway']])
    return dict(started=True)


def activate(root,f,spec):
    package=Path(spec['package'])
    if hashlib.sha256(package.read_bytes()).hexdigest()!=spec['package_sha256']:
        raise RuntimeError('replacement package checksum differs')
    if spec['package_sha256']==f['package_sha256']: return f
    stage=root/('activation-'+spec['package_sha256'][:12])
    if stage.exists(): raise RuntimeError('activation evidence already exists')
    stage.mkdir(mode=0o755)
    with tarfile.open(package) as archive:
        for name in ['waf-server','event-collector','waf-admin']:
            entry=archive.getmember('usr/lib/openwaf/'+name)
            if not entry.isfile() or entry.size>256<<20: raise RuntimeError('unexpected binary member')
            path=stage/name; path.write_bytes(archive.extractfile(entry).read()); path.chmod(0o755)
    command(['systemctl','stop',f['units']['gateway'],f['units']['collector']])
    checkpoint=stage/'checkpoint'
    command([stage/'waf-admin','backup','-config',root/'state/policy.json','-event-db',root/'state/events.db',
        '-collector-db',root/'state/collector.db','-binary',root/'waf-server','-out',checkpoint])
    proof=command([stage/'waf-admin','upgrade-check','-backup',checkpoint,'-candidate',stage/'waf-server'])
    (stage/'upgrade-check.json').write_text(proof)
    for name in ['waf-server','event-collector']:
        shutil.copyfile(stage/name,root/name)
        (root/name).chmod(0o755)
        f[name+'_sha256']=hashlib.sha256((root/name).read_bytes()).hexdigest()
    f.update(spec); save(root,f)
    return f


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('operation',choices=['setup','seed','report','stop','start','activate','stop-previous']); p.add_argument('--root',type=Path,required=True)
    args=p.parse_args(); root=args.root
    if os.geteuid()!=0 or not re.fullmatch(r'/var/lib/owaf-business-[a-f0-9]{8}',str(root)) or command(['systemd-detect-virt','--vm'])!='oracle':
        raise RuntimeError('requires root in the owned disposable VirtualBox guest')
    if args.operation=='setup': value=setup(root,json.load(sys.stdin))
    else:
        f=json.loads((root/'fixture.json').read_text())
        if args.operation=='seed': value=seed(root,f)
        elif args.operation=='activate': value=activate(root,f,json.load(sys.stdin))
        elif args.operation=='start': value=start(f)
        elif args.operation=='stop-previous': value=stop_packaged_fixture()
        elif args.operation=='report': value=report(root,f)
        else:
            for unit in f['units'].values():
                subprocess.run(['systemctl','stop',unit],capture_output=True,timeout=45)
            ids=command(['docker','ps','-q','--filter','label=openwaf.qualification='+f['tag']]).split()
            if ids: command(['docker','stop',*ids])
            active=command(['docker','ps','-q','--filter','label=openwaf.qualification='+f['tag']]).split()
            if active: raise RuntimeError('owned containers remain active')
            value=dict(stopped=True)
    print(json.dumps(value))


if __name__=='__main__': main()
