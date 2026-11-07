"""Owned Linux service fault drills; never run against a customer deployment."""
import argparse
from contextlib import closing
import errno
import hashlib
import http.client
import importlib.util
import json
import os
from pathlib import Path
import pwd
import re
import secrets
import shutil
import socket
import sqlite3
import ssl
import subprocess
import sys
import tarfile
import time
import urllib.error


def command(args, check=True):
    result=subprocess.run([str(x) for x in args],capture_output=True,text=True,timeout=120)
    if check and result.returncode:
        raise RuntimeError('controlled command failed: '+str(args[0]))
    return result


def digest(path):
    with Path(path).open('rb') as stream: return hashlib.file_digest(stream,'sha256').hexdigest()


def save(path,value):
    path.write_text(json.dumps(value,indent=2)+'\n');path.chmod(0o600)


def load(path,name):
    spec=importlib.util.spec_from_file_location(name,path)
    module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module);return module


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--root',type=Path,required=True)
    parser.add_argument('--package',type=Path,required=True)
    parser.add_argument('--package-sha256',required=True)
    parser.add_argument('--server-sha256',required=True)
    parser.add_argument('--sources',type=Path,required=True)
    args=parser.parse_args();root=args.root;tag=root.name.rsplit('-',1)[1]
    assert os.geteuid()==0 and re.fullmatch(r'/var/lib/owaf-m2-[a-f0-9]{8}',str(root))
    assert command(['systemd-detect-virt','--vm']).stdout.strip()=='oracle'
    assert digest(args.package)==args.package_sha256 and shutil.disk_usage('/var/lib').free>2<<30
    assert not root.exists()
    assert re.fullmatch(r'/tmp/owaf-alert-sources-[a-f0-9]{8}',str(args.sources))
    helper=load(args.sources/'m2_guest.py','fixture_helper')
    helper.setup(root,args.package,args.package)
    fixture=json.loads((root/'fixture.json').read_text())
    assert digest(root/'bin/current/waf-server')==args.server_sha256
    scripts=root/'scripts';shutil.copytree(args.sources,scripts);scripts.chmod(0o755)
    sys.path.insert(0,str(scripts));import pilot
    user='owaf-probe-'+tag
    command(['useradd','--system','--no-create-home','--shell','/usr/sbin/nologin',user])
    identity=pwd.getpwnam(user)
    for name in ['probes','alerts']:
        path=root/name;path.mkdir(mode=0o700);os.chown(path,identity.pw_uid,identity.pw_gid)
    recv=root/'alert-receiver';recv.mkdir(mode=0o700)
    waf=pwd.getpwnam('openwaf');os.chown(recv,waf.pw_uid,waf.pw_gid)
    for name,data in [('token',secrets.token_hex(32)),('mode','normal')]:
        path=recv/name;path.write_text(data);path.chmod(0o600);os.chown(path,waf.pw_uid,waf.pw_gid)
    with socket.socket() as listener:
        listener.bind(('127.0.0.1',0));port=listener.getsockname()[1]
    receiver_unit=f'openwaf-alert-receiver-{tag}.service'
    Path('/etc/systemd/system/'+receiver_unit).write_text(f'[Service]\nUser=openwaf\nGroup=openwaf\nExecStart=/usr/bin/python3 {scripts}/m4_alert_receiver.py {recv} {port}\nProtectSystem=strict\nReadWritePaths={recv}\nNoNewPrivileges=yes\n')
    directory=helper.api(fixture,'accounts')
    token=helper.api(fixture,'tokens',dict(revision=directory['revision'],owner='qa-viewer',name='Fault drill monitor',scopes=['monitoring:read'],lifetime_hours=1,reason='Isolated deployed fault qualification'))['secret']
    for name,value in [('monitor-token',token),('webhook-token',(recv/'token').read_text())]:
        path=root/'probes'/name;path.write_text(value);path.chmod(0o600);os.chown(path,identity.pw_uid,identity.pw_gid)
    shutil.copyfile(root/'tls/cert.pem',root/'probes/ca.pem')
    (root/'probes/ca.pem').chmod(0o600);os.chown(root/'probes/ca.pem',identity.pw_uid,identity.pw_gid)
    manifest=dict(schema=1,pilot_id='fault-drill-'+tag,owner='Isolated qualification fixture',host='Owned disposable VM',qualification_evidence='Current exact-build qualification',capacity_evidence='Not a sizing run',management_url=f"http://127.0.0.1:{fixture['admin']}",token_file=str(root/'probes/monitor-token'),canaries=[dict(name='application',url=f"https://application.test:{fixture['proxy']}/canary",status=200,sha256=hashlib.sha256(b'backend-ok').hexdigest())])
    alert_config=dict(schema=1,deployment='fault-drill-'+tag,pilot_manifest=str(root/'probes/manifest.json'),pilot_database=str(root/'probes/evidence.db'),webhook_url=f'http://127.0.0.1:{port}/alerts',webhook_token_file=str(root/'probes/webhook-token'))
    save(root/'probes/manifest.json',manifest);save(root/'probes/alerts.json',alert_config)
    for path in [root/'probes/manifest.json',root/'probes/alerts.json']:
        os.chown(path,identity.pw_uid,identity.pw_gid)
    pilot.initialize(root/'probes/evidence.db',manifest,time.time())
    os.chown(root/'probes/evidence.db',identity.pw_uid,identity.pw_gid)
    hosts=Path('/etc/hosts')
    if not re.search(r'^127\.0\.0\.1\s+application\.test(?:\s|$)',hosts.read_text(),re.M):
        with hosts.open('a') as stream:stream.write('\n127.0.0.1 application.test portal.test\n')
    units={}
    for kind in ['pilot','pilot-alerts']:
        name=f'openwaf-{kind}-{tag}.service';units[kind]=name
        text=(scripts/('openwaf-'+kind+'.service')).read_text()
        text=text.replace('User=openwaf-pilot\n','User='+user+'\n').replace('Group=openwaf-pilot\n','Group='+user+'\n').replace('/opt/openwaf-pilot',str(scripts)).replace('/etc/openwaf-pilot/manifest.json',str(root/'probes/manifest.json')).replace('/etc/openwaf-pilot/alerts.json',str(root/'probes/alerts.json')).replace('/var/lib/openwaf-pilot-alerts',str(root/'alerts')).replace('/var/lib/openwaf-pilot',str(root/'probes'))
        text=text.replace('[Service]','StartLimitIntervalSec=0\n\n[Service]')
        if kind=='pilot': text+=f'\nEnvironment=SSL_CERT_FILE={root}/probes/ca.pem\n'
        Path('/etc/systemd/system/'+name).write_text(text)
    command(['systemctl','daemon-reload']);command(['systemctl','start',receiver_unit])
    command(['runuser','-u',user,'--','test','-r',scripts/'pilot.py'])
    report=dict(passed=False,package_sha256=args.package_sha256,server_sha256=args.server_sha256,cases=[],scope='owned Ubuntu amd64 systemd services and isolated webhook receiver',business_pilot_started=False,real_operator_delivery_qualified=False)
    mounted=False;override=Path('/etc/systemd/system/openwaf.service.d/99-m2-operational.conf')
    original_override=override.read_text();key=(root/'tls/key.pem').read_bytes()

    def phase(name,healthy):
        sample=command(['systemctl','start',units['pilot']],check=False)
        if sample.returncode!=(0 if healthy else 1):
            (root/'diagnostic.private.txt').write_text(command(['journalctl','-u',units['pilot'],'-n','30','--no-pager'],check=False).stdout)
        assert sample.returncode==(0 if healthy else 1), 'unexpected sampler systemctl result'
        alert=command(['systemctl','start',units['pilot-alerts']],check=False)
        with closing(sqlite3.connect(root/'probes/evidence.db')) as db:
            row=db.execute('SELECT healthy,detail FROM samples ORDER BY started DESC LIMIT 1').fetchone()
        assert bool(row[0])==healthy
        with closing(sqlite3.connect(root/'alerts/outbox.db')) as db:
            pending=db.execute('SELECT count(*) FROM outbox WHERE acked=0').fetchone()[0]
        item=dict(name=name,healthy=healthy,checks=json.loads(row[1])['checks'],health=helper.api(fixture,'health'),watchdog_exit=alert.returncode,pending=pending)
        report['cases'].append(item);save(root/'drill-report.json',report)
        return item

    context=ssl.create_default_context(cafile=str(root/'tls/cert.pem'))
    def traffic(attack=False):
        connection=http.client.HTTPSConnection('application.test',fixture['proxy'],context=context,timeout=20)
        try:
            connection.request('GET','/?drill='+tag+'&q='+('%3Cscript%3Ealert(1)%3C/script%3E' if attack else 'customer+invoice'))
            response=connection.getresponse();body=response.read()
            assert response.status==(403 if attack else 200) and (attack or body==b'backend-ok')
            return response.status
        finally:connection.close()

    try:
        phase('baseline',True)
        # Bad reload retains the last valid certificate and inspecting listener.
        command(['systemctl','stop',receiver_unit])
        (root/'tls/key.pem').write_bytes(b'invalid qualification key')
        try:
            helper.api(fixture,'certificates/reload',{})
            raise AssertionError('invalid certificate activated')
        except urllib.error.HTTPError as error: assert error.code==503
        assert traffic()==200 and traffic(True)==403
        item=phase('certificate-reload-alert-receiver-offline',False)
        assert not item['health']['checks']['certificate_healthy'] and item['pending']>0
        with closing(sqlite3.connect(root/'alerts/outbox.db')) as db:
            original_id=db.execute('SELECT id FROM outbox WHERE acked=0 ORDER BY seq LIMIT 1').fetchone()[0]
        (recv/'mode').write_text('wrong-ack');command(['systemctl','start',receiver_unit])
        item=phase('wrong-alert-acknowledgement',False);assert item['pending']>0
        (recv/'mode').write_text('normal')
        item=phase('alert-retry-after-watchdog-restart',False);assert item['pending']==0
        with closing(sqlite3.connect(recv/'receipts.db')) as db:
            assert db.execute('SELECT count(*) FROM receipts WHERE id=?',(original_id,)).fetchone()[0]==1
            assert db.execute('SELECT count(*) FROM attempts WHERE id=?',(original_id,)).fetchone()[0]>=2
        (root/'tls/key.pem').write_bytes(key);helper.api(fixture,'certificates/reload',{})
        phase('certificate-recovery',True)
        # Requires= intentionally couples explicit service stops to the WAF.
        # Freeze the receiver instead to qualify an unavailable downstream while
        # the inspecting gateway remains up.
        command(['systemctl','kill','--signal=SIGSTOP',fixture['events_unit']]);traffic(True)
        deadline=time.monotonic()+20
        while helper.api(fixture,'health')['checks']['event_delivery_healthy'] and time.monotonic()<deadline:time.sleep(.2)
        item=phase('security-export-outage',False);assert not item['health']['checks']['event_delivery_healthy']
        command(['systemctl','kill','--signal=SIGCONT',fixture['events_unit']]);helper.wait_ready(fixture,drain=True)
        phase('security-export-recovery',True)
        command(['systemctl','kill','--signal=SIGSTOP',fixture['audit_unit']])
        helper.api(fixture,'login',dict(username='qa-viewer',password=fixture['password']))
        deadline=time.monotonic()+20
        while helper.api(fixture,'health')['checks']['administration_export_healthy'] and time.monotonic()<deadline:time.sleep(.2)
        item=phase('audit-export-outage',False);assert not item['health']['checks']['administration_export_healthy']
        command(['systemctl','kill','--signal=SIGCONT',fixture['audit_unit']]);helper.wait_ready(fixture,drain=True)
        phase('audit-export-recovery',True)
        # Real ENOSPC, strictly bounded to an owned 16-MiB tmpfs mount.
        command(['systemctl','stop','openwaf.service'])
        volume=root/'fault-storage';volume.mkdir(mode=0o700)
        command(['mount','-t','tmpfs','-o',f'size=16m,nosuid,nodev,noexec,mode=0700,uid={waf.pw_uid},gid={waf.pw_gid}','tmpfs',volume]);mounted=True
        assert command(['findmnt','-n','-o','FSTYPE','--target',volume]).stdout.strip()=='tmpfs'
        shutil.copyfile(Path(fixture['state'])/'events.db',volume/'events.db');os.chown(volume/'events.db',waf.pw_uid,waf.pw_gid)
        (volume/'events.db').chmod(0o600)
        override.write_text(original_override.replace('-event-db='+fixture['state']+'/events.db','-event-db='+str(volume/'events.db'))+'\nReadWritePaths='+str(volume)+'\n')
        command(['systemctl','daemon-reload']);command(['systemctl','start','openwaf.service']);helper.wait_ready(fixture,drain=True)
        with (volume/'padding').open('wb',buffering=0) as padding:
            try:
                while True: padding.write(b'x'*65536);padding.flush()
            except OSError as error: assert error.errno==errno.ENOSPC
        assert shutil.disk_usage(volume).free==0
        traffic(True)
        item=phase('event-storage-enospc',False)
        status=helper.api(fixture,'status');assert status['summary']['event_persistence_errors']>0
        item['persistence_errors']=status['summary']['event_persistence_errors'];item['isolated_filesystem_bytes']=16<<20
        # Free only generated padding. The failed write remains an explicit
        # incident; process-lifetime loss counters must not reset themselves.
        with (volume/'padding').open('wb'):pass
        assert not helper.api(fixture,'health')['healthy']
        command(['systemctl','stop','openwaf.service'])
        old=Path(fixture['state'])/'events.db';old.rename(root/'events.pre-storage.db')
        shutil.copyfile(volume/'events.db',old);os.chown(old,waf.pw_uid,waf.pw_gid)
        old.chmod(0o600)
        shutil.copyfile(volume/'events.db',root/'events.post-storage.db')
        (root/'events.post-storage.db').chmod(0o600)
        command(['umount',volume]);mounted=False
        override.write_text(original_override);command(['systemctl','daemon-reload']);command(['systemctl','start','openwaf.service']);helper.wait_ready(fixture,drain=True)
        traffic(True);helper.wait_ready(fixture,drain=True)
        phase('storage-recovery-and-replayed-attack',True)
        # Wait actual wall time; never fabricate a pilot record or its timestamp.
        command(['systemctl','stop',units['pilot']])
        print('Waiting for the real missing-sample threshold',file=sys.stderr,flush=True)
        time.sleep(pilot.MAX_GAP+2)
        result=command(['systemctl','start',units['pilot-alerts']],check=False);assert result.returncode!=0
        with closing(sqlite3.connect(root/'alerts/outbox.db')) as db:
            active=json.loads(db.execute('SELECT active FROM meta').fetchone()[0])
            assert active['reason']=='samples_missing'
        report['cases'].append(dict(name='missing-samples-real-time',healthy=False,waited_seconds=pilot.MAX_GAP+2,reason=active['reason']))
        phase('sampling-resumed',True)
        # Exercise unreadable evidence without altering a captured pilot record.
        path=root/'probes/evidence.db';path.chmod(0o000)
        result=command(['systemctl','start',units['pilot-alerts']],check=False);assert result.returncode!=0
        path.chmod(0o600);phase('evidence-read-recovery',True)
        report.update(passed=True,wrong_ack_retried_same_identity=True,receiver_deduplicated=True,storage_fault_unacknowledged_attempts=1)
        helper.wait_ready(fixture,drain=True);snapshot=helper.snapshot(fixture);helper.verify(fixture,snapshot)
        report['delivery_verification']=dict(events=len(snapshot['events']),audit_records=len(snapshot['audit']))
    finally:
        (root/'tls/key.pem').write_bytes(key)
        for unit in [fixture['events_unit'],fixture['audit_unit']]:
            command(['systemctl','kill','--signal=SIGCONT',unit],check=False)
        command(['systemctl','stop',units['pilot'],units['pilot-alerts'],'openwaf.service',*fixture['units'],receiver_unit],check=False)
        if mounted:
            # Keep the failed database before unmounting this owned tmpfs.
            shutil.copyfile(root/'fault-storage/events.db',root/'events.failed-storage.db')
            (root/'events.failed-storage.db').chmod(0o600)
            command(['umount',root/'fault-storage'],check=False)
        override.write_text(original_override);command(['systemctl','daemon-reload'])
        save(root/'drill-report.json',report)
        archive=root/'fault-evidence.private.tar.gz'
        with tarfile.open(archive,'w:gz') as tar:
            for name in ['state','collector','audit','probes','alerts','alert-receiver','drill-report.json','scripts',*(['diagnostic.private.txt'] if (root/'diagnostic.private.txt').exists() else [])]:
                tar.add(root/name,arcname=name)
        archive.chmod(0o600);qualifier=pwd.getpwnam('qualifier');os.chown(archive,qualifier.pw_uid,qualifier.pw_gid)
        report['capture_sha256']=digest(archive);save(root/'result.json',report)
    print(json.dumps(report))


if __name__=='__main__': main()
