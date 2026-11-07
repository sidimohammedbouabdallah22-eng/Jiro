"""A separate adverse boundary: genuine second clients, not forged headers."""
import argparse
import base64
from concurrent.futures import ThreadPoolExecutor
import http.client
import importlib.util
import json
from pathlib import Path
import time

from joint_fair_lab import FairLab
from joint_business_lab import sha

spec=importlib.util.spec_from_file_location('fair',Path(__file__).with_name('qualify-joint-fairness.py'))
fair=importlib.util.module_from_spec(spec);spec.loader.exec_module(fair)


class MultiSourceLab(FairLab):
    def send(self,app,label,method,path,body=None,headers=None,validate=None):
        if getattr(self.timing,'role',None)=='abuse':
            worker=int(self.timing.sequence.rsplit('-',2)[1])
            self.timing.lane='attacker' if worker<2 else 'second-attacker'
            # Keep each body small enough to isolate admission starvation from
            # the already-known long Unicode inspection timeout limitation.
            body=fair.abuse.body_bytes(32<<10,'unicode')
        return super().send(app,label,method,path,body,headers,validate)


def held_boundary(lab,product,ref,files):
    slots,client_slots=lab.report['limits']['application_slots'],lab.report['limits']['client_slots']
    fair.set_policy(lab,slots,client_slots,2);lab.drain();held=[];body=fair.abuse.body_bytes(32<<10,'ascii')
    key={'DOLAPIKEY':lab.fixture['dolibarr']['api_key']}
    try:
        for app in ['dolibarr','prestashop']:
            for lane in ['attacker']*client_slots+['second-attacker']*(slots-client_slots):
                c=http.client.HTTPConnection('127.0.0.1',lab.lanes[lane]['port'],timeout=45);begin=time.perf_counter()
                c.putrequest('POST','/api/index.php/thirdparties' if app=='dolibarr' else product,skip_host=True)
                c.putheader('Host',('erp' if app=='dolibarr' else 'shop')+'.joint.test:'+str(lab.ports['proxy']))
                c.putheader('Content-Type','application/json');c.putheader('Content-Length',str(len(body)))
                c.putheader('User-Agent','OpenWAF owned held-source boundary');c.putheader('X-Forwarded-For','198.51.100.200')
                if app=='dolibarr':c.putheader('DOLAPIKEY',key['DOLAPIKEY'])
                c.endheaders();c.send(body[:1024]);held.append((c,app,lane,begin))
        deadline=time.monotonic()+5
        while lab.admin('status')['resources']['active']!=2*slots:
            assert time.monotonic()<deadline;time.sleep(.05)
        occupied=lab.admin('status')['resources']
        lab.timing.role='held-legitimate';lab.timing.lane='storefront';lab.timing.sequence='held-shop';lab.timing.due=time.perf_counter()
        code,_=lab.send('prestashop','held-boundary','GET',product,validate=lambda c,d:c==503 and b'Application admission share exhausted' in d);assert code==503
        lab.timing.lane='upload';lab.timing.sequence='held-upload';lab.timing.due=time.perf_counter()
        content=b'a'*(700<<10);name='fair-'+lab.tag+'-held-refused.csv'
        payload=json.dumps(dict(filename=name,modulepart='invoice',ref=ref,filecontent=base64.b64encode(content).decode(),fileencoding='base64',overwriteifexists=0),separators=(',',':')).encode()
        code,_=lab.send('dolibarr','held-boundary','POST','/api/index.php/documents/upload',payload,key,
                        lambda c,d:c==503 and b'Application admission share exhausted' in d);assert code==503
        files.append(dict(name=name,ref=ref,kind='api',bytes=len(content),sha256=sha(content),committed=False))
        def finish(item):
            c,app,lane,begin=item
            row=dict(app=app,label='held-boundary',sequence=app+'-'+lane,lane=lane,peer=lab.lanes[lane]['peer'],role='held-abuse',
                     start_delay_ms=0,request_bytes=len(body),request_sha256=sha(body),status=0,valid=False)
            try:
                c.send(body[1024:]);response=c.getresponse();data=response.read(2<<20)
                row.update(status=response.status,response_bytes=len(data),response_sha256=sha(data),request_id=response.getheader('X-OpenWAF-Request-ID'))
                row['valid']=fair.abuse.missing_name(response.status,data) if app=='dolibarr' else response.status==200 and b'OpenWAF Qualification Product' in data
                assert row['valid']
            except Exception as error:row['error']=type(error).__name__;raise
            finally:
                elapsed=(time.perf_counter()-begin)*1000;row.update(service_ms=elapsed,scheduled_ms=elapsed)
                with lab.lock:lab.records.append(row)
                c.close()
        with ThreadPoolExecutor(max_workers=2*slots) as pool:list(pool.map(finish,held))
        recovered=lab.drain()
        lab.report['held_boundary']=dict(occupied_resources=occupied,legitimate_storefront_status=503,legitimate_upload_status=503,
                                        body_bytes=len(body),refused_file=name,recovered_resources=recovered['resources'],admission_guarantee=False)
        lab.save();print('Two-source held boundary: legitimate requests refused; all held work reclaimed',flush=True)
    finally:
        for c,*_ in held:c.close()


def main():
    if not __debug__:raise RuntimeError('qualification requires assertions')
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--package',type=Path,required=True)
    p.add_argument('--disposable-vm',action='store_true',required=True);p.add_argument('--seconds',type=int,default=80)
    p.add_argument('--vcpus',type=int,choices=[1,2,4],default=1)
    p.add_argument('--admission-wait-ms',type=int,default=1000)
    p.add_argument('--client-slots',type=int,choices=[1,2,3],default=3)
    p.add_argument('--slots',type=int,default=4)
    p.add_argument('--client-buffer-mib',type=int,default=5)
    p.add_argument('--client-burst',type=int,default=4)
    p.add_argument('--recheck-failed-run',type=Path,action='append',default=[])
    a=p.parse_args();assert 60<=a.seconds<=180 and a.seconds%20==0
    assert 0<=a.admission_wait_ms<=1000
    assert 0<=a.client_buffer_mib<=64 and 1<=a.client_burst<=20
    sources=['qualify-joint-multisource.py','qualify-joint-fairness.py','joint_fair_lab.py','joint_business_lab.py',
             'qualify-joint-abuse.py','m4_joint_abuse_state.php','m4_joint_store_state.php','m4_joint_fair_guest.py',
             'm4_joint_business_guest.py','m4_joint_domains.php','m4_joint_files.php','m4_business_guest.py',
             'joint_upload_data.py','check-joint-multisource-evidence.py','reject-multisource-evidence-mutations.py']
    lab=MultiSourceLab(a.package,sources,vcpus=a.vcpus);files=[]
    slots=a.slots;assert a.client_slots<slots<=2*a.client_slots
    lab.report.update(uploads=[],screen_only=True,source_boundary=True,abuse_body_bytes=32768,
                      admission_wait_ms=a.admission_wait_ms,
                      upload_format='mixed-csv',upload_fixture_sha256=sha(fair.upload_content('mixed-csv')),
                      limits=dict(application_slots=slots,client_slots=a.client_slots,client_rate=2,
                                  client_buffer_mib=a.client_buffer_mib,client_burst=a.client_burst,request_limit=1048576),
                      experiment='two genuine hostile source addresses per app; no universal fairness claim')
    (lab.out/'upload-content.bin').write_bytes(fair.upload_content('mixed-csv'))
    try:
        lab.start();original=lab.admin('config');lab.report['original_policy']=original
        lab.report['customers_before']=fair.abuse.customer_state(lab);lab.report['store_before']=fair.store_state(lab)
        lab.report['prior_run_rechecks']=[]
        for old_path in a.recheck_failed_run:
            old_path=old_path.resolve(strict=True)
            assert old_path.parent.parent==lab.repo/'artifacts' and old_path.name=='result.json'
            old=json.loads(old_path.read_text());assert not old['passed']
            manifest=old_path.parent/'files.json';old_files=json.loads(manifest.read_text())
            assert old['customers_before']==lab.report['customers_before'] and old['store_before']==lab.report['store_before']
            probe=lab.guest('files',dict(files=old_files));assert probe['passed']
            lab.report['prior_run_rechecks'].append(dict(artifact=old_path.parent.name,
                result_sha256=sha(old_path.read_bytes()),files_manifest_sha256=sha(manifest.read_bytes()),
                file_probe=probe,protected_state_unchanged=True))
            lab.save()
        product=fair.urllib.parse.urlsplit(lab.fixture['prestashop']['routes']['product']);product=product.path+('?' +product.query if product.query else '')
        workflow=json.loads((lab.repo/'artifacts/m4-business-2be162b6/results-19.json').read_text())
        invoice=next(c['invoice_id'] for c in workflow['cases'] if c['name']=='create, price and validate invoice')
        key={'DOLAPIKEY':lab.fixture['dolibarr']['api_key']}
        _,data=lab.send('dolibarr','invoice-preflight','GET','/api/index.php/invoices/'+str(invoice),headers=key,validate=lambda c,d:c==200);ref=json.loads(data)['ref']
        lab.send('prestashop','product-preflight','GET',product,validate=lambda c,d:c==200 and b'OpenWAF Qualification Product' in d)
        assert lab.records[-1]['valid']
        fair.phase(lab,'baseline',60,[],product,ref,files,slots,a.client_slots,2,True)
        held_boundary(lab,product,ref,files)
        supported=fair.phase(lab,'multi-source',a.seconds,['dolibarr','prestashop'],product,ref,files,slots,a.client_slots,2,False)
        lab.report['responsiveness_passed']=supported
        lab.report['files_verified']=lab.guest('files',dict(files=files))
        lab.report['customers_after']=fair.abuse.customer_state(lab);lab.report['store_after']=fair.store_state(lab)
        assert lab.report['customers_before']==lab.report['customers_after'] and lab.report['store_before']==lab.report['store_after']
        restore=dict(original,revision=lab.admin('config')['revision'])
        lab.admin('config/apply',dict(config=restore,reason='Restore owned policy after multi-source admission boundary screen'))
        lab.report['restored_policy']=lab.admin('config');assert original['applications']==lab.report['restored_policy']['applications']
        lab.report['final_status']=lab.drain();assert lab.report['final_status']['summary']['requests']==len(lab.records)
        lab.report['spool_after']=lab.guest('spool');assert lab.report['spool_after']['files']==lab.report['spool_after']['bytes']==0
        lab.capture()
        for name,digest in lab.report['sources'].items():assert sha((lab.repo/'scripts'/name).read_bytes())==digest
        lab.report['passed']=True # Integrity/evidence only; responsiveness has its own result.
    finally:
        (lab.out/'files.json').write_text(json.dumps(files));lab.close()
    assert lab.report['passed'] and lab.report['cleanup']['restored'] and lab.report['vm_powered_off']


if __name__=='__main__':main()
