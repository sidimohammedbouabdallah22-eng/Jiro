"""Bidirectional sustained abuse with real client addresses and real large uploads."""
import argparse
import base64
from collections import Counter
from concurrent.futures import ThreadPoolExecutor
import importlib.util
import json
from pathlib import Path
import shlex
import threading
import time
import urllib.parse

from joint_fair_lab import FairLab
from joint_business_lab import resources,sha
from joint_upload_data import upload_content

spec=importlib.util.spec_from_file_location('abuse',Path(__file__).with_name('qualify-joint-abuse.py'))
abuse=importlib.util.module_from_spec(spec);spec.loader.exec_module(abuse)


def refused(code,data):
    return (code==503 and b'share exhausted' in data) or (code==429 and
        (b'request rate exceeded' in data or data==b'Client request body rate exceeded\n'))


def p95(values):
    values=sorted(values);return round(values[int((len(values)-1)*.95)],3) if values else None


def store_state(lab):
    container=lab.fixture['prestashop']['containers']['app'];path='/tmp/openwaf-store-state.php'
    lab.run([*lab.ssh,shlex.join(['sudo','docker','cp',lab.remote+'/m4_joint_store_state.php',container+':'+path])])
    output=lab.run([*lab.ssh,shlex.join(['sudo','docker','exec','-u','www-data',container,'php',path])]).stdout
    return json.loads(output.split('OPENWAF_STORE_STATE:')[1])


def set_policy(lab,slots,client_slots,rate):
    config=lab.admin('config')
    for app in config['applications']:
        app['policy']['request_limit']=1048576
        app['traffic_controls']=dict(max_concurrent=slots,max_client_concurrent=client_slots,
                                     client_requests_per_second=rate,client_burst=lab.report['limits'].get('client_burst',rate),
                                     max_client_buffer_mib=lab.report['limits'].get('client_buffer_mib',0),
                                     admission_wait_ms=lab.report.get('admission_wait_ms',0))
    lab.admin('config/apply',dict(config=config,reason='Owned M4 bidirectional abuse: preserve 1-MiB envelopes and bound actual clients'))
    actual=lab.admin('config')
    for app in actual['applications']:
        assert app['policy']['request_limit']==1048576
        assert app['traffic_controls']['max_concurrent']==slots and app['traffic_controls']['max_client_concurrent']==client_slots
        assert app['traffic_controls'].get('admission_wait_ms',0)==lab.report.get('admission_wait_ms',0)
        assert app['traffic_controls'].get('max_client_buffer_mib',0)==lab.report['limits'].get('client_buffer_mib',0)
        assert app['traffic_controls']['client_burst']==lab.report['limits'].get('client_burst',rate)
    return actual


def phase(lab,name,seconds,targets,product,invoice_ref,files,slots,client_slots,rate,required):
    config=set_policy(lab,slots,client_slots,rate);before=lab.drain();begin=lab.guest('mark')
    first=len(lab.records);flow_first=len(lab.report['uploads']);start=time.perf_counter()
    lab.report['active_phase']=dict(name=name,policy=config,guest_begin=begin,targets=targets,seconds=seconds)
    lab.save();stop=threading.Event();errors=[];mutex=threading.Lock();key={'DOLAPIKEY':lab.fixture['dolibarr']['api_key']}
    heavy=abuse.body_bytes(900<<10,'unicode');content=upload_content(lab.report.get('upload_format','uniform'))

    def shop(i,due):
        lab.timing.due=due;lab.timing.sequence='shop-'+str(i);lab.timing.lane='storefront';lab.timing.role='legit-shop'
        try:lab.send('prestashop',name,'GET',product,validate=lambda c,d:(c==200 and b'OpenWAF Qualification Product' in d) or refused(c,d))
        except Exception as e:
            with mutex:errors.append(type(e).__name__)

    def upload(i,due):
        lab.timing.due=due;lab.timing.sequence='upload-'+str(i);lab.timing.lane='upload';lab.timing.role='legit-upload'
        filename='fair-'+lab.tag+'-'+name+'-'+str(i)+'.csv'
        body=json.dumps(dict(filename=filename,modulepart='invoice',ref=invoice_ref,filecontent=base64.b64encode(content).decode(),fileencoding='base64',overwriteifexists=0),separators=(',',':')).encode()
        flow=dict(phase=name,sequence=i,name=filename,passed=False)
        try:
            code,reply=lab.send('dolibarr',name,'POST','/api/index.php/documents/upload',body,key,
                                validate=lambda c,d:c==200 or refused(c,d))
            with mutex:files.append(dict(name=filename,ref=invoice_ref,kind='api',bytes=len(content),sha256=sha(content),committed=code==200))
            flow['upload_status']=code
            if code==200:
                lab.timing.due=time.perf_counter();lab.timing.sequence='download-'+str(i);lab.timing.role='legit-download'
                def downloaded(c,d):
                    if refused(c,d):return True
                    try:return c==200 and base64.b64decode(json.loads(d)['content'])==content
                    except (ValueError,KeyError,TypeError):return False
                code,reply=lab.send('dolibarr',name,'GET','/api/index.php/documents/download?modulepart=invoice&original_file='+urllib.parse.quote(invoice_ref+'/'+filename),headers=key,validate=downloaded)
                flow['download_status']=code;flow['passed']=code==200 and base64.b64decode(json.loads(reply)['content'])==content
        except Exception as e:
            flow['error']=type(e).__name__
            with mutex:errors.append(type(e).__name__)
        finally:
            flow['scheduled_ms']=(time.perf_counter()-due)*1000
            with mutex:lab.report['uploads'].append(flow)

    def burner(app,worker):
        lab.timing.lane='attacker';lab.timing.role='abuse';stop.wait(worker/4);i=0
        while not stop.is_set() and time.perf_counter()<start+seconds:
            due=time.perf_counter();lab.timing.due=due;lab.timing.sequence=app+'-burn-'+str(worker)+'-'+str(i)
            headers={'X-Forwarded-For':'198.51.100.'+str(1+(i+worker)%250)}
            if app=='dolibarr':headers.update(key)
            def valid(c,d):
                if refused(c,d):return True
                return abuse.missing_name(c,d) if app=='dolibarr' else c==200 and b'OpenWAF Qualification Product' in d
            try:lab.send(app,name,'POST','/api/index.php/thirdparties' if app=='dolibarr' else product,heavy,headers,valid)
            except Exception as e:
                with mutex:errors.append(type(e).__name__)
            i+=1;stop.wait(max(0,1-(time.perf_counter()-due)))

    threads=[threading.Thread(target=burner,args=(app,i),daemon=True) for app in targets for i in range(4)]
    for t in threads:t.start()
    with ThreadPoolExecutor(max_workers=8) as pool:
        jobs=[]
        schedule=sorted([(i,'shop',i) for i in range(seconds)]+[(i*20,'upload',i) for i in range(seconds//20)])
        for offset,kind,i in schedule:
            due=start+offset;time.sleep(max(0,due-time.perf_counter()));jobs.append(pool.submit(shop if kind=='shop' else upload,i,due))
            if kind=='shop' and i and i%30==0:
                lab.save();print(name+': scheduled '+str(i)+'/'+str(seconds),flush=True)
        time.sleep(max(0,start+seconds-time.perf_counter()));workload_end=lab.guest('mark');stop.set()
        for t in threads:t.join(timeout=90);assert not t.is_alive(),'inspection must finish before releasing reservations'
        for job in jobs:job.result()
    after=lab.drain();end=lab.guest('mark');rows=lab.records[first:];flows=lab.report['uploads'][flow_first:]
    shop_rows=[r for r in rows if r['role']=='legit-shop'];abuse_rows=[r for r in rows if r['role']=='abuse']
    assert len(shop_rows)==seconds and len(flows)==seconds//20
    raw=lab.run([*lab.ssh,'sudo cat '+lab.root+'/resources.jsonl']).stdout;sampled=resources(raw,begin,workload_end,lab.vcpus)
    integrity=not errors and all(r['valid'] for r in rows)
    late=sum(r['start_delay_ms']>100 for r in rows if r['role'] in ['legit-shop','legit-upload'])
    accepted=integrity and all(r['status']==200 for r in shop_rows) and all(f['passed'] for f in flows) and p95([r['scheduled_ms'] for r in shop_rows])<=2000 and p95([f['scheduled_ms'] for f in flows])<=10000 and late<=(seconds+seconds//20)*.01
    facts=dict(name=name,seconds=seconds,targets=targets,policy=config,required=required,requests=len(rows),
               storefront_requests=len(shop_rows),upload_workflows=len(flows),abuse_requests=len(abuse_rows),
               statuses=dict(Counter(str(r['status']) for r in rows)),abuse_statuses=dict(Counter(str(r['status']) for r in abuse_rows)),
               storefront_p95_ms=p95([r['scheduled_ms'] for r in shop_rows]),upload_workflow_p95_ms=p95([f['scheduled_ms'] for f in flows]),
               legitimate_late_over_100ms=late,integrity_passed=integrity,responsiveness_passed=accepted,errors=errors,
               before=before,after=after,guest_begin=begin,guest_workload_end=workload_end,guest_end=end,resources=sampled)
    lab.report['phases'].append(facts);lab.report.pop('active_phase',None);lab.save()
    (lab.out/'files.json').write_text(json.dumps(files))
    print(name+': integrity='+str(integrity)+' responsiveness='+str(accepted)+' shop p95='+str(facts['storefront_p95_ms'])+'ms',flush=True)
    assert integrity,'unexpected transport/inspection failure'
    assert not required or accepted,'required responsiveness or upload budget failed'
    return accepted


def main():
    if not __debug__:raise RuntimeError('qualification requires assertions')
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--package',type=Path,required=True)
    p.add_argument('--disposable-vm',required=True,action='store_true');p.add_argument('--seconds',type=int,default=300)
    p.add_argument('--slots',type=int,default=2);p.add_argument('--client-slots',type=int,default=1);p.add_argument('--client-rate',type=int,default=2)
    p.add_argument('--client-burst',type=int)
    p.add_argument('--client-buffer-mib',type=int,default=0)
    p.add_argument('--screen',action='store_true',help='Retain failed responsiveness screens without claiming support')
    p.add_argument('--admission-wait-ms',type=int,default=0)
    p.add_argument('--upload-format',choices=['uniform','mixed-csv'],default='uniform')
    p.add_argument('--recheck-failed-run',type=Path)
    p.add_argument('--vcpus',type=int,choices=[1,2,4],default=1)
    p.add_argument('--trace-upstream',action='store_true',help='Private bounded TCP diagnostics; screen only')
    a=p.parse_args();assert 60<=a.seconds<=900 and a.seconds%20==0 and 1<=a.slots<=8 and 0<=a.client_slots<=a.slots and 0<=a.client_rate<=10
    assert 0<=a.admission_wait_ms<=1000
    burst=a.client_rate if a.client_burst is None else a.client_burst
    assert 0<=burst<=20 and (burst==0)==(a.client_rate==0) and 0<=a.client_buffer_mib<=64
    assert not a.trace_upstream or a.screen
    sources=['qualify-joint-fairness.py','joint_fair_lab.py','joint_business_lab.py','qualify-joint-abuse.py',
             'm4_joint_abuse_state.php','m4_joint_store_state.php','m4_joint_fair_guest.py','m4_joint_business_guest.py',
             'm4_joint_domains.php','m4_joint_files.php','m4_business_guest.py',
             'check-joint-fairness-evidence.py','reject-fairness-evidence-mutations.py','joint_upload_data.py']
    lab=FairLab(a.package,sources,vcpus=a.vcpus,upstream_trace=a.trace_upstream);files=[]
    lab.report.update(experiment='real peer-address admission; bidirectional/simultaneous abuse with 700-KiB round trips',
                      admission_wait_ms=a.admission_wait_ms,upload_format=a.upload_format,
                      upload_fixture_sha256=sha(upload_content(a.upload_format)),
                      uploads=[],screen_only=a.screen,budgets=dict(storefront_p95_ms=2000,upload_workflow_p95_ms=10000,late_fraction=.01),
                      limits=dict(application_slots=a.slots,client_slots=a.client_slots,client_rate=a.client_rate,
                                  client_burst=burst,client_buffer_mib=a.client_buffer_mib,request_limit=1048576))
    (lab.out/'upload-content.bin').write_bytes(upload_content(a.upload_format))
    try:
        lab.start();original=lab.admin('config');lab.report['original_policy']=original
        lab.report['customers_before']=abuse.customer_state(lab);lab.report['store_before']=store_state(lab)
        if a.recheck_failed_run:
            old_path=a.recheck_failed_run.resolve(strict=True)
            assert old_path.parent.parent==lab.repo/'artifacts' and old_path.name=='result.json'
            old=json.loads(old_path.read_text());assert not old['passed']
            old_files=json.loads((old_path.parent/'files.json').read_text())
            recheck=lab.guest('files',dict(files=old_files))
            assert recheck['passed'] and old['customers_before']==lab.report['customers_before'] and old['store_before']==lab.report['store_before']
            lab.report['prior_run_recheck']=dict(artifact=old_path.parent.name,result_sha256=sha(old_path.read_bytes()),
                                                file_probe=recheck,business_state_unchanged=True)
        product=urllib.parse.urlsplit(lab.fixture['prestashop']['routes']['product']);product=product.path+('?' +product.query if product.query else '')
        workflow=json.loads((lab.repo/'artifacts/m4-business-2be162b6/results-19.json').read_text())
        invoice=next(c['invoice_id'] for c in workflow['cases'] if c['name']=='create, price and validate invoice')
        key={'DOLAPIKEY':lab.fixture['dolibarr']['api_key']}
        _,data=lab.send('dolibarr','invoice-preflight','GET','/api/index.php/invoices/'+str(invoice),headers=key,validate=lambda c,d:c==200)
        ref=json.loads(data)['ref']
        lab.timing.lane='attacker'
        lab.send('prestashop','post-preflight','POST',product,abuse.body_bytes(1024,'ascii'),validate=lambda c,d:c==200 and b'OpenWAF Qualification Product' in d)
        assert lab.records[-1]['valid'],'storefront POST probe did not reach a read-only product view'
        for lane in ['attacker','second-attacker']:
            lab.timing.lane=lane
            code,_=lab.send('dolibarr','identity-xss','POST','/api/index.php/thirdparties',abuse.body_bytes(1024,'attack'),
                            {**key,'X-Forwarded-For':'198.51.100.200'},lambda c,d:c==403);assert code==403
        phase(lab,'baseline',60,[],product,ref,files,a.slots,a.client_slots,a.client_rate,True)
        for name,targets in [('erp-abuse',['dolibarr']),('storefront-abuse',['prestashop']),('simultaneous-abuse',['dolibarr','prestashop'])]:
            phase(lab,name,a.seconds,targets,product,ref,files,a.slots,a.client_slots,a.client_rate,not a.screen)
        lab.report['files_verified']=lab.guest('files',dict(files=files))
        lab.report['customers_after']=abuse.customer_state(lab);lab.report['store_after']=store_state(lab)
        assert lab.report['customers_before']==lab.report['customers_after'] and lab.report['store_before']==lab.report['store_after']
        restore=dict(original,revision=lab.admin('config')['revision'])
        lab.admin('config/apply',dict(config=restore,reason='Restore owned joint policy after sustained fairness test'))
        lab.report['restored_policy']=lab.admin('config');assert lab.report['restored_policy']['applications']==original['applications']
        lab.report['final_status']=lab.drain();assert lab.report['final_status']['summary']['requests']==len(lab.records)
        lab.report['spool_after']=lab.guest('spool');assert lab.report['spool_after']['files']==lab.report['spool_after']['bytes']==0
        lab.capture()
        for name,digest in lab.report['sources'].items():assert sha((lab.repo/'scripts'/name).read_bytes())==digest
        lab.report['measurement_integrity_passed']=True
        lab.report['responsiveness_passed']=all(p['responsiveness_passed'] for p in lab.report['phases'])
        lab.report['sustained_profile_qualified']=not a.screen and a.seconds>=300 and lab.report['responsiveness_passed']
        lab.report['passed']=True
    finally:
        (lab.out/'files.json').write_text(json.dumps(files));lab.close()
    assert lab.report['passed'] and lab.report['cleanup']['restored'] and lab.report['vm_powered_off']


if __name__=='__main__':main()
