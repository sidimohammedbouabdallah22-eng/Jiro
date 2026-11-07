"""External offered-load profiles of a functionally qualified business cohort."""
import argparse
from concurrent.futures import ThreadPoolExecutor
import hashlib
import http.client
import importlib.util
import json
from pathlib import Path
import re
import shlex
import socket
import subprocess
import threading
import time
import urllib.parse
import uuid


def sha(path):return hashlib.sha256(path.read_bytes()).hexdigest()


def percentile(values,p):
    values=sorted(values);return round(values[int((len(values)-1)*p)],3) if values else None


def resource_summary(rows,begin,end):
    rows=[row for row in rows if begin<=row['monotonic']<=end]
    assert len(rows)>=2 and rows[0]['monotonic']-begin<=6 and end-rows[-1]['monotonic']<=6
    assert all(b['monotonic']-a['monotonic']<=6 for a,b in zip(rows,rows[1:]))
    span=rows[-1]['monotonic']-rows[0]['monotonic'];assert span>30
    result=dict(samples=len(rows),sampled_seconds=span,processes={},containers={},min_host_available_kib=min(r['host_available_kib'] for r in rows))
    for name in ['gateway','collector','relay']:
        values=[r['processes'][name] for r in rows];assert all(not r.get('unavailable') for r in values)
        assert len({r['pid'] for r in values})==1
        result['processes'][name]=dict(cpu_percent_one_vcpu=100*(values[-1]['cpu_seconds']-values[0]['cpu_seconds'])/span,peak_rss_kib=max(r['rss_kib'] for r in values),pid=values[0]['pid'])
    for name in rows[0]['containers']:
        values=[r['containers'][name] for r in rows];assert all(not r.get('unavailable') for r in values)
        result['containers'][name]=dict(cpu_percent_one_vcpu=100*(values[-1]['cpu_seconds']-values[0]['cpu_seconds'])/span,peak_memory_bytes=max(r['memory_bytes'] for r in values))
    first,last=rows[0]['host_cpu_ticks'],rows[-1]['host_cpu_ticks'];total=sum(last[:8])-sum(first[:8])
    result['host_busy_percent']=100*(1-((last[3]+last[4])-(first[3]+first[4]))/total)
    result['component_cpu_sum_percent']=sum(value['cpu_percent_one_vcpu'] for value in result['processes'].values())+sum(value['cpu_percent_one_vcpu'] for value in result['containers'].values())
    result['max_observed_cpu_percent']=max(result['host_busy_percent'],result['component_cpu_sum_percent'])
    return result


def accepted(phase):
    return (phase['functional_passed'] and phase['p95_scheduled_ms']<=2000 and phase['late_over_100ms']<=phase['planned']*.01
            and max(phase['resources']['host_busy_percent'],sum(value['cpu_percent_one_vcpu'] for value in phase['resources']['processes'].values())+sum(value['cpu_percent_one_vcpu'] for value in phase['resources']['containers'].values()))<=85 and phase['resources']['processes']['gateway']['cpu_percent_one_vcpu']<=80
            and phase['resources']['min_host_available_kib']>=512*1024)


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--fixture',type=Path,required=True);parser.add_argument('--workflow-report',type=Path,required=True)
    parser.add_argument('--endurance-seconds',type=int,default=600);parser.add_argument('--disposable-vm',action='store_true',required=True)
    args=parser.parse_args();repo=Path(__file__).resolve().parents[1]
    assert 300<=args.endurance_seconds<=1800
    private=args.fixture.resolve(strict=True);assert (repo/'artifacts').resolve() in private.parents
    f=json.loads(private.read_text());workflow=json.loads(args.workflow_report.read_text())
    assert workflow['passed'] and workflow['functional_passed'] and workflow['app']==f['app']
    assert workflow['server_sha256']==f['waf-server_sha256'] and workflow['package_sha256']==f['package_sha256']
    vm=Path(f['vm_dir']);assert vm.parent.resolve()==(repo/'artifacts/m2-vms').resolve()
    tag=uuid.uuid4().hex[:8];out=repo/'artifacts'/('m4-business-capacity-'+tag);out.mkdir()
    spec=importlib.util.spec_from_file_location('permissions',repo/'scripts/qualify-applications.py');permissions=importlib.util.module_from_spec(spec);spec.loader.exec_module(permissions);permissions.restrict_artifacts(out)
    sources=out/'source';sources.mkdir();hashes={}
    for name in ['qualify-business-capacity.py','m4_business_capacity_guest.py','m4_business_guest.py']:
        data=(repo/'scripts'/name).read_bytes();(sources/name).write_bytes(data);hashes[name]=hashlib.sha256(data).hexdigest()
    report=dict(passed=False,app=f['app'],vm=vm.name,package_sha256=f['package_sha256'],server_sha256=f['waf-server_sha256'],workflow_sha256=sha(args.workflow_report),workflow_report=str(args.workflow_report),sources=hashes,phases=[],budgets=dict(p95_scheduled_ms=2000,host_busy_percent=85,gateway_cpu_percent_one_vcpu=80,min_host_available_kib=512*1024),endurance_seconds=args.endurance_seconds)
    (sources/'workflow-report.json').write_bytes(args.workflow_report.read_bytes())
    vbox=r'C:\Program Files\Oracle\VirtualBox\VBoxManage.exe'
    def run(argv,timeout=180,check=True):
        r=subprocess.run([str(x) for x in argv],capture_output=True,text=True,timeout=timeout)
        if check and r.returncode:
            (out/'failure.private.txt').write_text(r.stdout+r.stderr);raise RuntimeError('controlled capacity command failed; private evidence: '+str(out))
        return r
    def info():
        for _ in range(60):
            r=run([vbox,'showvminfo',vm.name,'--machinereadable'],check=False)
            if r.returncode==0:return r.stdout
            time.sleep(1)
        raise RuntimeError('VM metadata unavailable')
    metadata=info();assert 'cpus=1\n' in metadata and 'memory=4096\n' in metadata
    port=re.search(r'Forwarding\(0\)="ssh,tcp,127\.0\.0\.1,(\d+),,22"',metadata)[1]
    opts=['-i',vm/'identity','-o','BatchMode=yes','-o','ConnectTimeout=5','-o','ServerAliveInterval=5','-o','ServerAliveCountMax=3','-o','UserKnownHostsFile='+str(vm/'known_hosts')]
    ssh=['ssh',*opts,'-p',port,'qualifier@127.0.0.1'];scp=['scp',*opts,'-P',port]
    remote='/tmp/business-capacity-'+tag;tunnel=None;started=False
    def guest(op):return json.loads(run([*ssh,shlex.join(['sudo','python3',remote+'/m4_business_capacity_guest.py',op,'--root',f['root'],'--tag',tag,'--server-sha256',f['waf-server_sha256']])]).stdout)
    def status():
        code,body=send('GET','/api/v1/status',None,{'Authorization':'Bearer '+f['token']},f['ports']['admin']);assert code==200;return json.loads(body)
    def send(method,path,body=None,headers=None,port=None):
        c=http.client.HTTPConnection('127.0.0.1',port or f['ports']['proxy'],timeout=20)
        try:
            c.request(method,path,body=body,headers={'Host':'localhost:'+str(f['ports']['proxy']),'Content-Type':'application/json','User-Agent':'OpenWAF business capacity',**(headers or {})})
            response=c.getresponse();data=response.read((2<<20)+1);assert len(data)<=2<<20
            return response.status,data
        finally:c.close()
    try:
        if 'VMState="poweroff"' in metadata:run([vbox,'startvm',vm.name,'--type','headless'])
        for _ in range(90):
            if run([*ssh,'true'],check=False).returncode==0:break
            time.sleep(2)
        else:raise RuntimeError('SSH unavailable')
        run([*ssh,'mkdir -m 700 '+remote]);run([*scp,*sources.iterdir(),'qualifier@127.0.0.1:'+remote+'/'])
        report['environment']=guest('start');started=True
        forwards=[]
        for value in f['ports'].values():forwards+=['-L',f'127.0.0.1:{value}:127.0.0.1:{value}']
        tunnel=subprocess.Popen([str(x) for x in [*ssh[:-1],'-N','-o','ExitOnForwardFailure=yes',*forwards,ssh[-1]]],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL);time.sleep(1);assert tunnel.poll() is None
        key={'DOLAPIKEY':f['api_key']};customer=None;download=None;content=b'capacity document\n'+b'a'*(64*1024)
        if f['app']=='dolibarr':
            customer=next(c['customer_id'] for c in workflow['cases'] if c['name']=='create, read and edit Unicode customer')
            invoice=next(c['invoice_id'] for c in workflow['cases'] if c['name']=='create, price and validate invoice')
            code,data=send('GET','/api/index.php/invoices/'+str(invoice),headers=key);assert code==200
            ref=json.loads(data)['ref'];filename='capacity-'+tag+'.csv'
            import base64
            upload=json.dumps(dict(filename=filename,modulepart='invoice',ref=ref,filecontent=base64.b64encode(content).decode(),fileencoding='base64',overwriteifexists=1)).encode()
            code,_=send('POST','/api/index.php/documents/upload',upload,key);assert code==200
            download='/api/index.php/documents/download?modulepart=invoice&original_file='+urllib.parse.quote(ref+'/'+filename)
        baseline=status();report['before']=baseline
        def recipe(seq,direct):
            n=seq%20
            if direct and n>=17:n=0
            if f['app']=='dolibarr':
                if n<10:return 'customer-read','GET','/api/index.php/thirdparties/'+str(customer),None,key,200
                if n<12:return 'customer-edit-16k','PUT','/api/index.php/thirdparties/'+str(customer),json.dumps(dict(note_public='Capacity '+tag+' '+str(seq)+' '+('a'*16384))).encode(),key,200
                if n<14:return 'attachment-download-64k','GET',download,None,key,200
                if n<16:return 'attachment-upload-64k','POST','/api/index.php/documents/upload',upload,key,200
                if n==16:return 'customer-list','GET','/api/index.php/thirdparties?limit=5',None,key,200
                if n<19:return 'attack','GET','/api/index.php/thirdparties?sortfield='+urllib.parse.quote('<script>alert(1)</script>' if n==18 else '1 UNION SELECT NULL,NULL-- -'),None,key,403
                return 'body-limit','POST','/api/index.php/thirdparties',b'{"name":"'+b'a'*1048577+b'"}',key,413
            if n<10:label,url='product',f['routes']['product']
            elif n<15:label,url='search',f['routes']['search']
            elif n<17:label,url='cart',f['routes']['cart']
            elif n<19:
                target=urllib.parse.urlsplit(f['routes']['search']);query=urllib.parse.parse_qs(target.query);query['s']=['<script>alert(1)</script>' if n==18 else '1 UNION SELECT NULL,NULL-- -'];url=urllib.parse.urlunsplit(('', '',target.path,urllib.parse.urlencode(query,doseq=True),''));label='attack'
            else:return 'body-limit','POST','/index.php',b'{"name":"'+b'a'*1048577+b'"}',{},413
            parsed=urllib.parse.urlsplit(url);return label,'GET',parsed.path+('?' + parsed.query if parsed.query else ''),None,{},403 if label=='attack' else 200
        def verify(label,expected,code,data):
            if code!=expected:return False
            if code!=200:return True
            if f['app']=='prestashop':return b'OpenWAF Qualification Product' in data if label in ['product','search'] else b'cart' in data.lower()
            value=json.loads(data)
            if label=='customer-read':return int(value['id'])==customer
            if label=='attachment-download-64k':return base64.b64decode(value['content'])==content
            if label=='customer-list':return isinstance(value,list) and bool(value)
            return not isinstance(value,dict) or 'error' not in value
        def phase(name,rate,duration,direct=False):
            before=status();mark=guest('mark');rows=[];limit=threading.BoundedSemaphore(24);start=time.perf_counter();planned=int(rate*duration)
            def task(seq,due):
                begin=time.perf_counter();label,method,path,body,headers,expected=recipe(seq,direct)
                try:
                    code,data=send(method,path,body,headers,f['ports']['app'] if direct else None)
                    ok=verify(label,expected,code,data);error=None
                except Exception as exc:code=0;ok=False;error=type(exc).__name__
                end=time.perf_counter();limit.release()
                return dict(sequence=seq,workload=label,expected=expected,status=code,ok=ok,error=error,scheduled_ms=(end-due)*1000,service_ms=(end-begin)*1000,late_ms=(begin-due)*1000)
            futures=[]
            with ThreadPoolExecutor(max_workers=8) as pool:
                for seq in range(planned):
                    due=start+seq/rate;time.sleep(max(0,due-time.perf_counter()))
                    if limit.acquire(blocking=False):futures.append(pool.submit(task,seq,due))
                for future in futures:rows.append(future.result())
                time.sleep(max(0,start+duration-time.perf_counter()))
            end=guest('mark');after=status()
            raw=run([*ssh,'sudo cat '+f['root']+'/capacity-'+tag+'/resources.jsonl']).stdout
            resources=resource_summary([json.loads(line) for line in raw.splitlines()],mark['monotonic'],end['monotonic'])
            value=dict(name=name,rate=rate,duration_seconds=duration,planned=planned,completed=len(rows),functional_passed=len(rows)==planned and all(r['ok'] for r in rows),p95_scheduled_ms=percentile([r['scheduled_ms'] for r in rows],.95),p99_scheduled_ms=percentile([r['scheduled_ms'] for r in rows],.99),late_over_100ms=sum(r['late_ms']>100 for r in rows),resources=resources,guest_begin=mark,guest_end=end,before=before,after=after)
            value['accepted_operating_profile']=accepted(value)
            (out/(name+'.requests.json')).write_text(json.dumps(rows));report['phases'].append(value);(out/'result.json').write_text(json.dumps(report,indent=2))
            print(name+': functional='+str(value['functional_passed'])+', accepted='+str(value['accepted_operating_profile'])+', p95='+str(value['p95_scheduled_ms'])+'ms, hostCPU='+str(round(resources['host_busy_percent'],1))+'%',flush=True)
            return value
        phase('direct-business',1,60,True)
        best=None
        for rate in [1,2,5]:
            value=phase('mixed-'+str(rate)+'rps',rate,60)
            if value['accepted_operating_profile']:best=rate
            else:break
        assert best is not None,'no supported business profile met declared budgets'
        endurance=phase('business-endurance',best,args.endurance_seconds);assert endurance['accepted_operating_profile']
        deadline=time.monotonic()+30
        while True:
            final=status();storage=final['storage']
            if storage['pending_writes']==0 and storage['export']['pending_records']==0:break
            assert time.monotonic()<deadline;time.sleep(.5)
        assert storage['healthy'] and final['summary']['event_persistence_errors']==0
        assert all(storage[k]==0 for k in ['queue_dropped','write_failed','ingest_timeouts'])
        report.update(final=final,accepted_rate=best,capture=guest('capture'))
        base=f['root']+'/capacity-'+tag+'/'
        for name in ['resources.jsonl','databases.tar']:run([*scp,'qualifier@127.0.0.1:'+base+name,out/name])
        assert sha(out/'databases.tar')==report['capture']['sha256'] and sha(out/'resources.jsonl')==report['capture']['resource_sha256']
        for name,digest in hashes.items():assert sha(repo/'scripts'/name)==digest
        report['passed']=True
    finally:
        if started:
            try:report['cleanup']=guest('stop')
            except Exception:report['cleanup']=dict(stopped=False)
        if tunnel:tunnel.terminate();tunnel.wait(timeout=20)
        if 'VMState="running"' in info():
            run([*ssh,'sudo poweroff'],check=False)
            for _ in range(60):
                if 'VMState="poweroff"' in info():break
                time.sleep(1)
        report['vm_powered_off']='VMState="poweroff"' in info()
        (out/'result.json').write_text(json.dumps(report,indent=2)+'\n');print(out/'result.json',flush=True)


if __name__=='__main__':main()
