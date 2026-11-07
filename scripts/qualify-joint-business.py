"""Higher concurrency, exact upload boundaries and real two-application load."""
import argparse
import base64
from collections import Counter
from concurrent.futures import ThreadPoolExecutor
import hashlib
from html.parser import HTMLParser
import http.client
from http.cookies import SimpleCookie
import importlib.util
import json
from pathlib import Path
import re
import shlex
import socket
import subprocess
import tarfile
import threading
import time
import urllib.parse
import uuid


def sha(data):return hashlib.sha256(data).hexdigest()


class Forms(HTMLParser):
    def __init__(self):super().__init__();self.forms=[];self.current=None
    def handle_starttag(self,tag,attrs):
        a=dict(attrs)
        if tag=='form':self.current=dict(action=a.get('action',''),fields={},files=[]);self.forms.append(self.current)
        if tag=='input' and self.current and a.get('name'):
            if a.get('type')=='file':self.current['files'].append(a['name'])
            elif a.get('type') not in ['checkbox','radio'] or 'checked' in a:self.current['fields'][a['name']]=a.get('value','')
    def handle_endtag(self,tag):
        if tag=='form':self.current=None


def multipart(fields,field,name,content):
    boundary='OpenWAFJointBoundary';parts=[]
    for key,value in fields.items():parts.append((f'--{boundary}\r\nContent-Disposition: form-data; name="{key}"\r\n\r\n{value}\r\n').encode())
    parts.extend([(f'--{boundary}\r\nContent-Disposition: form-data; name="{field}"; filename="{name}"\r\nContent-Type: text/csv\r\n\r\n').encode(),content,f'\r\n--{boundary}--\r\n'.encode()])
    return b''.join(parts),'multipart/form-data; boundary='+boundary


def percentile(rows,field,p):
    values=sorted(row[field] for row in rows);return round(values[int((len(values)-1)*p)],3) if values else None


def main():
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--package',type=Path,required=True);parser.add_argument('--disposable-vm',required=True,action='store_true');parser.add_argument('--endurance-seconds',type=int,default=300)
    args=parser.parse_args();assert 120<=args.endurance_seconds<=1800
    repo=Path(__file__).resolve().parents[1];package=args.package.resolve(strict=True);package_sha=sha(package.read_bytes());assert package_sha==Path(str(package)+'.sha256').read_text().split()[0]
    tag=uuid.uuid4().hex[:8];out=repo/'artifacts'/('m4-business-joint-'+tag);out.mkdir()
    spec=importlib.util.spec_from_file_location('permissions',repo/'scripts/qualify-applications.py');h=importlib.util.module_from_spec(spec);spec.loader.exec_module(h);h.restrict_artifacts(out)
    sources=out/'source';sources.mkdir();hashes={}
    for name in ['qualify-joint-business.py','m4_joint_business_guest.py','m4_joint_domains.php','m4_joint_files.php','m4_business_guest.py']:
        data=(repo/'scripts'/name).read_bytes();(sources/name).write_bytes(data);hashes[name]=sha(data)
    dol=json.loads((repo/'artifacts/m4-business-2be162b6/fixture.private.json').read_text());ps=json.loads((repo/'artifacts/m4-business-77aadf7d/fixture.private.json').read_text())
    workflow=json.loads((repo/'artifacts/m4-business-2be162b6/results-19.json').read_text());assert workflow['passed']
    assert dol['vm_dir']==ps['vm_dir'] and dol['package_sha256']==ps['package_sha256']
    with tarfile.open(package) as archive:server_sha=sha(archive.extractfile('usr/lib/openwaf/waf-server').read())
    listeners=[socket.socket() for _ in range(3)]
    for listener in listeners:listener.bind(('127.0.0.1',0))
    ports=dict(zip(['admin','proxy','collector'],[s.getsockname()[1] for s in listeners]))
    for listener in listeners:listener.close()
    root='/var/lib/owaf-joint-'+tag;remote='/tmp/owaf-joint-'+tag
    f=dict(dolibarr=dol,prestashop=ps,ports=ports,package=remote+'/candidate.tar.gz',package_sha256=package_sha,server_sha256=server_sha)
    private=out/'fixture.private.json';private.write_text(json.dumps(f))
    report=dict(passed=False,server_sha256=server_sha,package_sha256=package_sha,sources=hashes,cases=[],phases=[],scope='one Linux amd64 gateway and both pinned business cohorts',business_pilot_started=False)
    vm=Path(dol['vm_dir']);assert vm.parent.resolve()==(repo/'artifacts/m2-vms').resolve() and re.fullmatch(r'openwaf-m2-24\.04-[a-f0-9]{8}',vm.name)
    vbox=r'C:\Program Files\Oracle\VirtualBox\VBoxManage.exe';tunnel=None;attempted=False;records=[];files=[];lock=threading.Lock();timing=threading.local()
    def run(argv,data=None,timeout=180,check=True):
        p=subprocess.run([str(x) for x in argv],input=data,capture_output=True,text=True,timeout=timeout)
        if check and p.returncode:
            (out/'failure.private.txt').write_text(p.stdout+p.stderr);raise RuntimeError('joint qualification command failed; private evidence: '+str(out))
        return p
    def info():
        for _ in range(60):
            p=run([vbox,'showvminfo',vm.name,'--machinereadable'],check=False)
            if p.returncode==0:return p.stdout
            time.sleep(1)
        raise RuntimeError('VM metadata unavailable')
    metadata=info();assert 'cpus=1\n' in metadata and 'memory=4096\n' in metadata
    sshport=re.search(r'Forwarding\(0\)="ssh,tcp,127\.0\.0\.1,(\d+),,22"',metadata)[1]
    opts=['-i',vm/'identity','-o','BatchMode=yes','-o','ConnectTimeout=5','-o','ServerAliveInterval=5','-o','ServerAliveCountMax=3','-o','StrictHostKeyChecking=yes','-o','UserKnownHostsFile='+str(vm/'known_hosts')]
    ssh=['ssh',*opts,'-p',sshport,'qualifier@127.0.0.1'];scp=['scp',*opts,'-P',sshport]
    def guest(op,data=None):return json.loads(run([*ssh,shlex.join(['sudo','python3',remote+'/m4_joint_business_guest.py',op,'--root',root,'--sources',remote])],None if data is None else json.dumps(data)).stdout)
    def save():
        (out/'result.json').write_text(json.dumps(report,indent=2));(out/'requests.json').write_text(json.dumps(records));(out/'files.json').write_text(json.dumps(files))
    def admin(path,data=None):
        c=http.client.HTTPConnection('127.0.0.1',ports['admin'],timeout=20)
        try:
            c.request('POST' if data is not None else 'GET','/api/v1/'+path,body=None if data is None else json.dumps(data),headers={'Authorization':'Bearer '+f['token'],'Content-Type':'application/json'})
            r=c.getresponse();body=r.read();assert r.status==200;return json.loads(body)
        finally:c.close()
    def record(app,label,code,begin,body=None,extra=None):
        end=time.perf_counter();due=getattr(timing,'due',begin)
        with lock:records.append(dict(app=app,label=label,status=code,latency_ms=(end-begin)*1000,scheduled_latency_ms=(end-due)*1000,start_delay_ms=(begin-due)*1000,sequence=getattr(timing,'sequence',None),response_bytes=len(body or b''),**(extra or {})))
    def send(app,label,method,path,body=None,headers=None):
        c=http.client.HTTPConnection('127.0.0.1',ports['proxy'],timeout=40);begin=time.perf_counter()
        try:
            c.request(method,path,body=body,headers={'Host':('erp' if app=='dolibarr' else 'shop')+'.joint.test:'+str(ports['proxy']),'Content-Type':'application/json','User-Agent':'OpenWAF joint qualification',**(headers or {})})
            r=c.getresponse();data=r.read((2<<20)+1);assert len(data)<=2<<20
            response_headers=r.getheaders();details=dict(response_headers);details['set_cookies']=[v for k,v in response_headers if k.lower()=='set-cookie'];record(app,label,r.status,begin,data)
            return r.status,data,details
        except Exception as e:record(app,label,0,begin,extra=dict(error=type(e).__name__));raise
        finally:c.close()
    def check(name,operation):
        try:
            value=operation();assert value.pop('passed',True)
            report['cases'].append(dict(name=name,passed=True,**value));print(name+': passed',flush=True)
        except Exception as e:report['cases'].append(dict(name=name,passed=False,error=type(e).__name__+': '+str(e)));raise
        finally:save()
    customer=next(c['customer_id'] for c in workflow['cases'] if c['name']=='create, read and edit Unicode customer');invoice=next(c['invoice_id'] for c in workflow['cases'] if c['name']=='create, price and validate invoice')
    key={'DOLAPIKEY':dol['api_key']};ref=None
    def upload_body(name,size,pad=None):
        content=b'joint qualification\n'+b'a'*(size-len(b'joint qualification\n'))
        value=json.dumps(dict(filename=name,modulepart='invoice',ref=ref,filecontent=base64.b64encode(content).decode(),fileencoding='base64',overwriteifexists=0),separators=(',',':')).encode()
        if pad is not None:assert len(value)<=pad;value+=b' '*(pad-len(value))
        return value,content
    def note_file(name,content,committed,kind='api'):
        with lock:files.append(dict(name=name,ref=str(customer) if kind=='native' else ref,kind=kind,bytes=len(content),sha256=sha(content),committed=committed))
    def upload(label,size,index,pad=None,allow_reject=False):
        name='joint-'+tag+'-'+str(index)+'.csv';body,content=upload_body(name,size,pad)
        code,data,_=send('dolibarr',label,'POST','/api/index.php/documents/upload',body,key)
        assert code in ([200,503] if allow_reject else [413] if pad and pad>1048576 else [200]),'unexpected ERP upload verdict '+str(code)
        if code==503:assert b'Application admission share exhausted' in data
        note_file(name,content,code==200)
        return code
    product=urllib.parse.urlsplit(ps['routes']['product']);product_path=product.path+('?' + product.query if product.query else '')
    def read_shop(label,allow_reject=False):
        code,data,_=send('prestashop',label,'GET',product_path)
        assert code in ([200,503] if allow_reject else [200])
        if code==200:assert b'OpenWAF Qualification Product' in data
        else:assert b'Application admission share exhausted' in data
        return code
    try:
        if 'VMState="poweroff"' in metadata:run([vbox,'startvm',vm.name,'--type','headless'])
        for _ in range(90):
            if run([*ssh,'true'],check=False).returncode==0:break
            time.sleep(2)
        else:raise RuntimeError('SSH unavailable')
        run([*ssh,'mkdir -m 700 '+remote]);run([*scp,*sources.iterdir(),'qualifier@127.0.0.1:'+remote+'/']);run([*scp,package,'qualifier@127.0.0.1:'+f['package']])
        attempted=True;f=guest('setup',f);private.write_text(json.dumps(f))
        forwards=[]
        for port in ports.values():forwards+=['-L',f'127.0.0.1:{port}:127.0.0.1:{port}']
        tunnel=subprocess.Popen([str(x) for x in [*ssh[:-1],'-N','-o','ExitOnForwardFailure=yes',*forwards,ssh[-1]]],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL);time.sleep(1);assert tunnel.poll() is None
        for _ in range(120):
            try:
                if admin('health')['healthy']:break
            except (OSError,ValueError):pass
            time.sleep(.25)
        else:raise RuntimeError('joint gateway not healthy')
        report['spool_before']=guest('spool');assert report['spool_before']['files']==0
        code,data,_=send('dolibarr','invoice-read','GET','/api/index.php/invoices/'+str(invoice),headers=key);assert code==200;ref=json.loads(data)['ref']
        def routing():
            code,data,_=send('dolibarr','routing-erp','GET','/api/index.php/thirdparties/'+str(customer),headers=key);assert code==200 and int(json.loads(data)['id'])==customer
            read_shop('routing-shop');return dict(real_apps=True,one_gateway=True,policy=admin('config'))
        check('joint host routing and canonical storefront',routing)
        def sizes():
            facts=[]
            for i,size in enumerate([64<<10,256<<10,700<<10]):
                name='joint-'+tag+'-size'+str(i)+'.csv';body,content=upload_body(name,size)
                code,_,_=send('dolibarr','large-upload','POST','/api/index.php/documents/upload',body,key);assert code==200;note_file(name,content,True)
                path='/api/index.php/documents/download?modulepart=invoice&original_file='+urllib.parse.quote(ref+'/'+name)
                code,data,_=send('dolibarr','large-download','GET',path,headers=key);assert code==200 and base64.b64decode(json.loads(data)['content'])==content
                facts.append(dict(file_bytes=size,request_bytes=len(body),exact_download=True))
            upload('json-exact-limit',700<<10,'exact',1048576)
            upload('json-over-limit',700<<10,'over',1048577)
            return dict(sizes=facts,exact_limit=1048576,over_limit=1048577)
        check('larger API uploads and exact JSON body boundary',sizes)
        # Native login and document form: parse server fields, no hidden UI clicks.
        cookies={}
        def native(label,method,path,body=None,content_type=None):
            headers={}
            if cookies:headers['Cookie']='; '.join(k+'='+v for k,v in cookies.items())
            if content_type:headers['Content-Type']=content_type
            code,data,meta=send('dolibarr',label,method,path,body,headers)
            for value in meta['set_cookies']:
                jar=SimpleCookie();jar.load(value);cookies.update({k:v.value for k,v in jar.items()})
            return code,data,meta
        def native_large():
            code,data,_=native('native-login-form','GET','/index.php');assert code==200
            forms=Forms();forms.feed(data.decode());form=next(x for x in forms.forms if 'username' in x['fields']);fields=form['fields'];fields.update(username='lab-admin',password=dol['password'])
            code,_,_=native('native-login','POST','/index.php',urllib.parse.urlencode(fields).encode(),'application/x-www-form-urlencoded');assert code in [200,302,303]
            code,data,_=native('native-document-form','GET','/societe/document.php?socid='+str(customer));assert code==200
            parser=Forms();parser.feed(data.decode());form=next(x for x in parser.forms if x['files']);fields=form['fields'];fields['sendit']='Upload';field=form['files'][0]
            target=urllib.parse.urlsplit(urllib.parse.urljoin('http://erp.joint.test:'+str(ports['proxy'])+'/societe/document.php?socid='+str(customer),form['action']));assert target.hostname=='erp.joint.test'
            path=target.path+('?' + target.query if target.query else '')
            for suffix,size in [('900k',900<<10),('exact',None),('over',None)]:
                name='joint-native-'+tag+'-'+suffix+'.csv';overhead=len(multipart(fields,field,name,b'')[0]);size=size or (1048576+(suffix=='over')-overhead);content=b'a'*size;body,ctype=multipart(fields,field,name,content)
                code,_,_=native('native-'+suffix,'POST',path,body,ctype);assert code==([413] if suffix=='over' else [200,302,303])[0] or (suffix!='over' and code in [302,303])
                note_file(name,content,suffix!='over','native')
                if suffix!='over':
                    code,download,_=native('native-download','GET','/document.php?modulepart=societe&file='+urllib.parse.quote(str(customer)+'/'+name));assert code==200 and download==content
            return dict(native_900k=True,exact_multipart_limit=True,over_limit_refused=True)
        check('native multipart near-limit uploads',native_large)
        def bursts():
            result=[]
            for width in [4,8,16,32]:
                barrier=threading.Barrier(width)
                def task(i):
                    barrier.wait();return upload('burst-'+str(width),700<<10,'burst-'+str(width)+'-'+str(i),allow_reject=True) if i%2==0 else read_shop('burst-'+str(width),True)
                with ThreadPoolExecutor(max_workers=width) as pool:codes=list(pool.map(task,range(width)))
                result.append(dict(width=width,statuses=dict(Counter(codes))))
            assert any(row['statuses'].get(503,0)>0 for row in result)
            deadline=time.monotonic()+10
            while admin('status')['resources']['active'] and time.monotonic()<deadline:time.sleep(.1)
            resources=admin('status')['resources'];assert resources['active']==resources['reserved_buffer_bytes']==0
            return dict(bursts=result,slots_reclaimed=True)
        check('simultaneous business bursts and bounded refusals',bursts)
        def fairness():
            held=[]
            try:
                for i in range(8):
                    name='joint-'+tag+'-held-'+str(i)+'.csv';body,content=upload_body(name,700<<10);c=http.client.HTTPConnection('127.0.0.1',ports['proxy'],timeout=40)
                    c.putrequest('POST','/api/index.php/documents/upload',skip_host=True);c.putheader('Host','erp.joint.test:'+str(ports['proxy']));c.putheader('Content-Type','application/json');c.putheader('Content-Length',str(len(body)));c.putheader('DOLAPIKEY',dol['api_key']);c.endheaders();c.send(body[:1024]);held.append((c,body,content,name,time.perf_counter()))
                deadline=time.monotonic()+5
                while admin('status')['resources']['active']<8 and time.monotonic()<deadline:time.sleep(.05)
                assert admin('status')['resources']['active']==8
                with ThreadPoolExecutor(max_workers=8) as pool:shop=list(pool.map(lambda _:read_shop('fairness-shop'),range(8)))
                code,data,_=send('dolibarr','fairness-rejection','GET','/api/index.php/thirdparties/'+str(customer),headers=key);assert code==503 and b'Application admission share exhausted' in data
                def finish(item):
                    c,body,content,name,begin=item;c.send(body[1024:]);r=c.getresponse();data=r.read();record('dolibarr','held-upload',r.status,begin,data);assert r.status==200;note_file(name,content,True);c.close()
                with ThreadPoolExecutor(max_workers=8) as pool:list(pool.map(finish,held))
            finally:
                for item in held:item[0].close()
            resources=admin('status')['resources'];assert resources['active']==resources['reserved_buffer_bytes']==0
            return dict(erp_admissions_held=8,shop_successes=len(shop),extra_erp_status=503,slots_reclaimed=True,scope='admission fairness while bodies are incomplete; not CPU-time isolation')
        check('held ERP admissions preserve storefront access',fairness)
        def phase(name,duration,erp_rate,shop_rate,large=False,operating=True):
            start_mark=guest('mark');before=len(records);start=time.perf_counter();jobs=[]
            schedule=sorted([(i/erp_rate,'dolibarr',i) for i in range(int(duration*erp_rate))]+[(i/shop_rate,'prestashop',i) for i in range(int(duration*shop_rate))]);late=[]
            def job(app,i,due):
                timing.due=due;timing.sequence=app+'-'+str(i)
                late.append((time.perf_counter()-due)*1000)
                if app=='prestashop':read_shop(name,allow_reject=not operating)
                elif large:upload(name,700<<10,name+'-'+str(i),allow_reject=not operating)
                else:
                    code,data,_=send('dolibarr',name,'GET','/api/index.php/thirdparties/'+str(customer),headers=key);assert code==200 and int(json.loads(data)['id'])==customer
            with ThreadPoolExecutor(max_workers=16) as pool:
                for offset,app,i in schedule:
                    due=start+offset;time.sleep(max(0,due-time.perf_counter()));jobs.append(pool.submit(job,app,i,due))
                errors=[]
                for future in jobs:
                    try:future.result()
                    except Exception as e:errors.append(type(e).__name__+': '+str(e))
                time.sleep(max(0,start+duration-time.perf_counter()))
            end_mark=guest('mark');rows=records[before:];assert len(rows)==len(schedule)
            raw=run([*ssh,'sudo cat '+root+'/resources.jsonl']).stdout
            native_rows=[json.loads(x) for x in raw.splitlines()];native_rows=[r for r in native_rows if start_mark['monotonic']<=r['monotonic']<=end_mark['monotonic']]
            assert len(native_rows)>30 and native_rows[0]['monotonic']-start_mark['monotonic']<4 and end_mark['monotonic']-native_rows[-1]['monotonic']<4
            assert all(b['monotonic']-a['monotonic']<4 for a,b in zip(native_rows,native_rows[1:]))
            span=native_rows[-1]['monotonic']-native_rows[0]['monotonic'];cpu=0;rss=0
            for kind in ['processes','containers']:
                for component in native_rows[0][kind]:
                    values=[r[kind][component] for r in native_rows];assert all(not v.get('unavailable') for v in values);assert all(b['cpu_seconds']>=a['cpu_seconds'] for a,b in zip(values,values[1:]))
                    if kind=='processes':assert len({v['pid'] for v in values})==1
                    else:assert all(v['oom_kill']==0 for v in values)
                    cpu+=100*(values[-1]['cpu_seconds']-values[0]['cpu_seconds'])/span
                    if component=='gateway':rss=max(v['rss_kib'] for v in values)
            first,last=native_rows[0]['host_cpu_ticks'],native_rows[-1]['host_cpu_ticks'];busy=100*(1-((last[3]+last[4])-(first[3]+first[4]))/(sum(last[:8])-sum(first[:8])));available=min(r['host_available_kib'] for r in native_rows)
            erp=[r for r in rows if r['app']=='dolibarr'];shop=[r for r in rows if r['app']=='prestashop']
            facts=dict(name=name,duration=duration,erp_rate=erp_rate,shop_rate=shop_rate,large=large,requests=len(rows),p95_erp_ms=percentile(erp,'scheduled_latency_ms',.95),p95_shop_ms=percentile(shop,'scheduled_latency_ms',.95),statuses=dict(Counter(str(r['status']) for r in rows)),errors=errors,late_over_100ms=sum(x>100 for x in late),observed_cpu_percent=max(cpu,busy),cpu_components=cpu,cpu_guest_busy=busy,gateway_peak_rss_kib=rss,min_host_available_kib=available,guest_begin=start_mark,guest_end=end_mark)
            facts['operating_budget_passed']=not errors and all(r['status']==200 for r in rows) and facts['p95_shop_ms']<=2000 and facts['p95_erp_ms']<=(10000 if large else 2000) and max(cpu,busy)<=85 and available>=512*1024 and facts['late_over_100ms']<=len(rows)*.01
            report['phases'].append(facts);save();print(name+': '+str(facts['operating_budget_passed'])+', shop p95 '+str(facts['p95_shop_ms'])+'ms',flush=True)
            assert not errors,'unexpected request failure in '+name
            if operating:assert facts['operating_budget_passed'],'combined operating budget failed'
        phase('joint-steady',120,1,2)
        phase('large-cpu-screen',60,1,2,True,False)
        phase('large-joint-endurance',args.endurance_seconds,.25,1,True)
        check('committed files and refused-file absence',lambda:guest('files',dict(files=files)))
        # Explicit malformed payload pairs remain inspected on both hosts.
        for app,path in [('dolibarr','/api/index.php/thirdparties?sortfield=%3Cscript%3Ealert(1)%3C/script%3E'),('prestashop','/index.php?controller=search&s=%3Cscript%3Ealert(1)%3C/script%3E')]:
            code,_,_=send(app,'paired-xss','GET',path,headers=key if app=='dolibarr' else {});assert code==403
        deadline=time.monotonic()+30
        while True:
            status=admin('status');s=status['storage']
            if not s['pending_writes'] and not s['export']['pending_records'] and not status['resources']['active']:break
            assert time.monotonic()<deadline;time.sleep(.25)
        assert status['summary']['event_persistence_errors']==0 and s['healthy'] and s['export']['healthy']
        assert all(s[k]==0 for k in ['queue_dropped','write_failed','ingest_timeouts'])
        assert status['summary']['requests']==len(records)
        report['spool_after']=guest('spool');assert report['spool_after']['files']==report['spool_after']['bytes']==0
        report['final_status']=status;report['capture']=guest('capture')
        for name in ['databases.tar','resources.jsonl']:run([*scp,'qualifier@127.0.0.1:'+root+'/'+name,out/name])
        assert sha((out/'databases.tar').read_bytes())==report['capture']['sha256'] and sha((out/'resources.jsonl').read_bytes())==report['capture']['resources_sha256']
        for name,value in hashes.items():assert sha((repo/'scripts'/name).read_bytes())==value
        report['passed']=True
    finally:
        if attempted:
            if 'capture' not in report:
                try:
                    report['failure_status']=admin('status');report['failure_spool']=guest('spool');report['capture']=guest('capture')
                    for name in ['databases.tar','resources.jsonl']:run([*scp,'qualifier@127.0.0.1:'+root+'/'+name,out/name])
                except Exception as e:report['failure_capture_error']=type(e).__name__
            try:report['cleanup']=guest('cleanup')
            except Exception as e:report['cleanup']=dict(restored=False,error=type(e).__name__);report['passed']=False
        if tunnel:tunnel.terminate();tunnel.wait(timeout=20)
        if 'VMState="running"' in info():
            run([*ssh,'sudo poweroff'],check=False)
            for _ in range(60):
                if 'VMState="poweroff"' in info():break
                time.sleep(1)
        report['vm_powered_off']='VMState="poweroff"' in info();save();print(out/'result.json',flush=True)


if __name__=='__main__':main()
