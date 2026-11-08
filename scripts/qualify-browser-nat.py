"""Full browser assets, authenticated sessions and shared-IP uploads in the owned M4 VM."""
import argparse
from collections import Counter
import importlib.util
import json
from pathlib import Path
import re
import shlex
import subprocess
import threading
import time
from urllib.parse import urlsplit

from browser_proxy import BrowserProxy
from joint_fair_lab import FairLab
from joint_business_lab import resources, sha
from joint_upload_data import upload_content


spec = importlib.util.spec_from_file_location('fair', Path(__file__).with_name('qualify-joint-fairness.py'))
fair = importlib.util.module_from_spec(spec)
spec.loader.exec_module(fair)


def application_seed(lab, app, payload):
    container = lab.fixture[app]['containers']['app']
    target = '/tmp/openwaf-browser-seed.php'
    lab.run([*lab.ssh, shlex.join(['sudo','docker','cp',lab.remote+'/m4_browser_seed.php',container+':'+target])])
    output = lab.run([*lab.ssh, shlex.join(['sudo','docker','exec','-i','-u','www-data',container,'php',target])],
                     json.dumps(dict(payload,app=app))).stdout
    return json.loads(output.split('OPENWAF_BROWSER_SEED:')[1])


def phase(lab, proxies, name, controls, shared, waves, sequential=False,
          targets=(), seconds=0, attack_lane='attacker'):
    config = lab.admin('config')
    for app in config['applications']:
        app['traffic_controls'] = controls
    lab.admin('config/apply', dict(config=config,reason='Owned M4 browser and shared-NAT qualification'))
    applied = lab.admin('config')
    for proxy in proxies:
        proxy.profile = name
    before = lab.drain()
    begin = lab.guest('mark')
    first = len(lab.records)
    lab.report['active_phase'] = dict(name=name,policy=applied,guest_begin=begin,
                                     targets=list(targets),seconds=seconds,attack_lane=attack_lane)
    lab.save()
    private = dict(lab.browser_fixture, profile=name, sharedNat=shared, waves=waves,
                   sequential=sequential, uploads=True, intervalMs=15000)
    private_path = lab.out/(name+'.private.json')
    result_path = lab.out/(name+'-browser.json')
    private_path.write_text(json.dumps(private))
    source = lab.repo/'tools/application-check/browser-nat.cjs'
    assert sha(source.read_bytes()) == lab.report['browser_source_sha256']
    started = time.monotonic()
    stop = threading.Event()
    errors = []
    heavy = fair.abuse.body_bytes(900 << 10,'unicode')
    product = urlsplit(lab.fixture['prestashop']['routes']['product']).path

    def burner(app, worker):
        lab.timing.lane = attack_lane
        lab.timing.role = 'abuse'
        stop.wait(worker/4)
        index = 0
        while not stop.is_set() and time.monotonic() < started+seconds:
            due = time.monotonic()
            lab.timing.due = time.perf_counter()
            lab.timing.sequence = app+'-burn-'+str(worker)+'-'+str(index)
            headers = {'X-Forwarded-For':'198.51.100.'+str(1+(index+worker)%250)}
            if app == 'dolibarr':
                headers['DOLAPIKEY'] = lab.fixture[app]['api_key']
            def valid(code, body):
                return fair.refused(code,body) or (fair.abuse.missing_name(code,body) if app == 'dolibarr'
                    else code == 200 and b'OpenWAF Qualification Product' in body)
            try:
                lab.send(app,name,'POST','/api/index.php/thirdparties' if app == 'dolibarr' else product,
                         heavy,headers,valid)
            except Exception as error:
                errors.append(type(error).__name__)
            index += 1
            stop.wait(max(0,1-(time.monotonic()-due)))

    threads = [threading.Thread(target=burner,args=(app,worker),daemon=True)
               for app in targets for worker in range(4)]
    for thread in threads:
        thread.start()
    try:
        process = subprocess.run(['node',str(source),str(private_path),str(result_path)],
                                 capture_output=True,text=True,timeout=900)
        browser_seconds = time.monotonic()-started
        time.sleep(max(0,seconds-browser_seconds))
    finally:
        stop.set()
        for thread in threads:
            thread.join(timeout=90)
            assert not thread.is_alive(), 'abuse request did not finish'
    (lab.out/(name+'-runner.log')).write_text(process.stdout+process.stderr)
    assert process.returncode == 0, 'browser harness failed, inspect retained private evidence'
    assert sha(source.read_bytes()) == lab.report['browser_source_sha256']
    for proxy in proxies:
        proxy.wait_idle()
        assert proxy.saturated == 0, 'measurement proxy exhausted its own capacity'
    active_seconds = time.monotonic()-started
    observation_seconds = max(30,seconds)
    time.sleep(max(0,observation_seconds-active_seconds))
    browser = json.loads(result_path.read_text())
    flows = browser['initial_uploads'] + [upload for wave in browser['waves']
              for session in wave['sessions'] for upload in session['uploads']]
    lab.files.extend(flows)
    (lab.out/'files.json').write_text(json.dumps(lab.files))
    after = lab.drain()
    end = lab.guest('mark')
    rows = lab.records[first:]
    raw = lab.run([*lab.ssh,'sudo cat '+lab.root+'/resources.jsonl']).stdout
    measured = None
    try:
        measured = resources(raw,begin,end,lab.vcpus)
    except AssertionError:
        if not seconds:
            raise
    facts = dict(name=name,shared_nat=shared,waves=waves,sequential=sequential,
                 policy=applied,before=before,after=after,guest_begin=begin,guest_end=end,
                 requests=len(rows),statuses=dict(Counter(str(row['status']) for row in rows)),
                 browser_passed=browser['passed'],browser_result=result_path.name,
                 browser_result_sha256=sha(result_path.read_bytes()),resources=measured,
                 active_work_seconds=active_seconds,minimum_observation_seconds=30,
                 elapsed_seconds=time.monotonic()-started,
                 proxy_errors=sum('error' in row for row in rows),
                 blocked_external=[row for proxy in proxies for row in proxy.blocked if row['profile']==name])
    if seconds:
        abuse_rows = [row for row in rows if row['role'] == 'abuse']
        browser_rows = [row for row in rows if row['role'] == 'browser']
        navigations = [n['elapsed_ms'] for w in browser['waves'] for s in w['sessions'] for n in s['navigations']]
        latency = dict(navigation_p95_ms=fair.p95(navigations),
                       wave_p95_ms=fair.p95([w['elapsed_ms'] for w in browser['waves']]),
                       file_p95_ms=fair.p95([f['elapsed_ms'] for f in flows]))
        windows = []
        for offset in range(0,seconds,60):
            window_begin = dict(monotonic=begin['monotonic']+offset)
            window_end = dict(monotonic=begin['monotonic']+min(seconds,offset+60))
            sample = None
            try:
                sample = resources(raw,window_begin,window_end,lab.vcpus)
            except AssertionError:
                pass
            windows.append(dict(offset_seconds=offset,seconds=min(60,seconds-offset),resources=sample))
        responsive = (browser['passed'] and latency['navigation_p95_ms'] <= 5000 and
                      latency['wave_p95_ms'] <= 20000 and latency['file_p95_ms'] <= 10000 and
                      all(w['elapsed_ms'] <= 20000 for w in browser['waves']) and
                      all(f['elapsed_ms'] <= 10000 for f in flows))
        resource_valid = measured is not None and all(w['resources'] is not None for w in windows)
        facts.update(targets=list(targets),seconds=seconds,attack_lane=attack_lane,workers_per_target=4,
                     abuse_requests=len(abuse_rows),abuse_body_sha256=sha(heavy),abuse_body_bytes=len(heavy),
                     abuse_statuses=dict(Counter(str(row['status']) for row in abuse_rows)),
                     browser_requests=len(browser_rows),browser_active_seconds=browser_seconds,
                     minimum_observation_seconds=observation_seconds,errors=errors,latency=latency,
                     integrity_passed=not errors and all(row['valid'] for row in abuse_rows),
                     responsiveness_passed=responsive,
                     coverage_passed=browser_seconds <= seconds+5,
                     resource_evidence_passed=resource_valid,resource_windows=windows,
                     resource_budget_passed=resource_valid and measured['observed_cpu_percent'] <= 80 and
                         all(w['resources']['observed_cpu_percent'] <= 80 for w in windows))
    assert after['summary']['requests']-before['summary']['requests'] == len(rows)
    lab.report['phases'].append(facts)
    lab.report.pop('active_phase',None)
    lab.save()
    print(name+': browser='+str(browser['passed'])+' statuses='+str(facts['statuses']),flush=True)
    return browser['passed']


def main():
    if not __debug__:
        raise RuntimeError('qualification requires assertions')
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--package',type=Path,required=True)
    parser.add_argument('--disposable-vm',action='store_true',required=True)
    parser.add_argument('--waves',type=int,default=4)
    parser.add_argument('--prior-files',type=Path,action='append',default=[])
    parser.add_argument('--linux-qualification',type=Path)
    parser.add_argument('--abuse-seconds',type=int,default=0)
    parser.add_argument('--gateway-cpu-quota',type=int,choices=[0,200],default=0)
    parser.add_argument('--nat-client-buffer-mib',type=int,choices=[12,24],default=12)
    parser.add_argument('--nat-body-rate-kib',type=int,choices=[0,160],default=0)
    parser.add_argument('--nat-body-burst-kib',type=int,choices=[0,2048,3072,4096],default=0)
    parser.add_argument('--shared-abuse-seconds',type=int,default=0)
    args = parser.parse_args()
    assert 1 <= args.waves <= 20
    assert args.abuse_seconds == 0 or (60 <= args.abuse_seconds <= 300 and args.abuse_seconds%60 == 0)
    assert args.abuse_seconds or (args.gateway_cpu_quota == 0 and args.nat_client_buffer_mib == 12)
    assert (args.nat_body_rate_kib == 0) == (args.nat_body_burst_kib == 0)
    assert args.abuse_seconds or args.nat_body_rate_kib == 0
    assert args.shared_abuse_seconds == 0 or (args.abuse_seconds and 60 <= args.shared_abuse_seconds <= 300 and args.shared_abuse_seconds%60 == 0)
    sources = ['qualify-browser-nat.py','browser_proxy.py','joint_fair_lab.py','joint_business_lab.py',
               'm4_joint_business_guest.py','m4_joint_fair_guest.py','m4_joint_domains.php','m4_joint_files.php',
               'm4_business_guest.py','m4_browser_seed.php','joint_upload_data.py','qualify-joint-fairness.py',
               'qualify-joint-abuse.py','m4_joint_abuse_state.php','m4_joint_store_state.php']
    lab = FairLab(args.package,sources,vcpus=4,lane_connections=64)
    lab.fixture['qualification_resources'] = dict(max_concurrent=64,max_connections=128)
    lab.fixture['gateway_cpu_quota_percent'] = args.gateway_cpu_quota
    lab.report.update(experiment='Chromium authenticated asset bursts and real shared TCP source',
                      qualification_resources=lab.fixture['qualification_resources'],files=[],screen_only=True)
    lab.files = []
    source = lab.repo/'tools/application-check/browser-nat.cjs'
    lab.report['browser_source_sha256'] = sha(source.read_bytes())
    (lab.out/'source/browser-nat.cjs').write_bytes(source.read_bytes())
    content = lab.out/'upload-content.bin'
    content.write_bytes(upload_content('mixed-csv'))
    proxies = []
    original = None
    cpu_changed = False
    try:
        info = lab.info()
        assert 'VMState="poweroff"' in info and re.search(r'^cpus=1$',info,re.M)
        lab.run([lab.vbox,'modifyvm',lab.vm.name,'--cpus','4'])
        cpu_changed = True
        lab.start()
        lab.report['gateway_cpu_control'] = lab.fixture['gateway_cpu_control']
        if args.linux_qualification:
            deadline = time.monotonic()+900
            while not args.linux_qualification.exists():
                assert time.monotonic() < deadline, 'Linux qualification did not finish'
                time.sleep(2)
            qualified = json.loads(args.linux_qualification.read_text())
            assert qualified['passed'] and qualified['package_sha256'] == lab.package_sha
            lab.report['linux_qualification_sha256'] = sha(args.linux_qualification.read_bytes())
        original = lab.admin('config')
        lab.report['original_policy'] = original
        users = application_seed(lab,'dolibarr',{})
        email = 'nat-'+lab.tag+'@example.invalid'
        seeded = application_seed(lab,'prestashop',dict(email=email,password=lab.fixture['prestashop']['password']))
        lab.report['seeded_nat_customer_id'] = seeded['customer_id']
        lab.report['store_before'] = fair.store_state(lab)
        lab.report['customers_before'] = fair.abuse.customer_state(lab)
        prior_files = []
        prior_manifests = {}
        for manifest in args.prior_files:
            manifest = manifest.resolve(strict=True)
            assert manifest.name in ['files.json','recovered-files.json'] and manifest.parent.parent == lab.repo/'artifacts'
            assert re.fullmatch(r'm4-business-abuse-[a-f0-9]{8}',manifest.parent.name)
            prior_manifests[manifest.parent.name] = sha(manifest.read_bytes())
            prior_files.extend(json.loads(manifest.read_text()))
        lab.report['prior_file_manifests'] = prior_manifests
        if prior_files:
            lab.report['prior_files_verified'] = lab.guest('files',dict(files=prior_files))
        proxies = [BrowserProxy(lab,lane) for lane in ['upload','storefront','attacker','second-attacker']]
        urls = [proxy.start() for proxy in proxies]
        erp = 'http://erp.joint.test:'+str(lab.ports['proxy'])
        shop = 'http://shop.joint.test:'+str(lab.ports['proxy'])
        routes = {key:shop+urlsplit(value).path+('?' +urlsplit(value).query if urlsplit(value).query else '')
                  for key,value in lab.fixture['prestashop']['routes'].items()}
        workflow = json.loads((lab.repo/'artifacts/m4-business-2be162b6/results-19.json').read_text())
        invoice = next(case['invoice_id'] for case in workflow['cases'] if case['name']=='create, price and validate invoice')
        _,body = lab.send('dolibarr','control','GET','/api/index.php/invoices/'+str(invoice),
                         headers={'DOLAPIKEY':lab.fixture['dolibarr']['api_key']},validate=lambda status,data:status==200)
        lab.browser_fixture = dict(tag=lab.tag,proxies=urls,erpOrigin=erp,shopOrigin=shop,routes=routes,
            erpUsers=users,erpPassword=lab.fixture['dolibarr']['password'],natEmail=email,
            shopPassword=lab.fixture['prestashop']['password'],apiKey=lab.fixture['dolibarr']['api_key'],
            invoiceRef=json.loads(body)['ref'],uploadFixture=str(content),outputDirectory=str(lab.out))
        permissive = dict(max_concurrent=32,max_client_concurrent=0,client_requests_per_second=0,
                          client_burst=0,max_client_buffer_mib=0,admission_wait_ms=1000)
        strict = dict(max_concurrent=4,max_client_concurrent=3,client_requests_per_second=2,
                      client_burst=4,max_client_buffer_mib=5,admission_wait_ms=1000)
        candidate = dict(max_concurrent=32,max_client_concurrent=0,client_requests_per_second=30,
                         client_burst=96,max_client_buffer_mib=args.nat_client_buffer_mib,admission_wait_ms=1000)
        lab.report['nat_limits'] = candidate
        if args.nat_body_rate_kib:
            candidate.update(client_body_kib_per_second=args.nat_body_rate_kib,
                             client_body_burst_kib=args.nat_body_burst_kib)
        if args.abuse_seconds:
            lab.report['abuse_endurance'] = True
            lab.report['budgets'] = dict(navigation_p95_ms=5000,wave_p95_ms=20000,file_p95_ms=10000,cpu_percent=80)
            profiles = [('nat-baseline',[], 'attacker'),('nat-erp-abuse',['dolibarr'],'attacker'),
                        ('nat-shop-abuse',['prestashop'],'attacker'),
                        ('nat-both-abuse',['dolibarr','prestashop'],'attacker'),
                        ('nat-shared-abuse',['dolibarr','prestashop'],'upload')]
            for name,targets,lane in profiles:
                seconds = 60 if name=='nat-baseline' else args.abuse_seconds
                if name=='nat-shared-abuse' and args.shared_abuse_seconds:
                    seconds = args.shared_abuse_seconds
                phase(lab,proxies,name,candidate,True,seconds//15,
                      targets=targets,seconds=seconds,attack_lane=lane)
                if name == 'nat-baseline':
                    baseline = lab.report['phases'][-1]
                    lab.report['baseline_qualified'] = all(baseline[key] for key in [
                        'browser_passed','integrity_passed','responsiveness_passed',
                        'coverage_passed','resource_budget_passed'])
                    lab.save()
                    assert lab.report['baseline_qualified'], 'baseline failed; resolve host/workload limits before abuse qualification'
            lab.report['candidate_browser_passed'] = all(p['browser_passed'] for p in lab.report['phases'])
            lab.report['abuse_profile_qualified'] = all(p['browser_passed'] and p['integrity_passed'] and
                p['responsiveness_passed'] and p['coverage_passed'] and p['resource_budget_passed'] for p in lab.report['phases'])
            lab.report['external_source_profile_qualified'] = all(p['browser_passed'] and p['integrity_passed'] and
                p['responsiveness_passed'] and p['coverage_passed'] and p['resource_budget_passed'] for p in lab.report['phases'][:4])
        else:
            assert phase(lab,proxies,'reference',permissive,False,1,sequential=True), 'reference browser workflow failed'
            phase(lab,proxies,'strict-separate',strict,False,1)
            phase(lab,proxies,'strict-shared',strict,True,1)
            lab.report['candidate_browser_passed'] = phase(lab,proxies,'nat-candidate',candidate,True,args.waves)
        lab.report['files_verified'] = lab.guest('files',dict(files=lab.files))
        lab.report['store_after'] = fair.store_state(lab)
        lab.report['customers_after'] = fair.abuse.customer_state(lab)
        assert lab.report['customers_before'] == lab.report['customers_after']
        for key in ['orders','order_detail']:
            assert lab.report['store_before'][key] == lab.report['store_after'][key]
        restore = dict(original,revision=lab.admin('config')['revision'])
        lab.admin('config/apply',dict(config=restore,reason='Restore owned policy after browser/NAT qualification'))
        lab.report['restored_policy'] = lab.admin('config')
        lab.report['final_status'] = lab.drain()
        assert lab.report['final_status']['summary']['requests'] == len(lab.records)
        lab.report['spool_after'] = lab.guest('spool')
        lab.capture()
        for name,digest in lab.report['sources'].items():
            assert sha((lab.repo/'scripts'/name).read_bytes()) == digest
        lab.report['completed'] = True
        lab.report['passed'] = all(p.get('resource_evidence_passed',True) for p in lab.report['phases'])
    finally:
        for proxy in proxies:
            proxy.close()
        (lab.out/'files.json').write_text(json.dumps(lab.files))
        if lab.files and 'files_verified' not in lab.report:
            try:
                lab.report['files_verified'] = lab.guest('files',dict(files=lab.files))
            except Exception as error:
                lab.report['file_verification_error'] = type(error).__name__
        lab.close()
        if cpu_changed:
            info = lab.info()
            assert 'VMState="poweroff"' in info
            lab.run([lab.vbox,'modifyvm',lab.vm.name,'--cpus','1'])
            assert re.search(r'^cpus=1$',lab.info(),re.M)
            lab.report['original_cpu_restored'] = True
            lab.save()


if __name__ == '__main__':
    main()
