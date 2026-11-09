"""Restore the selected WAF and both owned business applications into isolated copies."""
import argparse
import importlib.util
import json
from pathlib import Path
import shlex
import shutil
import subprocess
import time
from urllib.parse import urlsplit

from browser_proxy import BrowserProxy
from joint_business_lab import sha
from joint_upload_data import upload_content
from m4_business_recovery_guest import digest
from wsl_fair_lab import WSLFairLab


spec = importlib.util.spec_from_file_location('browser_qualification', Path(__file__).with_name('qualify-browser-nat.py'))
browser_qualification = importlib.util.module_from_spec(spec)
spec.loader.exec_module(browser_qualification)


def recovery(lab, operation, payload=None):
    command = shlex.join(['sudo', 'python3', lab.remote + '/m4_business_recovery_guest.py', operation,
                          '--root', lab.root])
    return json.loads(lab.run([*lab.ssh, command], None if payload is None else json.dumps(payload),
                             timeout=1800).stdout)


def browsers(lab, proxies, profile):
    for proxy in proxies:
        proxy.profile = profile
    private = lab.out / (profile + '.private.json')
    private.write_text(json.dumps(dict(lab.browser_fixture, profile=profile, sharedNat=True,
                                      waves=1, sequential=False, uploads=True, intervalMs=15000)))
    result = lab.out / (profile + '-browser.json')
    process = subprocess.run(['node', str(lab.repo / 'tools/application-check/browser-nat.cjs'),
                              str(private), str(result)], capture_output=True, text=True, timeout=300)
    (lab.out / (profile + '-runner.log')).write_text(process.stdout + process.stderr)
    report = json.loads(result.read_text())
    files = report['initial_uploads'][:]
    for wave in report['waves']:
        for session in wave['sessions']:
            files.extend(session['uploads'])
    lab.files.extend(files)
    (lab.out / 'files.json').write_text(json.dumps(lab.files))
    assert process.returncode == 0 and report['passed'] and len(files) == 4
    assert all(item['committed'] and item['exact'] for item in files)
    return dict(result=result.name, sha256=sha(result.read_bytes()), files=files,
                requests=sum(row['label'] == profile for row in lab.records))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--package', type=Path, required=True)
    parser.add_argument('--wsl-fixture', type=Path, required=True)
    parser.add_argument('--prior-files', type=Path, required=True)
    args = parser.parse_args()
    host_free = shutil.disk_usage(Path(__file__).resolve().parents[1]).free
    if host_free < 15 << 30:
        raise RuntimeError('business recovery rehearsal requires fifteen GiB of host disk headroom')
    sources = ['qualify-business-recovery.py', 'm4_business_recovery_guest.py', 'm4_joint_business_guest.py',
               'm4_joint_fair_guest.py', 'm4_joint_domains.php', 'm4_joint_files.php', 'm4_business_guest.py',
               'm4_browser_seed.php', 'qualify-browser-nat.py', 'wsl_fair_lab.py', 'browser_proxy.py',
               'joint_business_lab.py', 'joint_fair_lab.py', 'joint_upload_data.py']
    lab = WSLFairLab(args.package, sources, args.wsl_fixture, lane_connections=64)
    lab.fixture['qualification_resources'] = dict(max_concurrent=64, max_connections=128)
    old = lab.out.resolve()
    target = lab.repo / 'artifacts' / ('m4-business-recovery-' + lab.tag)
    assert old.parent == target.parent.resolve() == lab.repo / 'artifacts' and not target.exists()
    old.rename(target)
    lab.out, lab.private = target, target / 'fixture.private.json'
    lab.report.update(experiment='Coordinated cold business and WAF recovery', functional_only=True,
                      capacity_qualification=False, business_pilot_started=False, scope='owned WSL2 service slice')
    lab.report['host_disk_free_before_bytes'] = host_free
    browser_source = lab.repo / 'tools/application-check/browser-nat.cjs'
    lab.report['browser_source_sha256'] = sha(browser_source.read_bytes())
    (lab.out / 'source/browser-nat.cjs').write_bytes(browser_source.read_bytes())
    lab.files = []
    proxies, attempted = [], False
    try:
        lab.start()
        users = browser_qualification.application_seed(lab, 'dolibarr', {})
        email = 'nat-' + lab.tag + '@example.invalid'
        browser_qualification.application_seed(lab, 'prestashop', dict(email=email,
            password=lab.fixture['prestashop']['password']))
        config = lab.admin('config')
        for app in config['applications']:
            app['traffic_controls'] = dict(max_concurrent=32, max_client_concurrent=0,
                client_requests_per_second=30, client_burst=96, max_client_buffer_mib=24,
                admission_wait_ms=1000, client_body_kib_per_second=192, client_body_burst_kib=5120)
            if app['application_id'] == 'dolibarr':
                app['traffic_controls']['client_body_reservation'] = dict(method='POST',
                    path='/api/index.php/documents/upload', kib_per_second=160, burst_kib=4096)
        lab.admin('config/apply', dict(config=config, reason='Owned coordinated business recovery rehearsal'))
        lab.report['checkpoint_policy'] = lab.admin('config')
        prior = args.prior_files.resolve(strict=True)
        assert prior.name == 'files.json' and prior.parent.parent == lab.repo / 'artifacts'
        prior_files = json.loads(prior.read_text())
        assert len(prior_files) >= 1 and all(item['committed'] and item['exact'] for item in prior_files)
        lab.report['prior_manifest'] = dict(directory=prior.parent.name, sha256=sha(prior.read_bytes()))
        lab.report['prior_files_verified'] = lab.guest('files', dict(files=prior_files))
        proxies = [BrowserProxy(lab, lane) for lane in ['upload', 'storefront', 'attacker', 'second-attacker']]
        urls = [proxy.start() for proxy in proxies]
        shop = 'http://shop.joint.test:' + str(lab.ports['proxy'])
        erp = 'http://erp.joint.test:' + str(lab.ports['proxy'])
        routes = {key:shop + urlsplit(value).path + ('?' + urlsplit(value).query if urlsplit(value).query else '')
                  for key, value in lab.fixture['prestashop']['routes'].items()}
        workflow = json.loads((lab.repo / 'artifacts/m4-business-2be162b6/results-19.json').read_text())
        invoice = next(case['invoice_id'] for case in workflow['cases'] if case['name'] == 'create, price and validate invoice')
        _, data = lab.send('dolibarr', 'control', 'GET', '/api/index.php/invoices/' + str(invoice),
            headers={'DOLAPIKEY':lab.fixture['dolibarr']['api_key']}, validate=lambda code, data:code == 200)
        content = lab.out / 'upload-content.bin'
        content.write_bytes(upload_content('mixed-csv'))
        lab.browser_fixture = dict(tag=lab.tag, proxies=urls, erpOrigin=erp, shopOrigin=shop,
            routes=routes, erpUsers=users, erpPassword=lab.fixture['dolibarr']['password'], natEmail=email,
            shopPassword=lab.fixture['prestashop']['password'], apiKey=lab.fixture['dolibarr']['api_key'],
            invoiceRef=json.loads(data)['ref'], uploadFixture=str(content), outputDirectory=str(lab.out))
        lab.report['source_browser'] = browsers(lab, proxies, 'before-recovery')
        lab.report['source_files'] = lab.guest('files', dict(files=prior_files + lab.files))
        for app in ['dolibarr', 'prestashop']:
            code, _ = lab.send(app, 'before-recovery-attack', 'GET', '/?q=%3Cscript%3Ealert(1)%3C/script%3E',
                               validate=lambda code, data:code == 403)
            assert code == 403
        lab.report['source_status'] = lab.drain()
        lab.capture()
        attempted = True
        lab.report['checkpoint'] = recovery(lab, 'checkpoint')
        lab.save()
        print('Business checkpoint created', flush=True)
        lab.report['restoration'] = recovery(lab, 'restore', lab.report['checkpoint'])
        for _ in range(120):
            try:
                if lab.admin('health')['healthy']:
                    break
            except OSError:
                pass
            time.sleep(1)
        else:
            raise RuntimeError('restored gateway health deadline exceeded')
        assert lab.admin('config') == lab.report['checkpoint_policy']
        lab.report['restored_existing_files'] = recovery(lab, 'files', dict(files=prior_files + lab.files,
                                                                         sources=lab.remote))
        print('Database, image, volume and policy restore verified', flush=True)
        lab.report['restored_browser'] = browsers(lab, proxies, 'after-recovery')
        lab.report['restored_all_files'] = recovery(lab, 'files', dict(files=prior_files + lab.files,
                                                                    sources=lab.remote))
        for app in ['dolibarr', 'prestashop']:
            code, _ = lab.send(app, 'after-recovery-attack', 'GET', '/?q=%3Cscript%3Ealert(1)%3C/script%3E',
                               validate=lambda code, data:code == 403)
            assert code == 403
        lab.report['restored_status'] = lab.drain()
        lab.report['recovery_capture'] = recovery(lab, 'capture')
        bundle = lab.out / 'business-recovery.private.tar'
        lab.run([*lab.scp, 'qualifier@127.0.0.1:' + lab.root + '/business-recovery.private.tar', bundle], timeout=1800)
        assert digest(bundle) == lab.report['recovery_capture']['sha256']
        for name, expected in lab.report['sources'].items():
            assert sha((lab.repo / 'scripts' / name).read_bytes()) == expected
        assert sha(browser_source.read_bytes()) == lab.report['browser_source_sha256']
        lab.report['completed'] = True
        lab.report['passed'] = True
    finally:
        for proxy in proxies:
            proxy.close()
        if attempted:
            if not lab.report.get('completed'):
                for kind in ('gateway', 'collector'):
                    try:
                        journal = lab.run([*lab.ssh, shlex.join(['sudo', 'journalctl', '-u',
                            lab.fixture['units'][kind], '--no-pager', '-n', '50', '-o', 'cat'])], check=False, timeout=30)
                        (lab.out / ('recovery-' + kind + '-journal.private.log')).write_text(journal.stdout + journal.stderr)
                    except (OSError, subprocess.TimeoutExpired):
                        lab.report['recovery_journal_incomplete'] = True
            try:
                lab.report['business_cleanup'] = recovery(lab, 'cleanup')
                if lab.report.get('completed'):
                    absent = [dict(item, committed=False, exact=False) for item in lab.report['restored_browser']['files']]
                    lab.report['source_isolation'] = lab.guest('files', dict(files=lab.report['source_browser']['files'] + absent))
            except Exception as error:
                lab.report['business_cleanup_error'] = type(error).__name__
                lab.report['passed'] = False
        (lab.out / 'files.json').write_text(json.dumps(lab.files))
        lab.close()


if __name__ == '__main__':
    main()
