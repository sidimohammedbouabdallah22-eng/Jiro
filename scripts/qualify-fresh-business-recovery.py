"""Move the retained business checkpoint to an explicitly owned clean Ubuntu VM."""
import argparse
import importlib.util
import json
from pathlib import Path
import re
import shlex
import shutil
import socket
import subprocess
import threading
import time
import uuid

from browser_proxy import BrowserProxy
from joint_business_lab import Lab, sha
from joint_upload_data import upload_content
from m4_business_recovery_guest import digest
from wsl_fair_lab import acquire_lease


spec = importlib.util.spec_from_file_location('business_recovery', Path(__file__).with_name('qualify-business-recovery.py'))
business = importlib.util.module_from_spec(spec)
spec.loader.exec_module(business)


class FreshBusinessLab(Lab):
    def __init__(self, args):
        self.repo = Path(__file__).resolve().parents[1]
        self.vm = self.repo / 'artifacts/m2-vms' / args.vm
        assert re.fullmatch(r'openwaf-m2-24\.04-[a-f0-9]{8}', args.vm)
        preparation = json.loads((self.vm / 'result.json').read_text())
        assert preparation['prepared'] and not preparation['qualification_performed']
        assert preparation['memory_mib'] == 4096 and preparation['disk_gib'] == 32
        self.package = args.package.resolve(strict=True)
        self.package_sha = digest(self.package)
        assert self.package_sha == Path(str(self.package) + '.sha256').read_text().split()[0]
        assert preparation['package_sha256'] == self.package_sha
        self.donor = args.donor_report.resolve(strict=True)
        assert self.donor.parent.parent == self.repo / 'artifacts'
        self.original = json.loads(self.donor.read_text())
        assert self.original['passed'] and self.original['completed'] and self.original['lab_stopped']
        assert self.original['package_sha256'] == self.package_sha
        self.bundle = self.donor.parent / 'business-recovery.private.tar'
        assert digest(self.bundle) == self.original['recovery_capture']['sha256']
        assert shutil.disk_usage(self.repo).free >= 30 << 30
        self.tag = uuid.uuid4().hex[:8]
        self.root, self.remote = '/var/lib/owaf-joint-' + self.tag, '/tmp/owaf-joint-' + self.tag
        self.out = self.repo / 'artifacts' / ('m4-fresh-business-' + self.tag)
        self.out.mkdir()
        spec = importlib.util.spec_from_file_location('permissions', self.repo / 'scripts/qualify-applications.py')
        permissions = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(permissions)
        permissions.restrict_artifacts(self.out)
        source = self.out / 'source'
        source.mkdir()
        names = ['qualify-fresh-business-recovery.py', 'm4_fresh_business_guest.py',
            'm4_business_recovery_guest.py', 'm4_business_guest.py', 'm4_joint_files.php',
            'owned_lab_environment.py', 'qualify-business-recovery.py', 'browser_proxy.py',
            'joint_business_lab.py', 'joint_upload_data.py']
        hashes = {}
        for name in names:
            data = (self.repo / 'scripts' / name).read_bytes()
            (source / name).write_bytes(data)
            hashes[name] = sha(data)
        browser = self.repo / 'tools/application-check/browser-nat.cjs'
        (source / browser.name).write_bytes(browser.read_bytes())
        (source / 'target-preparation.json').write_text(json.dumps(preparation, indent=2))
        self.report = dict(passed=False, completed=False, vm=args.vm, functional_only=True,
            capacity_qualification=False, business_pilot_started=False, sources=hashes,
            browser_source_sha256=digest(browser), package_sha256=self.package_sha,
            server_sha256=self.original['server_sha256'], donor_report=str(self.donor),
            donor_report_sha256=digest(self.donor), donor_bundle_sha256=digest(self.bundle),
            checkpoint=self.original['checkpoint'], checkpoint_policy=self.original['checkpoint_policy'],
            scope='fresh Ubuntu 24.04 amd64 OS, cold Dolibarr/PrestaShop/Jiro recovery')
        self.vbox = r'C:\Program Files\Oracle\VirtualBox\VBoxManage.exe'
        self.records, self.lock, self.files = [], threading.Lock(), []
        self.fixture = json.loads((self.donor.parent / 'fixture.private.json').read_text())
        self.ports = self.fixture['ports']
        self.lanes = {name:dict(port=self.ports['proxy'], peer='127.0.0.1')
            for name in ['upload', 'storefront', 'attacker', 'second-attacker']}
        self.timing = threading.local()
        self.tunnel = None
        self.save()

    def guest(self, operation, payload=None):
        command = shlex.join(['sudo', 'python3', self.remote + '/m4_fresh_business_guest.py',
            operation, '--root', self.root])
        return json.loads(self.run([*self.ssh, command], None if payload is None else json.dumps(payload),
                                  timeout=2400).stdout)

    def donor_off(self):
        manifest = self.repo / 'artifacts/m4-wsl-qualification-20261108/fixture.private.json'
        config = json.loads(manifest.read_text())
        lease = acquire_lease(manifest.parent / 'qualification.lock')
        distribution = config['distribution']
        try:
            script = "import json,hashlib,subprocess; from pathlib import Path; marker=json.loads(Path('/etc/jiro-m4-owned-lab.json').read_text()); assert marker==json.loads(" + repr(json.dumps(dict(lab_id=config['lab_id'], scope='owned-jiro-m4-lab'))) + "); assert not subprocess.check_output(['docker','ps','-q'],text=True).strip(); print(json.dumps(dict(machine_id=hashlib.sha256(Path('/etc/machine-id').read_bytes()).hexdigest(),containers_stopped=True,lab_id=marker['lab_id'])))"
            result = self.run(['wsl', '-d', distribution, '-u', 'root', '--exec', 'python3', '-c', script])
            proof = json.loads(result.stdout)
        finally:
            self.run(['wsl', '-d', distribution, '-u', 'root', '--exec', 'sh', '-c',
                'systemctl stop docker.socket docker.service containerd.service && sync'], timeout=120)
            self.run(['wsl', '--terminate', distribution])
            lease.close()
        self.assert_donor_off(distribution)
        proof.update(distribution=distribution, powered_off=True)
        return proof

    def assert_donor_off(self, distribution):
        result = subprocess.run(['wsl', '--list', '--running', '--quiet'], capture_output=True, check=True)
        data = result.stdout
        text = data.decode('utf-16-le') if b'\x00' in data[:100] else data.decode()
        assert distribution.casefold() not in {line.strip().casefold() for line in text.lstrip('\ufeff').splitlines()}

    def execute(self):
        proxies = []
        started = False
        restored = False
        try:
            self.report['donor_off'] = self.donor_off()
            info = self.info()
            assert 'VMState="poweroff"' in info and 'cpus=1\n' in info and 'memory=4096\n' in info
            for port in [self.ports['admin'], self.ports['proxy']]:
                with socket.socket() as probe:
                    probe.bind(('127.0.0.1', port))
            port = re.search(r'Forwarding\(0\)="ssh,tcp,127\.0\.0\.1,(\d+),,22"', info)[1]
            self.configure_ssh(port, self.vm / 'identity', self.vm / 'known_hosts')
            self.run([self.vbox, 'startvm', self.vm.name, '--type', 'headless'])
            started = True
            deadline = time.monotonic() + 240
            while time.monotonic() < deadline:
                if self.run([*self.ssh, 'true'], check=False).returncode == 0:
                    break
                time.sleep(2)
            else:
                raise RuntimeError('fresh VM SSH startup deadline exceeded')
            self.run([*self.ssh, 'mkdir -m 700 ' + self.remote])
            self.run([*self.scp, *(self.out / 'source').glob('*.py'), self.repo / 'scripts/m4_joint_files.php',
                'qualifier@127.0.0.1:' + self.remote + '/'])
            self.report['preconditions'] = self.guest('prepare', dict(source_machine_id=self.report['donor_off']['machine_id'],
                checkpoint_sha256=self.original['checkpoint']['manifest_sha256']))
            self.save()
            print('Clean OS and empty Docker verified; transferring cold checkpoint', flush=True)
            self.run([*self.scp, self.package, 'qualifier@127.0.0.1:' + self.remote + '/candidate.tar.gz'], timeout=600)
            self.run([*self.scp, self.bundle, 'qualifier@127.0.0.1:' + self.remote + '/business-recovery.private.tar'], timeout=1800)
            self.assert_donor_off(self.report['donor_off']['distribution'])
            self.report['activation'] = self.guest('restore', dict(bundle=self.remote + '/business-recovery.private.tar',
                bundle_sha256=self.report['donor_bundle_sha256'], package=self.remote + '/candidate.tar.gz',
                package_sha256=self.package_sha, server_sha256=self.report['server_sha256'],
                checkpoint_sha256=self.original['checkpoint']['manifest_sha256'],
                source_tag=self.donor.parent.name.rsplit('-', 1)[1]))
            restored = True
            forward = []
            for value in [self.ports['admin'], self.ports['proxy']]:
                forward.extend(['-L', f'127.0.0.1:{value}:127.0.0.1:{value}'])
            self.tunnel = self.create_tunnel(forward)
            deadline = time.monotonic() + 120
            while time.monotonic() < deadline:
                try:
                    if self.admin('health')['healthy']:
                        break
                except OSError:
                    pass
                time.sleep(1)
            else:
                raise RuntimeError('restored management health deadline exceeded')
            assert self.admin('config') == self.original['checkpoint_policy']
            prior = json.loads((self.repo / 'artifacts' / self.original['prior_manifest']['directory'] / 'files.json').read_text())
            known = prior + self.original['source_browser']['files']
            self.report['existing_files'] = self.guest('files', dict(files=known, sources=self.remote))
            proxies = [BrowserProxy(self, name) for name in self.lanes]
            urls = [proxy.start() for proxy in proxies]
            self.browser_fixture = json.loads((self.donor.parent / 'before-recovery.private.json').read_text())
            content = self.out / 'upload-content.bin'
            content.write_bytes(upload_content('mixed-csv'))
            self.browser_fixture.update(tag=self.tag, proxies=urls, uploadFixture=str(content), outputDirectory=str(self.out))
            self.report['browser'] = business.browsers(self, proxies, 'fresh-recovery')
            self.report['all_files'] = self.guest('files', dict(files=known + self.files, sources=self.remote))
            for app in ['dolibarr', 'prestashop']:
                self.send(app, 'fresh-recovery-attack', 'GET', '/?q=%3Cscript%3Ealert(1)%3C/script%3E',
                    validate=lambda status, body:status == 403)
            self.report['status'] = self.drain()
            self.report['capture'] = self.guest('capture')
            self.run([*self.scp, 'qualifier@127.0.0.1:' + self.root + '/business-recovery.private.tar',
                self.out / 'business-recovery.private.tar'], timeout=1800)
            assert digest(self.out / 'business-recovery.private.tar') == self.report['capture']['sha256']
            self.assert_donor_off(self.report['donor_off']['distribution'])
            assert all(digest(self.repo / 'scripts' / name) == value for name, value in self.report['sources'].items())
            assert digest(self.repo / 'tools/application-check/browser-nat.cjs') == self.report['browser_source_sha256']
            self.report.update(passed=True, completed=True)
        finally:
            for proxy in proxies:
                proxy.close()
            if started:
                try:
                    if restored:
                        self.report['cleanup'] = self.guest('stop')
                    self.run([*self.ssh, 'sudo poweroff'], check=False, timeout=30)
                    deadline = time.monotonic() + 90
                    while time.monotonic() < deadline and 'VMState="poweroff"' not in self.info():
                        time.sleep(1)
                    self.report['vm_powered_off'] = 'VMState="poweroff"' in self.info()
                    if not self.report['vm_powered_off']:
                        self.report['passed'] = False
                except Exception as error:
                    self.report.update(passed=False, cleanup_error=type(error).__name__)
            if self.tunnel:
                self.tunnel.terminate()
                self.tunnel.wait(timeout=20)
            self.save()
            print(self.out / 'result.json', flush=True)


if __name__ == '__main__':
    if not __debug__:
        raise RuntimeError('qualification requires assertions; do not use -O')
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--vm', required=True)
    parser.add_argument('--package', type=Path, required=True)
    parser.add_argument('--donor-report', type=Path, required=True)
    parser.add_argument('--disposable-vm', action='store_true', required=True)
    FreshBusinessLab(parser.parse_args()).execute()
