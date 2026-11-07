"""Lifecycle and evidence helpers for the owned two-product M4 abuse lab."""
import hashlib
import http.client
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
import uuid


def sha(data):
    return hashlib.sha256(data).hexdigest()


class Lab:
    def __init__(self, package, sources, vcpus=1):
        if not __debug__:
            raise RuntimeError('qualification requires Python assertions; do not use -O')
        self.repo = Path(__file__).resolve().parents[1]
        assert vcpus in [1,2,4]
        self.vcpus = vcpus
        self.package = package.resolve(strict=True)
        self.package_sha = sha(self.package.read_bytes())
        assert self.package_sha == Path(str(self.package) + '.sha256').read_text().split()[0]
        self.tag = uuid.uuid4().hex[:8]
        self.out = self.repo / 'artifacts' / ('m4-business-abuse-' + self.tag)
        self.out.mkdir()
        spec = importlib.util.spec_from_file_location('permissions', self.repo / 'scripts/qualify-applications.py')
        permissions = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(permissions)
        permissions.restrict_artifacts(self.out)
        source = self.out / 'source'
        source.mkdir()
        hashes = {}
        for name in sources:
            data = (self.repo / 'scripts' / name).read_bytes()
            (source / name).write_bytes(data)
            hashes[name] = sha(data)
        dol = json.loads((self.repo / 'artifacts/m4-business-2be162b6/fixture.private.json').read_text())
        shop = json.loads((self.repo / 'artifacts/m4-business-77aadf7d/fixture.private.json').read_text())
        assert dol['vm_dir'] == shop['vm_dir'] and dol['package_sha256'] == shop['package_sha256']
        self.vm = Path(dol['vm_dir']).resolve(strict=True)
        assert self.vm.parent == (self.repo / 'artifacts/m2-vms').resolve()
        assert re.fullmatch(r'openwaf-m2-24\.04-[a-f0-9]{8}', self.vm.name)
        self.vbox = r'C:\Program Files\Oracle\VirtualBox\VBoxManage.exe'
        self.root, self.remote = '/var/lib/owaf-joint-' + self.tag, '/tmp/owaf-joint-' + self.tag
        with tarfile.open(self.package) as archive:
            server_sha = sha(archive.extractfile('usr/lib/openwaf/waf-server').read())
        listeners = [socket.socket() for _ in range(3)]
        for listener in listeners:
            listener.bind(('127.0.0.1', 0))
        self.ports = dict(zip(['admin', 'proxy', 'collector'], [s.getsockname()[1] for s in listeners]))
        for listener in listeners:
            listener.close()
        self.fixture = dict(dolibarr=dol, prestashop=shop, ports=self.ports,
                            package=self.remote + '/candidate.tar.gz', package_sha256=self.package_sha,
                            server_sha256=server_sha)
        self.report = dict(passed=False, server_sha256=server_sha, package_sha256=self.package_sha,
                           vcpus=vcpus,
                           base_fixture_package_sha256=dol['package_sha256'],
                           sources=hashes, phases=[], cases=[], business_pilot_started=False,
                           scope='one Linux amd64 gateway, real ERP and storefront, synthetic inspection abuse')
        self.records, self.lock = [], threading.Lock()
        self.timing = threading.local()
        self.attempted, self.tunnel, self.ssh = False, None, None
        self.private = self.out / 'fixture.private.json'
        self.private.write_text(json.dumps(self.fixture))
        self.save()

    def run(self, argv, data=None, timeout=180, check=True):
        p = subprocess.run([str(x) for x in argv], input=data, capture_output=True, text=True, timeout=timeout)
        if check and p.returncode:
            (self.out / 'failure.private.txt').write_text(p.stdout + p.stderr)
            raise RuntimeError('owned lab command failed; inspect private evidence')
        return p

    def info(self):
        for _ in range(30):
            p = self.run([self.vbox, 'showvminfo', self.vm.name, '--machinereadable'], timeout=20, check=False)
            if p.returncode == 0 and re.search(r'^VMState=', p.stdout, re.M):
                return p.stdout
            time.sleep(1)
        raise RuntimeError('VM metadata unavailable')

    def guest(self, op, data=None):
        command = shlex.join(['sudo', 'python3', self.remote + '/m4_joint_business_guest.py', op,
                              '--root', self.root, '--sources', self.remote])
        return json.loads(self.run([*self.ssh, command], None if data is None else json.dumps(data)).stdout)

    def save(self):
        (self.out / 'result.json').write_text(json.dumps(self.report, indent=2))
        with self.lock:
            (self.out / 'requests.json').write_text(json.dumps(self.records))

    def admin(self, path, data=None):
        c = http.client.HTTPConnection('127.0.0.1', self.ports['admin'], timeout=30)
        try:
            c.request('GET' if data is None else 'POST', '/api/v1/' + path,
                      body=None if data is None else json.dumps(data),
                      headers={'Authorization': 'Bearer ' + self.fixture['token'], 'Content-Type': 'application/json'})
            r = c.getresponse()
            body = r.read(4 << 20)
            assert r.status == 200, 'administration operation failed: ' + str(r.status)
            return json.loads(body)
        finally:
            c.close()

    def send(self, app, label, method, path, body=None, headers=None, validate=None):
        start = time.perf_counter()
        due = getattr(self.timing, 'due', start)
        row = dict(app=app, label=label, sequence=getattr(self.timing, 'sequence', None),
                   start_delay_ms=(start-due)*1000, request_bytes=len(body or b''),
                   request_sha256=sha(body or b''), status=0, valid=False)
        c = http.client.HTTPConnection('127.0.0.1', self.ports['proxy'], timeout=45)
        try:
            c.request(method, path, body, {'Host': ('erp' if app == 'dolibarr' else 'shop') +
                      '.joint.test:' + str(self.ports['proxy']), 'Content-Type': 'application/json',
                      'User-Agent': 'OpenWAF owned CPU abuse qualification', **(headers or {})})
            r = c.getresponse()
            data = r.read((2 << 20) + 1)
            assert len(data) <= 2 << 20
            row.update(status=r.status, response_bytes=len(data), response_sha256=sha(data))
            row['valid'] = bool(validate(r.status, data)) if validate else True
            return r.status, data
        except Exception as error:
            row['error'] = type(error).__name__
            raise
        finally:
            end = time.perf_counter()
            row.update(service_ms=(end-start)*1000, scheduled_ms=(end-due)*1000)
            with self.lock:
                self.records.append(row)
            c.close()

    def start(self):
        info = self.info()
        assert 'cpus='+str(self.vcpus)+'\n' in info and 'memory=4096\n' in info
        # Refuse overlap with another qualification or an operator-owned session.
        assert 'VMState="poweroff"' in info, 'CPU lab requires the owned VM to be powered off first'
        port = re.search(r'Forwarding\(0\)="ssh,tcp,127\.0\.0\.1,(\d+),,22"', info)[1]
        opts = ['-i', self.vm/'identity', '-o', 'BatchMode=yes', '-o', 'ConnectTimeout=5',
                '-o', 'ServerAliveInterval=5', '-o', 'ServerAliveCountMax=3',
                '-o', 'StrictHostKeyChecking=yes', '-o', 'UserKnownHostsFile='+str(self.vm/'known_hosts')]
        self.ssh = ['ssh', *opts, '-p', port, 'qualifier@127.0.0.1']
        self.scp = ['scp', *opts, '-P', port]
        self.run([self.vbox, 'startvm', self.vm.name, '--type', 'headless'])
        for _ in range(90):
            if self.run([*self.ssh, 'true'], check=False).returncode == 0:
                break
            time.sleep(2)
        else:
            raise RuntimeError('SSH startup deadline exceeded')
        actual_cpus=int(self.run([*self.ssh,'getconf _NPROCESSORS_ONLN']).stdout)
        assert actual_cpus==self.vcpus
        self.report['guest_logical_cpus']=actual_cpus
        self.run([*self.ssh, 'mkdir -m 700 ' + self.remote])
        self.run([*self.scp, *(self.out/'source').iterdir(), 'qualifier@127.0.0.1:'+self.remote+'/'])
        self.run([*self.scp, self.package, 'qualifier@127.0.0.1:'+self.fixture['package']])
        self.attempted = True
        self.fixture = self.guest('setup', self.fixture)
        self.report['backend_keepalive_directives']=self.fixture.get('backend_keepalive_directives',{})
        self.report['sampler_version']=self.fixture.get('sampler_version',1)
        self.private.write_text(json.dumps(self.fixture))
        forwards = []
        for port in self.ports.values():
            forwards += ['-L', f'127.0.0.1:{port}:127.0.0.1:{port}']
        self.tunnel = subprocess.Popen([str(x) for x in [*self.ssh[:-1], '-N', '-o',
                                      'ExitOnForwardFailure=yes', *forwards, self.ssh[-1]]],
                                      stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        for _ in range(120):
            try:
                if self.admin('health')['healthy']:
                    break
            except (OSError, ValueError):
                pass
            time.sleep(.25)
        else:
            raise RuntimeError('joint gateway health deadline exceeded')
        self.report['spool_before'] = self.guest('spool')
        assert self.report['spool_before']['files'] == 0

    def drain(self):
        deadline = time.monotonic() + 90
        while True:
            status = self.admin('status')
            storage = status['storage']
            if not status['resources']['active'] and not status['resources'].get('pending_admissions', 0) and not storage['pending_writes'] and not storage['export']['pending_records'] and storage['healthy'] and storage['export']['healthy']:
                break
            assert time.monotonic() < deadline, 'inspection or delivery did not drain'
            time.sleep(.25)
        assert status['summary']['event_persistence_errors'] == 0
        assert all(storage[k] == 0 for k in ['queue_dropped', 'write_failed', 'ingest_timeouts'])
        assert storage['healthy'] and storage['export']['healthy']
        assert status['resources']['reserved_buffer_bytes'] == 0
        return status

    def capture(self):
        self.report['capture'] = self.guest('capture')
        for name, key in [('databases.tar', 'sha256'), ('resources.jsonl', 'resources_sha256')]:
            self.run([*self.scp, 'qualifier@127.0.0.1:'+self.root+'/'+name, self.out/name])
            assert sha((self.out/name).read_bytes()) == self.report['capture'][key]

    def close(self):
        try:
            if self.attempted:
                if 'capture' not in self.report:
                    try:
                        self.report['failure_status'] = self.admin('status')
                        self.capture()
                    except Exception as error:
                        self.report['failure_capture_error'] = type(error).__name__
                try:
                    self.report['cleanup'] = self.guest('cleanup')
                except Exception as error:
                    self.report['cleanup'] = dict(restored=False, error=type(error).__name__)
                    self.report['passed'] = False
        finally:
            if self.tunnel:
                self.tunnel.terminate()
                self.tunnel.wait(timeout=20)
            if self.ssh and 'VMState="running"' in self.info():
                self.run([*self.ssh, 'sudo poweroff'], check=False)
                for _ in range(60):
                    if 'VMState="poweroff"' in self.info():
                        break
                    time.sleep(1)
            self.report['vm_powered_off'] = 'VMState="poweroff"' in self.info()
            self.save()
            print(self.out/'result.json', flush=True)


def resources(raw, begin, end, vcpus=1):
    if not __debug__:
        raise RuntimeError('resource verification requires Python assertions; do not use -O')
    samples = [json.loads(line) for line in raw.splitlines()]
    selected = [s for s in samples if begin['monotonic'] <= s['monotonic'] <= end['monotonic']]
    assert vcpus in [1,2,4] and all(s.get('cpus',1)==vcpus for s in selected)
    assert len(selected) >= 20
    assert selected[0]['monotonic']-begin['monotonic'] < 4 and end['monotonic']-selected[-1]['monotonic'] < 4
    assert all(b['monotonic']-a['monotonic'] < 4 for a, b in zip(selected, selected[1:]))
    span = selected[-1]['monotonic']-selected[0]['monotonic']
    result = dict(samples=len(selected), sampled_seconds=span, processes={}, containers={})
    for kind in ['processes', 'containers']:
        for name in selected[0][kind]:
            values = [s[kind][name] for s in selected]
            assert all(not v.get('unavailable') for v in values)
            assert all(b['cpu_seconds'] >= a['cpu_seconds'] for a, b in zip(values, values[1:]))
            facts = dict(cpu_percent=100*(values[-1]['cpu_seconds']-values[0]['cpu_seconds'])/span)
            if kind == 'processes':
                assert len({v['pid'] for v in values}) == 1
                facts.update(pid=values[0]['pid'], peak_rss_kib=max(v['rss_kib'] for v in values))
            else:
                assert all(v['oom_kill'] == 0 for v in values)
                facts.update(peak_memory_bytes=max(v['memory_bytes'] for v in values), oom_kill=0)
            result[kind][name] = facts
    first, last = selected[0]['host_cpu_ticks'], selected[-1]['host_cpu_ticks']
    result['guest_busy_percent'] = 100*(1-((last[3]+last[4])-(first[3]+first[4]))/(sum(last[:8])-sum(first[:8])))
    component = sum(v['cpu_percent'] for kind in ['processes', 'containers'] for v in result[kind].values())
    result['logical_cpus'] = vcpus
    result['component_cpu_percent_one_vcpu'] = component
    result['component_cpu_percent'] = component/vcpus
    result['observed_cpu_percent'] = max(component/vcpus, result['guest_busy_percent'])
    result['min_available_kib'] = min(s['host_available_kib'] for s in selected)
    return result
