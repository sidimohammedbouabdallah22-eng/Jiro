"""Measure and fault-test an existing owned amd64 VirtualBox qualification VM.

All traffic originates in this host process. The gateway, backend and reference
receivers run in separate guest processes. Only the gateway PID is measured.
"""

import argparse
import concurrent.futures
import hashlib
import http.client
import json
from pathlib import Path
import queue
import re
import shlex
import socket
import ssl
import subprocess
import tarfile
import threading
import time
import uuid


def percentile(values, fraction):
    ordered = sorted(values)
    return ordered[min(len(ordered) - 1, int((len(ordered) - 1) * fraction))] if ordered else 0


class TLSConnection(http.client.HTTPSConnection):
    def __init__(self, host, port, context):
        super().__init__(host, timeout=5, context=context)
        self.forwarded_port = port
        self.fixture_context = context

    def connect(self):
        raw = socket.create_connection(("127.0.0.1", self.forwarded_port), self.timeout)
        self.sock = self.fixture_context.wrap_socket(raw, server_hostname=self.host)


class Qualification:
    def __init__(self, args):
        self.args = args
        self.repo = Path(__file__).resolve().parents[1]
        self.vm = args.vm_dir.resolve(strict=True)
        record = json.loads((self.vm / "result.json").read_text())
        if record["vm"] != self.vm.name or not record["passed"] or not re.fullmatch(r"openwaf-m2-(22|24)\.04-[a-f0-9]{8}", self.vm.name):
            raise RuntimeError("requires an owned passing disposable qualification VM")
        allowed = (self.repo / "artifacts/m2-vms").resolve()
        if self.vm.parent != allowed:
            raise RuntimeError("VM is outside the qualification workspace")
        self.root = "/var/lib/owaf-m2-" + uuid.uuid4().hex[:8]
        self.package_inputs = {}
        for label in ["current", "previous"]:
            package = getattr(args, label)
            with tarfile.open(package) as archive:
                member = archive.getmember("usr/lib/openwaf/waf-server")
                if not member.isfile() or member.size > 256 << 20:
                    raise ValueError("unexpected candidate executable member")
                server_digest = hashlib.sha256(archive.extractfile(member).read()).hexdigest()
            self.package_inputs[label] = dict(package_sha256=hashlib.sha256(package.read_bytes()).hexdigest(),
                executable_sha256=server_digest, remote="/tmp/" + self.root.rsplit("/",1)[1] + "-" + label + ".tar.gz")
        if self.package_inputs["current"]["executable_sha256"] == self.package_inputs["previous"]["executable_sha256"]:
            raise ValueError("upgrade qualification requires two different executables")
        self.out = self.repo / "artifacts" / ("m2-operational-" + self.root.rsplit("-", 1)[1])
        self.out.mkdir()
        self.log = (self.out / "commands.log").open("w", encoding="utf-8", buffering=1)
        self.tunnel = None
        self.fixture = None
        info = subprocess.check_output([args.vbox, "showvminfo", self.vm.name, "--machinereadable"], text=True)
        self.ssh_port = int(re.search(r'Forwarding\(0\)="ssh,tcp,127\.0\.0\.1,(\d+),,22"', info)[1])
        if 'VMState="poweroff"' not in info:
            raise RuntimeError("qualification guest must start stopped")
        self.options = ["-i", str(self.vm / "identity"), "-o", "BatchMode=yes", "-o", "ConnectTimeout=3",
                        "-o", "StrictHostKeyChecking=accept-new", "-o", f"UserKnownHostsFile={self.vm / 'known_hosts'}"]
        self.ssh = ["ssh", *self.options, "-p", str(self.ssh_port), "qualifier@127.0.0.1"]
        self.report = dict(vm=self.vm.name, platform="linux-amd64",
                           gateway_vcpus=int(re.search(r'^cpus=(\d+)$', info, re.MULTILINE)[1]),
                           vm_memory_mib=int(re.search(r'^memory=(\d+)$', info, re.MULTILINE)[1]),
                           client="external host", measured_process="gateway PID only", smoke=args.smoke,
                           resource_limits=dict(concurrent=64, connections=256, buffer_mib=256),
                           harness_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
                           guest_helper_sha256=hashlib.sha256((self.repo / "scripts/m2_guest.py").read_bytes()).hexdigest(),
                           sizing_performed=not args.functional_only, phases=[], power_cuts=[], passed=False)
        self.report["package_inputs"] = self.package_inputs

    def execute(self, arguments, timeout=300, input_data=None, check=True):
        result = subprocess.run([str(value) for value in arguments], input=input_data, capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=timeout)
        if result.returncode or not check:
            self.log.write(result.stderr)
        if check and result.returncode:
            self.log.write(result.stdout)
            raise RuntimeError(f"{Path(arguments[0]).name} failed, see commands.log")
        return result

    def guest(self, operation, expected=None, **options):
        arguments = ["sudo", "python3", self.root + "/guest.py", operation, "--root", self.root, "--disposable-vm"]
        for name, value in options.items():
            arguments.extend(["--" + name, str(value)])
        result = self.execute([*self.ssh, shlex.join(arguments)], timeout=600,
                              input_data=None if expected is None else json.dumps(expected))
        return json.loads(result.stdout)

    def start_vm(self):
        self.execute([self.args.vbox, "startvm", self.vm.name, "--type", "headless"])
        deadline = time.monotonic() + 180
        while time.monotonic() < deadline:
            if self.execute([*self.ssh, "true"], timeout=10, check=False).returncode == 0:
                return
            time.sleep(1)
        raise RuntimeError("guest SSH startup deadline exceeded")

    def open_tunnel(self):
        if not hasattr(self, "admin_port"):
            listeners = [socket.socket() for _ in range(2)]
            for listener in listeners:
                listener.bind(("127.0.0.1", 0))
            self.admin_port, self.proxy_port = [listener.getsockname()[1] for listener in listeners]
            for listener in listeners:
                listener.close()
        self.tunnel = subprocess.Popen([*self.ssh[:-1], "-N", "-o", "ExitOnForwardFailure=yes",
            "-L", f"127.0.0.1:{self.admin_port}:127.0.0.1:{self.fixture['admin']}",
            "-L", f"127.0.0.1:{self.proxy_port}:127.0.0.1:{self.fixture['proxy']}", self.ssh[-1]], stdout=self.log, stderr=self.log)
        for _ in range(100):
            try:
                self.api("health")
                return
            except (OSError, ValueError, RuntimeError):
                if self.tunnel.poll() is not None:
                    raise RuntimeError("SSH forwarding exited")
                time.sleep(.1)
        raise RuntimeError("SSH forwarding was unavailable")

    def close_tunnel(self):
        if self.tunnel and self.tunnel.poll() is None:
            self.tunnel.terminate()
            self.tunnel.wait(timeout=15)

    def api(self, path, data=None):
        connection = http.client.HTTPConnection("127.0.0.1", self.admin_port, timeout=15)
        try:
            connection.request("GET" if data is None else "POST", "/api/v1/" + path,
                body=None if data is None else json.dumps(data),
                headers={"Authorization": "Bearer " + self.token, "Content-Type": "application/json"})
            response = connection.getresponse()
            payload = json.loads(response.read())
            if response.status != 200:
                raise RuntimeError(f"administration API {path} returned {response.status}")
            return payload
        finally:
            connection.close()

    def request(self, sequence, connection=None, marker="sizing"):
        owned = connection is None
        host = ["application.test", "portal.test"][sequence % 2]
        connection = connection or TLSConnection(host, self.proxy_port, self.context)
        attack = sequence % 10 in [5, 6, 7]
        body = None
        method = "GET"
        target = f"/search?qa={marker}-{sequence}&q=customer+invoice"
        if attack:
            target = f"/search?qa={marker}-{sequence}&q=%3Cscript%3Ealert(1)%3C/script%3E"
        elif sequence % 10 == 8:
            method = "POST"
            target = "/api/submit"
            body = json.dumps(dict(message="a" * 16384))
        try:
            connection.request(method, target, body=body, headers={"Host": host, "Content-Type": "application/json", "User-Agent": "OpenWAF M2 qualification"})
            response = connection.getresponse()
            payload = response.read()
            expected = 403 if attack else 200
            return response.status, response.status == expected and (attack or payload == b"backend-ok")
        finally:
            if owned:
                connection.close()

    def save(self):
        path = self.out / "result.json"
        temporary = self.out / "result.next"
        temporary.write_text(json.dumps(self.report, indent=2) + "\n")
        temporary.replace(path)

    def phase(self, label, rate, duration, required):
        jobs = queue.Queue(maxsize=32)
        lock = threading.Lock()
        results = []
        errors = []

        def worker():
            connections = {}
            try:
                while True:
                    sequence = jobs.get()
                    if sequence is None:
                        return
                    host = ["application.test", "portal.test"][sequence % 2]
                    if host not in connections:
                        connections[host] = TLSConnection(host, self.proxy_port, self.context)
                    connection = connections[host]
                    started = time.monotonic()
                    try:
                        status, correct = self.request(sequence, connection)
                        with lock:
                            results.append((status, correct, (time.monotonic() - started) * 1000))
                    except Exception as error:
                        connection.close()
                        connections.pop(host, None)
                        with lock:
                            errors.append(type(error).__name__)
                    finally:
                        jobs.task_done()
            finally:
                for connection in connections.values():
                    connection.close()

        threads = [threading.Thread(target=worker) for _ in range(8)]
        for thread in threads:
            thread.start()
        samples = []
        first = self.guest("sample")
        started = time.monotonic()
        deadline = started + duration
        sampling_done = threading.Event()
        sampling_errors = []

        def sampler():
            while not sampling_done.is_set():
                try:
                    sample = self.guest("sample")
                    sample["elapsed_seconds"] = time.monotonic() - started
                    samples.append(sample)
                    if len(samples) % 12 == 1:
                        print(f"{label}: {sample['elapsed_seconds']:.0f}/{duration}s RSS={sample['process']['rss_bytes']//1048576}MiB", flush=True)
                except Exception as error:
                    sampling_errors.append(type(error).__name__)
                    sampling_done.set()
                    return
                sampling_done.wait(5)

        sampling_thread = threading.Thread(target=sampler)
        sampling_thread.start()
        sequence = 0
        next_request = started
        try:
            while time.monotonic() < deadline and not sampling_done.is_set():
                now = time.monotonic()
                if now < next_request:
                    time.sleep(min(next_request - now, .02))
                    continue
                try:
                    jobs.put(sequence, timeout=.05)
                    sequence += 1
                except queue.Full:
                    pass
                next_request = max(next_request + 1 / rate, time.monotonic())
        finally:
            sampling_done.set()
            sampling_thread.join(timeout=120)
            jobs.join()
            for _ in threads:
                jobs.put(None)
            for thread in threads:
                thread.join()
        last = self.guest("sample")
        elapsed = time.monotonic() - started
        latencies = [row[2] for row in results]
        cpu = last["process"]["cpu_seconds"] - first["process"]["cpu_seconds"]
        result = dict(name=label, target_rps=rate, duration_seconds=elapsed, requests=len(results), network_errors=len(errors),
                      unexpected=sum(not row[1] for row in results), statuses={str(code):sum(row[0] == code for row in results) for code in {row[0] for row in results}},
                      achieved_rps=len(results)/elapsed, p50_ms=percentile(latencies,.5), p95_ms=percentile(latencies,.95), p99_ms=percentile(latencies,.99),
                      gateway_cpu_seconds=cpu, gateway_average_cpu_percent=cpu/elapsed*100,
                      gateway_peak_rss_bytes=max([last["process"]["peak_rss_bytes"], *[sample["process"]["rss_bytes"] for sample in samples]]), samples=samples)
        same_pid = first["process"]["pid"] == last["process"]["pid"] and first["process"]["start_ticks"] == last["process"]["start_ticks"]
        result["sampling_errors"] = sampling_errors
        result["passed"] = not errors and not sampling_errors and result["unexpected"] == 0 and result["achieved_rps"] >= rate*.9 and result["p95_ms"] < 1000 and result["gateway_peak_rss_bytes"] < 512*1048576 and same_pid and last["health"]["healthy"]
        self.report["phases"].append(result)
        self.save()
        print(f"{label} complete: passed={result['passed']} rate={result['achieved_rps']:.1f} p95={result['p95_ms']:.1f}ms", flush=True)
        if required and not result["passed"]:
            raise RuntimeError(f"required capacity profile failed: {label}")

    def power_cuts(self):
        for index in range(1 if self.args.smoke else 3):
            self.guest("change", label=f"Acknowledged before power cut {index}")
            for sequence in [5, 6, 7]:
                assert self.request(sequence, marker=f"power-{index}")[1]
            expected = self.guest("snapshot")
            oracle = self.out / f"power-{index}-acknowledged.json"
            with oracle.open("w") as output:
                json.dump(expected, output)
                output.flush()
                import os
                os.fsync(output.fileno())
            self.guest("arm")
            with concurrent.futures.ThreadPoolExecutor(max_workers=1) as executor:
                pending = executor.submit(self.request, 5, None, f"unacknowledged-{index}")
                journal = False
                for _ in range(10):
                    journal = self.guest("journal")["active"]
                    if journal:
                        break
                    time.sleep(.02)
                assert journal and not pending.done(), "cut must interrupt an active journaled request"
                cut_time = time.monotonic()
                self.execute([self.args.vbox, "controlvm", self.vm.name, "poweroff"])
                self.close_tunnel()
                try:
                    pending.result(timeout=10)
                except (OSError, http.client.HTTPException):
                    pass
            self.start_vm()
            self.guest("disarm")
            self.open_tunnel()
            verified = self.guest("verify", expected)
            assert time.monotonic() - cut_time < 180
            if self.args.m3:
                self.passkey_proof()
            self.report["power_cuts"].append(dict(journal_observed=True, recovery_seconds=time.monotonic()-cut_time, **verified))
            self.save()
            print(f"Power cut {index+1} verified", flush=True)

    def passkey_proof(self):
        private = self.out / "passkey-credential.private.json"
        fixture = dict(origin=f"http://localhost:{self.admin_port}")
        if private.exists():
            fixture.update(json.loads(private.read_text()))
        else:
            fixture["password"] = json.loads(self.execute([*self.ssh, f"sudo cat {self.root}/fixture.json"]).stdout)["password"]
        result = self.execute(["node", self.repo / "tools/ui-check/native-auth.cjs"], input_data=json.dumps(fixture))
        proof = json.loads(result.stdout)
        private.write_text(json.dumps(dict(credential=proof["credential"],totp=proof["totp"])))
        private.chmod(0o600)
        for sequence in range(4):
            assert self.request(sequence, marker="m3-recovery")[1]
        self.report.setdefault("passkey_proofs", []).append(dict(identity=proof["identity"], counter=proof["credential"]["signCount"], totp=True, **self.guest("m3-check")))
        self.save()

    def run(self):
        try:
            self.start_vm()
            scp = ["scp", *self.options, "-P", str(self.ssh_port)]
            self.execute([*scp, self.repo / "scripts/m2_guest.py", "qualifier@127.0.0.1:/tmp/"])
            for label in ["current", "previous"]:
                self.execute([*scp, getattr(self.args,label), "qualifier@127.0.0.1:" + self.package_inputs[label]["remote"]])
            setup = ["sudo", "python3", "/tmp/m2_guest.py", "setup", "--root", self.root, "--disposable-vm",
                     "--current", self.package_inputs["current"]["remote"], "--previous", self.package_inputs["previous"]["remote"]]
            self.fixture = json.loads(self.execute([*self.ssh, shlex.join(setup)]).stdout)
            for label in ["current", "previous"]:
                assert self.fixture[label+"_sha256"] == self.package_inputs[label]["executable_sha256"], "guest binary differs from selected host archive"
            self.token = self.execute([*self.ssh, "sudo cat /etc/openwaf/admin-token"]).stdout.strip()
            certificate = self.execute([*self.ssh, f"sudo cat {self.root}/tls/cert.pem"]).stdout
            self.context = ssl.create_default_context(cadata=certificate)
            self.open_tunnel()
            self.report["binaries"] = {name:self.fixture[name] for name in ["current_sha256", "previous_sha256"]}
            baseline = None
            if self.args.m3:
                baseline = self.guest("upgrade", stage="previous")
                assert baseline["executable_sha256"] == self.fixture["previous_sha256"]
                self.report["previous_login"] = self.guest("login")
                self.report["upgrade"] = self.guest("upgrade", stage="current")
                self.guest("verify", baseline)
                self.report["m3"] = self.guest("m3", origin=f"http://localhost:{self.admin_port}")
                self.passkey_proof()
            if self.args.functional_only:
                for sequence in range(10):
                    assert self.request(sequence, marker="functional")[1]
            else:
                for rate in [25, 50, 100]:
                    self.phase(f"ramp-{rate}", rate, 10 if self.args.smoke else 120, required=rate == 25)
                self.phase("sustained-25", 25, 20 if self.args.smoke else 7200, required=True)
            self.report["sizing_final"] = self.guest("snapshot")
            self.power_cuts()
            if baseline is None:
                baseline = self.guest("upgrade", stage="previous")
                assert baseline["executable_sha256"] == self.fixture["previous_sha256"]
                self.report["previous_login"] = self.guest("login")
                self.report["upgrade"] = self.guest("upgrade", stage="current")
                self.guest("verify", baseline)
            self.report["upgraded_login"] = self.guest("login")
            self.guest("change", label="Current binary post-checkpoint activation")
            assert self.request(5, marker="after-upgrade")[1]
            newer = self.guest("snapshot")
            self.report["rollback"] = self.guest("upgrade", stage="rollback")
            self.report["rollback_verification"] = self.guest("verify", baseline)
            assert self.report["rollback_verification"]["revision"] == baseline["policy"]["revision"]
            self.report["rollback_login"] = self.guest("login")
            self.report["post_upgrade_revision"] = newer["policy"]["revision"]
            self.report["passed"] = True
        finally:
            self.save()
            if self.fixture:
                self.execute([*self.ssh, shlex.join(["sudo", "python3", self.root+"/guest.py", "stop", "--root", self.root, "--disposable-vm"])], check=False)
            self.close_tunnel()
            self.execute([*self.ssh, "sudo poweroff"], timeout=20, check=False)
            self.log.close()
            print(self.out / "result.json", flush=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--vm-dir", type=Path, required=True)
    parser.add_argument("--current", type=Path, required=True)
    parser.add_argument("--previous", type=Path, required=True)
    parser.add_argument("--disposable-vm", action="store_true", required=True)
    parser.add_argument("--smoke", action="store_true")
    parser.add_argument("--functional-only", action="store_true", help="Run response/recovery/upgrade checks without a sizing claim")
    parser.add_argument("--m3", action="store_true", help="Upgrade before enabling pools, OIDC bindings and enforced passkeys")
    parser.add_argument("--vbox", default=r"C:\Program Files\Oracle\VirtualBox\VBoxManage.exe")
    args = parser.parse_args()
    for path in [args.current, args.previous]:
        expected = Path(str(path) + ".sha256").read_text().split()[0]
        assert hashlib.sha256(path.read_bytes()).hexdigest() == expected
    Qualification(args).run()


if __name__ == "__main__":
    main()
