"""Owned M4 capacity services, bounded backend and native process measurements."""

import argparse
from concurrent.futures import ThreadPoolExecutor
import hashlib
from http.server import BaseHTTPRequestHandler, HTTPServer
import json
import os
from pathlib import Path
import pwd
import re
import shutil
import sqlite3
import subprocess
import sys
import tarfile
import threading
import time
import urllib.parse


def command(args):
    return subprocess.check_output([str(v) for v in args], text=True, stderr=subprocess.DEVNULL, timeout=40).strip()


def setup(root, fixture):
    if root.exists():
        raise ValueError("capacity state already exists")
    disk=shutil.disk_usage(root.parent)
    if disk.free < 2<<30:
        raise RuntimeError("capacity qualification requires at least 2 GiB of free guest disk")
    root.mkdir(mode=0o755)
    requirements=command(['systemctl','show','openwaf.service','-p','Requires','--value']).split()
    previous=[name for name in requirements if re.fullmatch(r'openwaf-m2-(backend|events|audit)-[a-f0-9]{8}\.service',name)]
    command(['systemctl','stop','openwaf.service',*previous])
    fixture['stopped_previous_units']=['openwaf.service',*previous]
    cpu = Path("/proc/cpuinfo").read_text()
    memory = Path("/proc/meminfo").read_text()
    fixture["environment"] = dict(kernel=command(["uname", "-sr"]), architecture=command(["uname", "-m"]),
        cpu_model=re.search(r"model name\s*:\s*(.+)",cpu)[1], logical_cpus=os.cpu_count(),
        memory_total_kib=int(re.search(r"MemTotal:\s+(\d+)",memory)[1]), virtualization="VirtualBox", cgroup_version=2,
        filesystem_total_bytes=disk.total,filesystem_free_before_bytes=disk.free,minimum_free_before_bytes=2<<30)
    identity = pwd.getpwnam("openwaf")
    tls_arguments=""
    if fixture.get("proxy_tls"):
        certificates=root/"tls"
        certificates.mkdir(mode=0o750)
        os.chown(certificates,0,identity.pw_gid)
        command(["openssl","req","-x509","-newkey","rsa:2048","-nodes","-keyout",certificates/"ca.key","-out",certificates/"ca.pem",
                 "-subj","/CN=OpenWAF M4 qualification CA","-days","45",
                 "-addext","basicConstraints=critical,CA:TRUE","-addext","keyUsage=critical,keyCertSign,cRLSign"])
        command(["openssl","req","-newkey","rsa:2048","-nodes","-keyout",certificates/"proxy.key","-out",certificates/"proxy.csr","-subj","/CN=localhost"])
        (certificates/"extensions").write_text("subjectAltName=DNS:localhost,DNS:dvwa.capacity.test,DNS:probe.capacity.test\nbasicConstraints=critical,CA:FALSE\nextendedKeyUsage=serverAuth\nkeyUsage=critical,digitalSignature,keyEncipherment\nsubjectKeyIdentifier=hash\nauthorityKeyIdentifier=keyid,issuer\n")
        command(["openssl","x509","-req","-in",certificates/"proxy.csr","-CA",certificates/"ca.pem","-CAkey",certificates/"ca.key",
                 "-CAcreateserial","-out",certificates/"proxy.pem","-days","45","-extfile",certificates/"extensions"])
        (certificates/"ca.key").chmod(0o600)
        (certificates/"proxy.key").chmod(0o600)
        os.chown(certificates/"proxy.key",identity.pw_uid,identity.pw_gid)
        fixture["proxy_ca_pem"]=(certificates/"ca.pem").read_text()
        fixture["proxy_ca_sha256"]=hashlib.sha256((certificates/"ca.pem").read_bytes()).hexdigest()
        tls_arguments=f" -tls-cert={certificates}/proxy.pem -tls-key={certificates}/proxy.key"
    state = root / "state"
    state.mkdir(mode=0o700)
    os.chown(state, identity.pw_uid, identity.pw_gid)
    (root / "control.py").write_bytes(Path(__file__).read_bytes())
    (root / "control.py").chmod(0o644)
    base = root.parent
    package = Path(fixture["package"])
    if hashlib.sha256(package.read_bytes()).hexdigest() != fixture["package_sha256"]:
        raise ValueError("qualified package checksum mismatch")
    with tarfile.open(package) as archive:
        for name in ("waf-server", "event-collector"):
            binary = root / name
            binary.write_bytes(archive.extractfile("usr/lib/openwaf/" + name).read())
            binary.chmod(0o755)
            fixture[name + "_sha256"] = hashlib.sha256(binary.read_bytes()).hexdigest()
    for name in ("token", "collector-token"):
        (root / name).write_text(fixture[name])
        (root / name).chmod(0o600)
    original = json.loads((base / "state/policy.json").read_text())
    apps = original["applications"]
    apps[0]["hosts"] = ["dvwa.capacity.test"]
    for app in apps:
        app["traffic_controls"] = dict(requests_per_second=0, burst=0, client_requests_per_second=0,
            client_burst=0, max_concurrent=8, max_client_concurrent=8)
    probe = dict(application_id="probe", name="Controlled capacity backend", hosts=["probe.capacity.test"],
        upstream=f"http://127.0.0.1:{fixture['ports']['backend']}", policy=apps[0]["policy"].copy(),
        traffic_controls=dict(apps[0]["traffic_controls"], max_concurrent=4, max_client_concurrent=4))
    probe["upstream_pool"] = dict(backends=[dict(id="controlled", url=probe["upstream"])],
        failure_threshold=10, cooldown_seconds=2, header_timeout_seconds=1)
    apps.append(probe)
    policy = state / "policy.json"
    policy.write_text(json.dumps(dict(schema_version=2, revision=1, applications=apps)))
    policy.chmod(0o600)
    os.chown(policy, identity.pw_uid, identity.pw_gid)
    fixture["policy"] = json.loads(policy.read_text())
    tag = root.parent.name + "-" + root.name
    fixture["units"] = {name:tag + "-" + name + ".service" for name in ("gateway", "backend", "collector", "monitor")}
    (root / "fixture.json").write_text(json.dumps(fixture))
    (root / "fixture.json").chmod(0o600)
    def unit(name, executable, memory):
        credentials = ""
        if name == "gateway":
            credentials += f"LoadCredential=admin-token:{root}/token\n"
        if name in ("gateway", "collector"):
            credentials += f"LoadCredential=collector-token:{root}/collector-token\n"
        text = ("[Service]\nUser=openwaf\nGroup=openwaf\nNoNewPrivileges=yes\nPrivateTmp=yes\nProtectSystem=strict\n"
                f"ReadWritePaths={state}\nMemoryMax={memory}M\nTasksMax=128\n"
                + credentials +
                f"ExecStart={executable}\n")
        Path("/etc/systemd/system/" + fixture["units"][name]).write_text(text)
    unit("backend", f"/usr/bin/python3 {root}/control.py serve --port {fixture['ports']['backend']}", 128)
    unit("collector", f"{root}/event-collector -listen=127.0.0.1:{fixture['ports']['collector']} -db={state}/collector.db -db-mib=256 -token-file=${{CREDENTIALS_DIRECTORY}}/collector-token", 256)
    unit("gateway", f"{root}/waf-server -config={policy} -event-db={state}/events.db -event-db-mib=256 -event-rows=10000 -event-export-rows=10000 -event-export-url=http://127.0.0.1:{fixture['ports']['collector']}/v1/events -event-export-token-file=${{CREDENTIALS_DIRECTORY}}/collector-token -admin-token-file=${{CREDENTIALS_DIRECTORY}}/admin-token -listen=127.0.0.1:{fixture['ports']['proxy']} -admin=127.0.0.1:{fixture['ports']['admin']} -max-concurrent=32 -max-connections=128 -buffer-mib=64 -body-timeout=5s -request-timeout=15s"+tls_arguments, 512)
    command(["systemctl", "daemon-reload"])
    command(["systemctl", "stop", fixture["base_tag"] + ".service"])
    command(["systemctl", "start", fixture["units"]["backend"], fixture["units"]["collector"], fixture["units"]["gateway"]])
    measurement = {name:int(command(["systemctl", "show", "--property=MainPID", "--value", fixture["units"][name]]))
                   for name in ("gateway", "backend", "collector")}
    measurement["cgroups"] = {}
    measurement["units"] = fixture["units"]
    for name, container in fixture["containers"].items():
        pid = int(command(["docker", "inspect", "--format={{.State.Pid}}", container]))
        if pid:
            group = Path(f"/proc/{pid}/cgroup").read_text().strip().split(":", 2)[2]
            measurement["cgroups"][name] = "/sys/fs/cgroup" + group
    (root / "measurement.json").write_text(json.dumps(measurement))
    unit("monitor", f"/usr/bin/python3 {root}/control.py monitor --root {root}", 64)
    (root / "fixture.json").write_text(json.dumps(fixture))
    (root / "fixture.json").chmod(0o600)
    command(["systemctl", "daemon-reload"])
    command(["systemctl", "start", fixture["units"]["monitor"]])
    return fixture


class BoundedServer(HTTPServer):
    def __init__(self, address, handler):
        super().__init__(address, handler)
        self.slots = threading.BoundedSemaphore(16)
        self.pool = ThreadPoolExecutor(max_workers=16)

    def process_request(self, request, address):
        if not self.slots.acquire(blocking=False):
            request.close()
            return
        def handle():
            try:
                request.settimeout(6)
                self.finish_request(request, address)
            finally:
                self.shutdown_request(request)
                self.slots.release()
        self.pool.submit(handle)


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass

    def do_POST(self):
        self.do_GET()

    def do_GET(self):
        target = urllib.parse.urlsplit(self.path)
        length = int(self.headers.get("Content-Length", "0"))
        if length < 0 or length > 2 << 20:
            self.send_error(413)
            return
        body = self.rfile.read(length)
        delay = min(3000, max(0, int(urllib.parse.parse_qs(target.query).get("delay_ms", ["0"])[0])))
        if delay:
            time.sleep(delay / 1000)
        value = json.dumps(dict(marker="capacity-backend", bytes=len(body), sha256=hashlib.sha256(body).hexdigest())).encode()
        try:
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(value)))
            self.end_headers()
            self.wfile.write(value)
        except (BrokenPipeError, ConnectionResetError):
            pass


def monitor(root):
    spec = json.loads((root / "measurement.json").read_text())
    ticks = os.sysconf("SC_CLK_TCK")
    with (root / "state/resources.jsonl").open("a", buffering=1) as stream:
        for _ in range(6000):
            value = dict(time=time.time(), monotonic=time.monotonic(), processes={}, containers={})
            for name in ("gateway", "backend", "collector"):
                try:
                    if not Path(f"/proc/{spec[name]}/stat").exists():
                        spec[name] = int(command(["systemctl", "show", "--property=MainPID", "--value", spec["units"][name]]))
                    fields = Path(f"/proc/{spec[name]}/stat").read_text().split(")", 1)[1].split()
                    status = dict(line.split(":", 1) for line in Path(f"/proc/{spec[name]}/status").read_text().splitlines() if ":" in line)
                    value["processes"][name] = dict(pid=spec[name], cpu_seconds=(int(fields[11]) + int(fields[12])) / ticks,
                        rss_kib=int(status["VmRSS"].split()[0]), hwm_kib=int(status["VmHWM"].split()[0]))
                except (OSError, KeyError):
                    value["processes"][name] = dict(unavailable=True)
            for name, group in spec["cgroups"].items():
                try:
                    cpu = dict(line.split() for line in (Path(group) / "cpu.stat").read_text().splitlines())
                    value["containers"][name] = dict(cpu_seconds=int(cpu["usage_usec"]) / 1e6,
                        memory_bytes=int((Path(group) / "memory.current").read_text()))
                except OSError:
                    value["containers"][name] = dict(unavailable=True)
            mem = dict(line.split(":", 1) for line in Path("/proc/meminfo").read_text().splitlines())
            value["host_available_kib"] = int(mem["MemAvailable"].split()[0])
            value["host_cpu_ticks"] = [int(n) for n in Path("/proc/stat").read_text().splitlines()[0].split()[1:]]
            stream.write(json.dumps(value) + "\n")
            time.sleep(2)


def reconcile(root):
    with sqlite3.connect(f"file:{root}/state/events.db?mode=ro", uri=True) as sender, sqlite3.connect(f"file:{root}/state/collector.db?mode=ro", uri=True) as receiver:
        local = {json.loads(row[0])["id"]:json.loads(row[0]) for row in sender.execute("SELECT data FROM events")}
        remote = {row[0]:json.loads(row[1]) for row in receiver.execute("SELECT id,data FROM collected_events")}
        same = local.keys() == remote.keys() and all(local[key] == remote[key] for key in local)
        return dict(identical_event_ids_and_payloads=same, local_records=len(local), receiver_records=len(remote),
            receiver_occurrences=sum(max(1, int(value.get("occurrences", 1))) for value in remote.values()),
            receiver_totals=receiver.execute("SELECT records,occurrences FROM collector_totals").fetchone(),
            event_database_bytes=(root / "state/events.db").stat().st_size,
            receiver_database_bytes=(root / "state/collector.db").stat().st_size)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("operation", choices=["setup", "stop", "collector-stop", "collector-start", "backend-stop", "backend-start", "reconcile", "resources", "serve", "monitor"])
    parser.add_argument("--root", type=Path)
    parser.add_argument("--port", type=int)
    args = parser.parse_args()
    if args.operation == "serve":
        BoundedServer(("127.0.0.1", args.port), Handler).serve_forever()
        return
    root = args.root
    if not re.fullmatch(r"/var/lib/owaf-m4-[a-f0-9]{8}/capacity-[a-f0-9]{8}", str(root)):
        raise ValueError("requires owned capacity state")
    if args.operation == "monitor":
        monitor(root)
        return
    if os.getuid() != 0 or command(["systemd-detect-virt", "--vm"]) != "oracle":
        raise ValueError("requires the owned VirtualBox guest")
    if args.operation == "setup":
        result = setup(root, json.load(sys.stdin))
    else:
        fixture = json.loads((root / "fixture.json").read_text())
        if args.operation == "reconcile":
            result = reconcile(root)
        elif args.operation == "resources":
            print((root / "state/resources.jsonl").read_text(), end="")
            return
        elif args.operation == "stop":
            command(["systemctl", "stop", *fixture["units"].values()])
            result = dict(stopped=True)
        else:
            name, operation = args.operation.split("-")
            command(["systemctl", operation, fixture["units"][name]])
            result = dict(completed=True)
    print(json.dumps(result))


if __name__ == "__main__":
    main()
