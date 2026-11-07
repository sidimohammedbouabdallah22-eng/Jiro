"""Bounded, external offered-load qualification of the owned native M4 lab."""

import argparse
import base64
from concurrent.futures import ThreadPoolExecutor
import hashlib
import http.client
import http.cookiejar
import importlib.util
import json
import math
import os
from pathlib import Path
import platform
import queue
import re
import secrets
import shlex
import socket
import subprocess
import threading
import time
import urllib.parse
import urllib.request
import uuid

REPO = Path(__file__).resolve().parents[1]
LOSS = ["event_persistence_errors_total", "event_queue_dropped_total", "event_write_failed_total", "event_ingest_timeouts_total"]
MAX_SAMPLE_GAP_SECONDS = 6


def complete_coverage(rows, begin, end):
    times=sorted(row["time"] for row in rows if begin<=row["time"]<=end)
    return (len(times)>=2 and times[0]<=begin+MAX_SAMPLE_GAP_SECONDS
        and times[-1]>=end-MAX_SAMPLE_GAP_SECONDS
        and all(b-a<=MAX_SAMPLE_GAP_SECONDS for a,b in zip(times,times[1:])))


def operating_budget(result):
    resources=result.get("native_resources",{})
    return (result["functional_passed"] and result["planned"]>0
        and result["scheduled"]==result["completed"]==result["planned"]
        and result["scheduled_latency_ms"]["p95"] is not None
        and 0<=result["scheduled_latency_ms"]["p95"]<=2000
        and result["scheduler_late_over_100ms"]<=result["scheduled"]*.01
        and not resources.get("insufficient_duration")
        and resources.get("processes",{}).get("gateway",{}).get("cpu_percent_of_one_vcpu",101)<=85
        and resources.get("host_busy_percent",101)<=90)


def validate_plan(max_rate, endurance_seconds):
    ordinary=sum(rate*60 for rate in (5,10,25) if rate<=max_rate)+max_rate*(300+30+endurance_seconds)
    # This experiment reconciles every retained event, without history eviction.
    if ordinary//4+128>10000:
        raise ValueError("duration/rate can exceed the 10,000-record evidence history; select a lower maximum rate or shorter duration")


def percentile(values, fraction):
    ordered = sorted(values)
    return round(ordered[min(len(ordered)-1, int((len(ordered)-1)*fraction))], 3) if ordered else None


def validate_delivery(values, received):
    if not received["identical_event_ids_and_payloads"]:
        raise RuntimeError("sender and independent receiver event evidence differs")
    if not (received["receiver_records"]==values["event_export_acked_records_total"]==values["event_export_enqueued_records_total"]==received["receiver_totals"][0]):
        raise RuntimeError("durable export record totals differ")
    if not (received["receiver_occurrences"]==values["event_export_acked_occurrences_total"]==values["event_export_enqueued_occurrences_total"]==values["security_occurrences_total"]==received["receiver_totals"][1]):
        raise RuntimeError("security occurrence totals differ")
    if any(values[key] for key in LOSS) or values["event_export_pending_records"] or values["event_pending_writes"]:
        raise RuntimeError("event delivery contains failures or undrained evidence")
    if values["healthy"]!=1 or values["audit_healthy"]!=1:
        raise RuntimeError("final operational health is degraded")


def admission_boundary(result):
    return (result["capacity_refusals"]>0 and result["non_capacity_unexpected"]==0
        and result["network_errors"]==0 and result["generator_refusals"]==0
        and all(result["after"][key]==result["before"][key] for key in LOSS)
        and result["after"]["overload_requests_total"]>result["before"]["overload_requests_total"])


class Runner:
    def __init__(self, args):
        self.args = args
        private = args.fixture.resolve(strict=True)
        if (REPO / "artifacts").resolve() not in private.parents:
            raise ValueError("requires a private owned M4 fixture")
        self.base = json.loads(private.read_text())
        self.vm = Path(self.base["vm_dir"]).resolve(strict=True)
        if self.vm.parent != (REPO / "artifacts/m2-vms").resolve() or not re.fullmatch(r"openwaf-m2-24\.04-[a-f0-9]{8}", self.vm.name):
            raise ValueError("requires an owned Ubuntu 24.04 VM")
        self.vbox = r"C:\Program Files\Oracle\VirtualBox\VBoxManage.exe"
        info = subprocess.check_output([self.vbox, "showvminfo", self.vm.name, "--machinereadable"], text=True)
        self.was_off = 'VMState="poweroff"' in info
        if 'cpus=1\n' not in info or 'memory=4096\n' not in info:
            raise ValueError("this reference profile requires the recorded 1-vCPU/4-GiB lab")
        port = re.search(r'Forwarding\(0\)="ssh,tcp,127\.0\.0\.1,(\d+),,22"', info)[1]
        self.options = ["-i", str(self.vm / "identity"), "-o", "BatchMode=yes", "-o", "ConnectTimeout=5", "-o", "UserKnownHostsFile="+str(self.vm / "known_hosts")]
        self.ssh = ["ssh", *self.options, "-p", port, "qualifier@127.0.0.1"]
        tag = uuid.uuid4().hex[:8]
        self.out = REPO / "artifacts" / ("m4-capacity-"+tag)
        self.out.mkdir()
        spec = importlib.util.spec_from_file_location("applications", REPO / "scripts/qualify-applications.py")
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        module.restrict_artifacts(self.out)
        sockets = [socket.socket() for _ in range(4)]
        for listener in sockets:
            listener.bind(("127.0.0.1", 0))
        ports = dict(zip(["admin", "proxy", "collector", "backend"], [s.getsockname()[1] for s in sockets]))
        for listener in sockets:
            listener.close()
        self.fixture = dict(root=self.base["root"]+"/capacity-"+tag, base_tag=self.base["tag"], ports=ports,
            token=secrets.token_hex(32), **{"collector-token":secrets.token_hex(32)}, containers=self.base["containers"],
            package="/tmp/openwaf-m3-20261104-r7-linux-amd64.tar.gz", package_sha256=self.base["package_sha256"])
        self.package = getattr(args,"package",None) or REPO/"artifacts/openwaf-m3-20261104-r7-linux-amd64.tar.gz"
        self.package = Path(self.package).resolve(strict=True)
        package_digest=hashlib.sha256(self.package.read_bytes()).hexdigest()
        if package_digest!=Path(str(self.package)+".sha256").read_text().split()[0]:
            raise ValueError("candidate package checksum mismatch")
        self.fixture.update(package="/tmp/"+self.package.name,package_sha256=package_digest)
        self.log = (self.out / "commands.log").open("a", encoding="utf-8")
        self.tunnel = None
        self.prepared = False
        self.setup_attempted = False
        self.base_started = False
        self.samples = []
        self.scheduled_budget = 0
        self.stop_sampling = threading.Event()
        self.report = dict(passed=False, deployment_capacity_gate="open: business workload/SLO/headroom are unspecified",
            maximum_screen_rate=args.max_rate,
            profile="Ubuntu 24.04 amd64; 1 vCPU/4GiB shared with pinned products; loopback HTTP over SSH; PL1 enforcement; no response inspection",
            applications=self.base["images"], phases=[], checks=[], package_sha256=self.fixture["package_sha256"],
            started=time.time(), screening_limits=dict(max_p95_ms=2000, max_gateway_cpu_percent=85, max_host_busy_percent=90, max_generator_late_fraction=.01),
            limits=dict(max_requests=100000, max_monitoring_samples=6000, max_sample_gap_seconds=MAX_SAMPLE_GAP_SECONDS, workers=16, queue=32, response_bytes=2<<20, client_timeout_seconds=20,
                gateway_request_timeout_seconds=15,body_read_timeout_seconds=5,probe_header_timeout_seconds=1,
                global_concurrent=32,connections=128,buffer_mib=64,event_database_mib=256,receiver_database_mib=256),
            source_sha256={name:hashlib.sha256((REPO/name).read_bytes()).hexdigest() for name in ["scripts/qualify-capacity.py", "scripts/m4_capacity_guest.py"]})
        for name in self.report["source_sha256"]:
            snapshot=self.out/"source"/name
            snapshot.parent.mkdir(parents=True,exist_ok=True)
            snapshot.write_bytes((REPO/name).read_bytes())

    def execute(self, args, data=None, check=True, timeout=300):
        result = subprocess.run([str(a) for a in args], input=data, capture_output=True, text=True, timeout=timeout)
        if result.stderr:
            self.log.write(result.stderr)
            self.log.flush()
        if check and result.returncode:
            raise RuntimeError("owned lab command failed; inspect private commands.log")
        return result.stdout

    def guest(self, operation):
        return json.loads(self.execute([*self.ssh, shlex.join(["sudo", "python3", self.fixture["root"]+"/control.py", operation, "--root", self.fixture["root"]])]))

    def save(self):
        temporary = self.out / "results.next"
        temporary.write_text(json.dumps(self.report, indent=2)+"\n")
        temporary.replace(self.out / "results.json")

    def api(self, endpoint):
        connection = http.client.HTTPConnection("127.0.0.1", self.fixture["ports"]["admin"], timeout=3)
        try:
            connection.request("GET", "/api/v1/"+endpoint, headers={"Authorization":"Bearer "+self.fixture["token"]})
            response = connection.getresponse()
            data = response.read(1<<20)
            if response.status != 200:
                raise RuntimeError("management read failed")
            return data
        finally:
            connection.close()

    def metrics(self):
        values = {}
        for line in self.api("metrics").decode().splitlines():
            fields = line.split()
            if len(fields)==2 and fields[0].startswith("openwaf_"):
                value = float(fields[1])
                if not math.isfinite(value):
                    raise ValueError("invalid metric")
                values[fields[0][8:]] = value
        return values

    def sample(self):
        while not self.stop_sampling.is_set():
            try:
                self.samples.append(dict(time=time.time(), metrics=self.metrics()))
            except Exception:
                self.samples.append(dict(time=time.time(), unavailable=True))
            with (self.out/"metrics-live.jsonl").open("a") as stream:
                stream.write(json.dumps(self.samples[-1])+"\n")
            if len(self.samples)>=6000:
                self.stop_sampling.set()
            self.stop_sampling.wait(2)

    def start(self):
        if self.was_off:
            self.execute([self.vbox, "startvm", self.vm.name, "--type", "headless"])
        deadline=time.monotonic()+120
        while time.monotonic()<deadline:
            if subprocess.run([*self.ssh,"true"],capture_output=True,timeout=8).returncode==0:
                break
            time.sleep(1)
        else:
            raise RuntimeError("guest boot deadline")
        self.base_started = True
        self.execute([*self.ssh, shlex.join(["sudo", "python3", self.base["root"]+"/guest.py", "start", "--root", self.base["root"]])])
        package=self.package
        if hashlib.sha256(package.read_bytes()).hexdigest()!=self.fixture["package_sha256"]:
            raise ValueError("local qualified archive checksum mismatch")
        self.execute(["scp", *self.options, "-P", self.ssh[self.ssh.index("-p")+1], REPO/"scripts/m4_capacity_guest.py", package, "qualifier@127.0.0.1:/tmp/"])
        remote = shlex.join(["sudo", "python3", "/tmp/m4_capacity_guest.py", "setup", "--root", self.fixture["root"]])
        self.setup_attempted = True
        self.fixture = json.loads(self.execute([*self.ssh, remote], json.dumps(self.fixture)))
        self.prepared = True
        (self.out/"fixture.private.json").write_text(json.dumps(self.fixture, indent=2))
        self.report.update(server_sha256=self.fixture["waf-server_sha256"], collector_sha256=self.fixture["event-collector_sha256"], policy=self.fixture["policy"],
            native_environment=self.fixture.get("environment"),generator_environment=dict(os=platform.platform(),logical_cpus=os.cpu_count(),cpu=platform.processor()),
            audit_export_scope="local durable audit health checked; independent audit export qualification remains the existing M3 profile")
        forwards = []
        for port in [*self.fixture["ports"].values(), self.base["ports"]["dvwa"], self.base["ports"]["wordpress"]]:
            forwards += ["-L", f"127.0.0.1:{port}:127.0.0.1:{port}"]
        self.tunnel = subprocess.Popen([*self.ssh[:-1], "-N", "-o", "ExitOnForwardFailure=yes", *forwards, self.ssh[-1]], stdout=self.log, stderr=self.log)
        for _ in range(60):
            try:
                if json.loads(self.api("health"))["healthy"]:
                    break
            except (OSError, ValueError):
                pass
            time.sleep(.5)
        else:
            raise RuntimeError("gateway readiness deadline")
        self.sampler = threading.Thread(target=self.sample, daemon=True)
        self.sampler.start()
        self.prepare_workflows()
        self.save()
        print("Capacity evidence: "+str(self.out), flush=True)

    def prepare_workflows(self):
        jar = http.cookiejar.CookieJar()
        opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), urllib.request.HTTPCookieProcessor(jar))
        direct = "http://127.0.0.1:"+str(self.base["ports"]["dvwa"])
        page = opener.open(direct+"/login.php", timeout=7).read().decode()
        token = re.search(r"name=['\"]user_token['\"]\s+value=['\"]([^'\"]+)", page)[1]
        body = urllib.parse.urlencode(dict(username="admin", password="password", Login="Login", user_token=token)).encode()
        result = opener.open(direct+"/login.php", data=body, timeout=7).read()
        assert b"Welcome to Damn Vulnerable Web Application" in result
        self.cookie = "; ".join(c.name+"="+c.value for c in jar if c.name!="security")+"; security=low"
        self.auth = "Basic "+base64.b64encode(("site-admin:"+self.base["wordpress_app_password"]).encode()).decode()
        self.png = base64.b64decode("iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mP8/x8AAwMCAO+a1ZkAAAAASUVORK5CYII=")
        self.bodies = {}
        for size in (64<<10, 256<<10, 900<<10, (1<<20)+1):
            prefix, suffix = b'{"payload":"', b'"}'
            payload = prefix+b"a"*(size-len(prefix)-len(suffix))+suffix
            self.bodies[size] = payload
        status, raw = self.send("localhost", "POST", "/wp-json/wp/v2/posts", json.dumps(dict(title="Capacity fixture", content="<p>Reviewed invoice.</p>", status="publish")).encode(), extra={"Authorization":self.auth})
        assert status==201, "WordPress fixture publish failed"
        self.post = json.loads(raw)["id"]
        upload = self.upload_case()
        status, raw = self.send(*upload[:4], extra=upload[5])
        assert status==201
        self.media_path = urllib.parse.urlsplit(json.loads(raw)["source_url"]).path
        target = "/vulnerabilities/sqli/?"+urllib.parse.urlencode(dict(id="1' OR '1'='1' -- ", Submit="Submit"))
        connection = http.client.HTTPConnection("127.0.0.1", self.base["ports"]["dvwa"], timeout=7)
        connection.request("GET", target, headers={"Cookie":self.cookie})
        baseline = connection.getresponse().read()
        connection.close()
        assert baseline.count(b"First name:")>1
        self.report["direct_attack_baseline"] = dict(sql_injection_multiple_rows=True)
        connection = http.client.HTTPConnection("127.0.0.1", self.base["ports"]["dvwa"], timeout=7)
        connection.request("GET", "/vulnerabilities/xss_r/?name=%3Cscript%3Ealert(1)%3C/script%3E", headers={"Cookie":self.cookie})
        assert b"<script>alert(1)</script>" in connection.getresponse().read()
        connection.close()
        self.report["direct_attack_baseline"]["reflected_xss_markup"] = True

    def upload_case(self):
        boundary = "OpenWAF-capacity-boundary"
        body = ("--"+boundary+'\r\nContent-Disposition: form-data; name="file"; filename="capacity.png"\r\nContent-Type: image/png\r\n\r\n').encode()+self.png+("\r\n--"+boundary+"--\r\n").encode()
        return ("localhost", "POST", "/wp-json/wp/v2/media", body, "upload", {"Authorization":self.auth,"Content-Type":"multipart/form-data; boundary="+boundary}, 201)

    def case(self, sequence, profile="mixed"):
        extra = {}
        if profile=="direct":
            sequence %= 15
        if profile in ("large", "large-direct"):
            sizes=[64<<10,256<<10,900<<10] if profile=="large-direct" else [64<<10,256<<10,900<<10,(1<<20)+1]
            size = sizes[sequence%len(sizes)]
            return ("probe.capacity.test","POST","/echo",self.bodies[size],"body-"+str(size),extra,413 if size>1<<20 else 200)
        n = sequence%20
        if n<6:
            return ("localhost","GET","/wp-json/wp/v2/posts",None,"wordpress-read",extra,200)
        if n==6:
            return ("localhost","GET","/wp-json/wp/v2/posts?search=O%27Reilly%20caf%C3%A9",None,"wordpress-search",extra,200)
        if n==7:
            return ("localhost","POST","/wp-json/wp/v2/posts/"+str(self.post),b'{"title":"Capacity reviewed invoice","content":"<p>Approved customer quotation.</p>"}',"wordpress-edit",{"Authorization":self.auth},200)
        if n==8:
            return self.upload_case()
        if n==9:
            return ("localhost","GET",self.media_path,None,"wordpress-download",extra,200)
        if n<14:
            return ("dvwa.capacity.test","GET","/vulnerabilities/sqli/?id=1&Submit=Submit",None,"dvwa-lookup",{"Cookie":self.cookie},200)
        if n==14:
            return ("probe.capacity.test","POST","/echo",self.bodies[64<<10],"json-64k",extra,200)
        target = "/vulnerabilities/sqli/?"+urllib.parse.urlencode(dict(id="1' OR '1'='1' -- ", Submit="Submit")) if n%2 else "/vulnerabilities/xss_r/?"+urllib.parse.urlencode(dict(name="<script>alert(1)</script>"))
        return ("dvwa.capacity.test","GET",target,None,"attack-sqli" if n%2 else "attack-xss",{"Cookie":self.cookie},403)

    def send(self, host, method, path, body, extra=None, direct=None):
        connection = http.client.HTTPConnection("127.0.0.1", direct or self.fixture["ports"]["proxy"], timeout=20)
        try:
            connection.request(method,path,body=body,headers={"Host":host,"Content-Type":"application/json","User-Agent":"OpenWAF M4 capacity",**(extra or {})})
            response = connection.getresponse()
            payload = response.read((2<<20)+1)
            if len(payload)>2<<20:
                raise ValueError("response bound exceeded")
            return response.status,payload
        finally:
            connection.close()

    def perform(self, case, direct=None):
        host, method, path, body, name, extra, expected = case
        status, raw = self.send(host, method, path, body, extra, direct)
        correct = status==expected
        if correct and status in (200,201):
            if host=="probe.capacity.test":
                result = json.loads(raw)
                correct = result["marker"]=="capacity-backend" and result["bytes"]==len(body or b"") and result["sha256"]==hashlib.sha256(body or b"").hexdigest()
            elif name=="dvwa-lookup":
                correct = b"First name: admin" in raw
            elif name=="wordpress-download":
                correct = raw==self.png
            elif name=="wordpress-edit":
                correct = json.loads(raw)["title"]["raw"]=="Capacity reviewed invoice"
            elif name=="upload":
                correct = json.loads(raw)["media_type"]=="image"
            else:
                correct = isinstance(json.loads(raw),list)
        return status,correct

    def phase(self, name, rate, seconds, profile="mixed", direct=False, outage=False):
        total = int(rate*seconds)
        self.scheduled_budget += total
        if self.scheduled_budget>100000:
            raise RuntimeError("total scheduled-request budget exceeded")
        tasks = queue.Queue(maxsize=32)
        results, errors = [], []
        lock = threading.Lock()
        start = time.monotonic()
        cpu_started = time.process_time()
        wall = time.time()
        before = self.metrics()
        abort = threading.Event()
        def worker():
            while True:
                job = tasks.get()
                if job is None:
                    tasks.task_done()
                    return
                sequence,due = job
                began = time.monotonic()
                case = self.case(sequence,profile)
                try:
                    port = None
                    if direct:
                        port = self.fixture["ports"]["backend"] if case[0]=="probe.capacity.test" else self.base["ports"]["wordpress"] if case[0]=="localhost" else self.base["ports"]["dvwa"]
                    status,correct = self.perform(case,port)
                    with lock:
                        results.append((status,correct,(time.monotonic()-due)*1000,(time.monotonic()-began)*1000,case[4],(began-due)*1000))
                    if not correct:
                        abort.set()
                except Exception as error:
                    with lock:
                        errors.append(type(error).__name__)
                    abort.set()
                finally:
                    tasks.task_done()
        threads = [threading.Thread(target=worker,daemon=True) for _ in range(16)]
        for thread in threads:
            thread.start()
        dropped,late = 0,0
        next_progress = start+15
        if outage:
            self.guest("collector-stop")
            start = time.monotonic()
            wall=time.time()
        scheduled=0
        for sequence in range(total):
            if abort.is_set():
                break
            due = start+sequence/rate
            pause = due-time.monotonic()
            if pause>0:
                time.sleep(pause)
            if time.monotonic()-due>.1:
                late+=1
            try:
                tasks.put_nowait((sequence,due))
            except queue.Full:
                dropped+=1
                abort.set()
            scheduled+=1
            if time.monotonic()>next_progress:
                print(f"{name}: scheduled {sequence+1}/{total}, completed {len(results)}, generator refusals {dropped}",flush=True)
                next_progress=time.monotonic()+15
        tasks.join()
        for _ in threads:
            tasks.put(None)
        for thread in threads:
            thread.join(timeout=10)
        during = self.metrics()
        if outage:
            self.guest("collector-start")
        statuses = {str(status):sum(row[0]==status for row in results) for status in {row[0] for row in results}}
        result = dict(name=name,rate=rate,requested_seconds=seconds,started=wall,finished=time.time(),
            planned=total,scheduled=scheduled,completed=len(results),generator_refusals=dropped,scheduler_late_over_100ms=late,
            generator_cpu_seconds=time.process_time()-cpu_started,
            elapsed_seconds=time.monotonic()-start,completed_per_second=len(results)/(time.monotonic()-start),
            network_errors=len(errors),error_types=sorted(set(errors)),unexpected=sum(not row[1] for row in results),statuses=statuses,
            capacity_refusals=sum(not row[1] and row[0]==503 for row in results),non_capacity_unexpected=sum(not row[1] and row[0]!=503 for row in results),
            scheduled_latency_ms={"p50":percentile([r[2] for r in results],.5),"p95":percentile([r[2] for r in results],.95),"p99":percentile([r[2] for r in results],.99),"max":max((r[2] for r in results),default=0)},
            service_latency_ms={"p50":percentile([r[3] for r in results],.5),"p95":percentile([r[3] for r in results],.95),"p99":percentile([r[3] for r in results],.99)},
            workflows={key:dict(completed=sum(r[4]==key for r in results),unexpected=sum(r[4]==key and not r[1] for r in results),
                statuses={str(status):sum(r[4]==key and r[0]==status for r in results) for status in {r[0] for r in results if r[4]==key}},
                scheduled_p95_ms=percentile([r[2] for r in results if r[4]==key],.95),service_p95_ms=percentile([r[3] for r in results if r[4]==key],.95)) for key in {r[4] for r in results}},
            before=before,after=during)
        result["functional_passed"] = not (dropped or errors or result["unexpected"] or any(during[k]!=before[k] for k in LOSS))
        self.report["phases"].append(result)
        try:
            result["native_resources"] = self.resources(wall,result["finished"])
        except RuntimeError:
            if not result["functional_passed"] and result["elapsed_seconds"]<4:
                result["native_resources"] = dict(insufficient_duration=True,samples=0)
            else:
                self.save()
                raise
        self.save()
        print(name+": "+str(result["functional_passed"])+", p95 "+str(result["scheduled_latency_ms"]["p95"])+" ms",flush=True)
        return result

    def resources(self, begin, end):
        raw=self.execute([*self.ssh,shlex.join(["sudo","python3",self.fixture["root"]+"/control.py","resources","--root",self.fixture["root"]])])
        rows=[]
        for line in raw.splitlines():
            try:
                value=json.loads(line)
                if begin<=value["time"]<=end:
                    rows.append(value)
            except ValueError:
                continue
        if not complete_coverage(rows,begin,end) or any(row["processes"]["gateway"].get("unavailable") for row in rows):
            raise RuntimeError("native process measurement coverage missing")
        span=rows[-1]["monotonic"]-rows[0]["monotonic"]
        processes={}
        for name in ("gateway","backend","collector"):
            valid=[row["processes"][name] for row in rows if not row["processes"][name].get("unavailable")]
            cpu=sum(max(0,b["cpu_seconds"]-a["cpu_seconds"]) for a,b in zip(valid,valid[1:]) if a.get("pid")==b.get("pid"))
            processes[name]=dict(cpu_percent_of_one_vcpu=round(100*cpu/span,2),
                peak_rss_kib=max((row["rss_kib"] for row in valid),default=0),lifetime_hwm_kib=max((row["hwm_kib"] for row in valid),default=0),
                unavailable_samples=len(rows)-len(valid),observed_pids=len({row.get("pid") for row in valid}))
        result=dict(samples=len(rows),interval_seconds=span,
            processes=processes,
            min_host_available_kib=min(row["host_available_kib"] for row in rows),
            containers={name:dict(cpu_percent_of_one_vcpu=round(100*(rows[-1]["containers"][name]["cpu_seconds"]-rows[0]["containers"][name]["cpu_seconds"])/span,2),
                peak_memory_bytes=max(row["containers"][name]["memory_bytes"] for row in rows)) for name in rows[0]["containers"]})
        first,last=rows[0]["host_cpu_ticks"],rows[-1]["host_cpu_ticks"]
        total=sum(last[:8])-sum(first[:8])
        result["host_busy_percent"]=round(100*(1-((last[3]+last[4])-(first[3]+first[4]))/total),2)
        return result

    def check(self,name,operation):
        try:
            detail=operation()
            self.report["checks"].append(dict(name=name,passed=True,detail=detail))
        except Exception as error:
            self.report["checks"].append(dict(name=name,passed=False,error=type(error).__name__+": "+str(error)[:300]))
            self.save()
            raise
        self.save()

    def faults(self):
        slow=("probe.capacity.test","GET","/slow?delay_ms=300",None,"slow",{},200)
        assert self.perform(slow)[1]
        timeout=(*slow[:2],"/slow?delay_ms=3000",*slow[3:6],502)
        begin=time.monotonic()
        assert self.perform(timeout)[1]
        assert time.monotonic()-begin<2.5
        self.guest("backend-stop")
        try:
            assert self.perform(("probe.capacity.test","GET","/echo",None,"unavailable",{},502))[1]
        finally:
            self.guest("backend-start")
        time.sleep(3)
        assert self.perform(("probe.capacity.test","GET","/echo",None,"recovered",{},200))[1]
        return dict(header_deadline_bounded=True,unavailable_rejected=True,recovery=True)

    def body_verdicts(self):
        rows=[]
        self.report["body_verdicts"]=rows
        for index in range(4):
            case=self.case(index,"large")
            started=time.monotonic()
            status,correct=self.perform(case)
            rows.append(dict(bytes=len(case[3]),status=status,expected=case[-1],correct=correct,milliseconds=round((time.monotonic()-started)*1000,3)))
            assert correct, "large body returned an unexpected status or payload: "+str(rows[-1])
        return rows

    def fairness(self):
        before=self.metrics()
        barrier=threading.Barrier(52)
        def invoke(index):
            barrier.wait(timeout=10)
            if index<48:
                return "probe",self.send("probe.capacity.test","GET","/slow?delay_ms=700",None)[0]
            case=self.case(0)
            status,correct=self.perform(case)
            return "wordpress",status if correct else -1
        with ThreadPoolExecutor(max_workers=52) as pool:
            rows=list(pool.map(invoke,range(52)))
        assert all(status==200 for app,status in rows if app=="wordpress")
        assert any(status==503 for app,status in rows if app=="probe")
        assert all(status in (200,503) for app,status in rows if app=="probe")
        after=self.metrics()
        assert after["fairness_rejections_total"]>before["fairness_rejections_total"]
        return {app:{str(status):sum(a==app and s==status for a,s in rows) for status in {s for a,s in rows if a==app}} for app in ("probe","wordpress")}

    def drain(self):
        for _ in range(90):
            values=self.metrics()
            if values["event_export_pending_records"]==0 and values["event_pending_writes"]==0:
                time.sleep(1.2)
                values=self.metrics()
                if values["event_export_pending_records"]==0 and values["event_pending_writes"]==0:
                    return values
            time.sleep(1)
        raise RuntimeError("export drain deadline")

    def run(self):
        self.report["endurance_requested_seconds"]=15 if self.args.smoke else getattr(self.args,"endurance_seconds",600)
        self.start()
        # Direct benign/application baselines are separated from inspected verdicts.
        self.phase("direct-benign",5,20 if self.args.smoke else 60,profile="direct",direct=True)
        self.phase("inspected-benign",5,12 if self.args.smoke else 60,profile="direct")
        self.phase("direct-large",2,12 if self.args.smoke else 60,profile="large-direct",direct=True)
        self.check("large-body-verdicts",self.body_verdicts)
        self.check("slow-unavailable-recovery",self.faults)
        self.check("concurrent-admission-fairness",self.fairness)
        self.phase("large-bodies",.25,16 if self.args.smoke else 120,"large")
        chosen=0
        for rate in (5,10,25):
            if rate>self.args.max_rate:
                break
            result=self.phase("screen-"+str(rate),rate,12 if self.args.smoke else 60)
            result["screening_passed"] = operating_budget(result)
            result["observed_admission_boundary"] = admission_boundary(result)
            if not result["screening_passed"]:
                break
            chosen=rate
        if not chosen:
            raise RuntimeError("no healthy screening point")
        self.report["selected_lab_rate"]=chosen
        steady=self.phase("steady",chosen,15 if self.args.smoke else 300)
        steady["operating_budget_passed"]=operating_budget(steady)
        if not steady["operating_budget_passed"]:
            raise RuntimeError("steady workload exceeded its declared operating budget")
        self.phase("collector-outage",chosen,12 if self.args.smoke else 30,outage=True)
        self.drain()
        endurance=self.phase("combined-endurance",chosen,self.report["endurance_requested_seconds"])
        endurance["operating_budget_passed"]=operating_budget(endurance)
        if not endurance["operating_budget_passed"]:
            raise RuntimeError("endurance workload exceeded its declared operating budget")
        values=self.drain()
        received=self.guest("reconcile")
        validate_delivery(values,received)
        monitoring_ok=(complete_coverage(self.samples,self.report["phases"][0]["started"],self.report["phases"][-1]["finished"])
            and not any(row.get("unavailable") or any(row.get("metrics",{}).get(key,0) for key in LOSS) for row in self.samples))
        starts={row["metrics"]["start_timestamp_seconds"] for row in self.samples if "metrics" in row}
        assert len(starts)==1, "unexpected gateway lifecycle reset during measurement"
        self.report.update(reconciliation=received,final_metrics=values,smoke=self.args.smoke,
            monitoring_coverage_passed=monitoring_ok,
            passed=monitoring_ok and all(p["functional_passed"] or (p["name"].startswith("screen-") and p.get("observed_admission_boundary")) for p in self.report["phases"]) and all(c["passed"] for c in self.report["checks"]))

    def close(self):
        self.stop_sampling.set()
        if hasattr(self,"sampler"):
            self.sampler.join(timeout=5)
        if self.prepared:
            raw=self.execute([*self.ssh,shlex.join(["sudo","python3",self.fixture["root"]+"/control.py","resources","--root",self.fixture["root"]])],check=False)
            (self.out/"resources.jsonl").write_text(raw)
            self.guest("stop")
        elif self.setup_attempted:
            self.execute([*self.ssh,shlex.join(["sudo","python3","/tmp/m4_capacity_guest.py","stop","--root",self.fixture["root"]])],check=False)
        if self.base_started:
            self.execute([*self.ssh,shlex.join(["sudo","python3",self.base["root"]+"/guest.py","stop","--root",self.base["root"]])],check=False)
        if self.tunnel:
            self.tunnel.terminate()
            self.tunnel.wait(timeout=15)
        if self.was_off:
            self.execute([self.vbox,"controlvm",self.vm.name,"acpipowerbutton"],check=False)
        self.report["metrics_samples"]=self.samples
        self.report["finished"]=time.time()
        self.save()
        self.log.close()


def main():
    if not __debug__:
        raise RuntimeError("qualification must run with Python assertions enabled")
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--fixture",type=Path,required=True)
    parser.add_argument("--package",type=Path,help="Explicit checksummed candidate archive; defaults to the qualified M3 reference")
    parser.add_argument("--smoke",action="store_true",help="Short tool verification, never capacity evidence")
    parser.add_argument("--max-rate",type=int,choices=[5,10,25],default=25,help="Maximum ordinary screening rate; retain higher-rate failures separately")
    parser.add_argument("--endurance-seconds",type=int,choices=[600,1800,3600,7200],default=600,help="Combined workload duration; longer runs must fit the retained-event evidence budget")
    args=parser.parse_args()
    if args.smoke and args.endurance_seconds!=600:
        parser.error("smoke schedules cannot advertise a longer endurance qualification")
    try: validate_plan(args.max_rate,args.endurance_seconds)
    except ValueError as error: parser.error(str(error))
    runner=Runner(args)
    try:
        runner.run()
    except Exception as error:
        runner.report["failure"]=type(error).__name__+": "+str(error)[:300]
        raise
    finally:
        runner.close()
    if not runner.report["passed"]:
        raise SystemExit(1)


if __name__=="__main__":
    main()
