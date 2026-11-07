"""Qualify verified TLS, persistent HTTP/1 and multiplexed HTTP/2 in the owned lab."""
import argparse
import base64
import hashlib
import http.client
import importlib.util
import json
from pathlib import Path
import socket
import ssl
import subprocess
import time

spec=importlib.util.spec_from_file_location("capacity",Path(__file__).with_name("qualify-capacity.py"))
capacity=importlib.util.module_from_spec(spec)
spec.loader.exec_module(capacity)
REPO=capacity.REPO


class TunnelHTTPSConnection(http.client.HTTPSConnection):
    def connect(self):
        raw=socket.create_connection(("127.0.0.1",self.port),self.timeout)
        try: self.sock=self._context.wrap_socket(raw,server_hostname=self.host)
        except BaseException:
            raw.close()
            raise


class TLSRunner(capacity.Runner):
    def send(self,host,method,path,body,extra=None,direct=None):
        if direct: return super().send(host,method,path,body,extra,direct)
        context=ssl.create_default_context(cadata=self.fixture["proxy_ca_pem"])
        connection=TunnelHTTPSConnection(host,self.fixture["ports"]["proxy"],timeout=20,context=context)
        try:
            connection.request(method,path,body=body,headers={"Host":host,"Content-Type":"application/json","User-Agent":"OpenWAF M4 TLS qualification",**(extra or {})})
            response=connection.getresponse()
            payload=response.read((2<<20)+1)
            if len(payload)>2<<20: raise ValueError("response bound exceeded")
            return response.status,payload
        finally: connection.close()


def case(runner,value):
    host,method,path,body,kind,headers,expected=value
    result=dict(host=host,method=method,path=path,body=base64.b64encode(body).decode() if body is not None else None,
                kind=kind,headers=headers,expected=expected)
    if kind=="wordpress-download": result["response_sha256"]=hashlib.sha256(runner.png).hexdigest()
    return result


def run():
    if not __debug__: raise RuntimeError("qualification requires Python assertions")
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--fixture",type=Path,required=True)
    parser.add_argument("--package",type=Path,required=True)
    parser.add_argument("--generator",type=Path,default=REPO/"artifacts/m4-transportcheck.exe")
    parser.add_argument("--seconds",type=int,choices=[120,300,600],default=120)
    args=parser.parse_args();args.smoke=False;args.max_rate=5
    generator=args.generator.resolve(strict=True)
    if (REPO/"artifacts").resolve() not in generator.parents: raise ValueError("requires an owned generator artifact")
    runner=TLSRunner(args)
    runner.fixture["proxy_tls"]=True
    runner.report.update(experiment="Verified TLS application transports; not a deployment sizing claim",
        profile="Ubuntu 24.04 amd64 1-vCPU/4-GiB colocated lab; private qualification CA; external Windows generator over SSH; PL1; no response inspection",
        generator_binary_sha256=hashlib.sha256(generator.read_bytes()).hexdigest(),transport_phase_seconds=args.seconds)
    sources=["scripts/qualify-transports.py",*[str(p.relative_to(REPO)).replace('\\','/') for p in sorted((REPO/"tools/transportcheck").glob('*.go'))]]
    runner.report["transport_source_sha256"]={name:hashlib.sha256((REPO/name).read_bytes()).hexdigest() for name in sources}
    for name in sources:
        target=runner.out/"source"/name;target.parent.mkdir(parents=True,exist_ok=True);target.write_bytes((REPO/name).read_bytes())
    try:
        runner.start()
        runner.report["qualification_ca_sha256"]=runner.fixture["proxy_ca_sha256"]
        configuration=dict(target="127.0.0.1:"+str(runner.fixture["ports"]["proxy"]),ca=runner.fixture["proxy_ca_pem"],
            seconds=args.seconds,rate=5,cases=[case(runner,runner.case(i)) for i in range(20)],
            large=[case(runner,runner.case(i,"large")) for i in range(4)])
        private=runner.out/"transport.private.json";private.write_text(json.dumps(configuration));private.chmod(0o600)
        output=runner.out/"transport-generator.json"
        with (runner.out/"transport-generator.log").open("w") as log:
            process=subprocess.run([str(generator),"-config",str(private),"-out",str(output)],stdout=log,stderr=subprocess.STDOUT,timeout=args.seconds*3+180)
        measured=json.loads(output.read_text());runner.report["transport"]=measured
        expected_security=3*args.seconds*5//4+9
        for _ in range(90):
            settled=runner.metrics()
            if settled["active_requests"]==0 and settled["security_occurrences_total"]>=expected_security: break
            time.sleep(1)
        else: raise RuntimeError("transport workload or counted security evidence failed to settle")
        values=runner.drain();received=runner.guest("reconcile")
        capacity.validate_delivery(values,received)
        runner.report["transport_native_resources"]=[]
        for phase in measured["phases"]:
            resources=runner.resources(phase["started"],phase["finished"])
            normalized=dict(functional_passed=phase["passed"],planned=phase["planned"],scheduled=phase["planned"],completed=phase["completed"],
                scheduled_latency_ms=dict(p95=phase["p95_ms"]),scheduler_late_over_100ms=phase["scheduler_late_over_100ms"],native_resources=resources)
            runner.report["transport_native_resources"].append(dict(name=phase["name"],resources=resources,operating_budget_passed=capacity.operating_budget(normalized)))
        assert values["requests_total"]==2+measured["http_attempts"],"transport frontend accounting mismatch"
        assert capacity.complete_coverage(runner.samples,measured["started"],measured["finished"]),"transport monitoring coverage incomplete"
        assert all(not row.get("unavailable") and not any(row["metrics"][key] for key in capacity.LOSS) for row in runner.samples)
        assert len({row["metrics"]["start_timestamp_seconds"] for row in runner.samples})==1
        assert max(row["metrics"]["active_requests"] for row in runner.samples)<=32
        assert max(row["metrics"]["reserved_buffer_bytes"] for row in runner.samples)<=64<<20
        runner.report.update(passed=process.returncode==0 and measured["passed"] and all(p["operating_budget_passed"] for p in runner.report["transport_native_resources"]),
            minimum_expected_security_occurrences=expected_security,
            final_metrics=values,reconciliation=received)
    except Exception as error:
        runner.report["failure"]=type(error).__name__+": "+str(error)[:300]
        raise
    finally: runner.close()
    if not runner.report["passed"]: raise SystemExit(1)


if __name__=="__main__": run()
