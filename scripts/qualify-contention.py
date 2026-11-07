"""Measure CPU-heavy cross-application contention in the owned M4 lab."""

import argparse
import importlib.util
import json
from pathlib import Path
import queue
import threading
import time
import http.client
import hashlib

spec=importlib.util.spec_from_file_location("capacity",Path(__file__).with_name("qualify-capacity.py"))
capacity=importlib.util.module_from_spec(spec)
spec.loader.exec_module(capacity)


def quiesce(runner):
    for _ in range(90):
        if runner.metrics()["active_requests"]==0:
            return runner.drain()
        time.sleep(1)
    raise RuntimeError("inspection did not quiesce within its test budget")


def measure(runner,name,seconds,body=None):
    start=time.monotonic()
    wall=time.time()
    before=runner.metrics()
    stop=threading.Event()
    lock=threading.Lock()
    jobs=queue.Queue(maxsize=8)
    legitimate=[]
    heavy=[]
    failures=[]
    def worker():
        while True:
            due=jobs.get()
            if due is None:
                jobs.task_done()
                return
            began=time.monotonic()
            try:
                status,correct=runner.perform(runner.case(0))
                with lock: legitimate.append(dict(status=status,correct=correct,scheduled_ms=(time.monotonic()-due)*1000,service_ms=(time.monotonic()-began)*1000))
                if not correct: stop.set()
            except Exception as error:
                with lock: failures.append(type(error).__name__)
                stop.set()
            finally:
                jobs.task_done()
    def burner():
        while not stop.is_set() and time.monotonic()<start+seconds:
            began=time.monotonic()
            try:
                status,correct=runner.perform(("probe.capacity.test","POST","/echo",body,"cpu-heavy",{},200))
                with lock: heavy.append(dict(status=status,correct=correct,ms=(time.monotonic()-began)*1000))
            except Exception as error:
                with lock: heavy.append(dict(error=type(error).__name__,ms=(time.monotonic()-began)*1000))
            stop.wait(max(0,1-(time.monotonic()-began)))
    workers=[threading.Thread(target=worker,daemon=True) for _ in range(4)]
    burners=[threading.Thread(target=burner,daemon=True) for _ in range(4)] if body is not None else []
    for thread in workers+burners: thread.start()
    refused=late=scheduled=0
    for index in range(seconds*2):
        if stop.is_set(): break
        due=start+index/2
        time.sleep(max(0,due-time.monotonic()))
        late+=time.monotonic()-due>.1
        try: jobs.put_nowait(due)
        except queue.Full:
            refused+=1
            stop.set()
        scheduled+=1
        if index and index%30==0:
            print(f"{name}: legitimate {len(legitimate)}/{seconds*2}; heavy attempts {len(heavy)}",flush=True)
    jobs.join()
    for _ in workers: jobs.put(None)
    for thread in workers: thread.join(timeout=25)
    stop.set()
    for thread in burners: thread.join(timeout=25)
    after=quiesce(runner)
    elapsed=time.monotonic()-start
    p95=capacity.percentile([row["scheduled_ms"] for row in legitimate],.95)
    heavy_invalid=sum("status" in row and (row["status"] not in (200,503) or (row["status"]==200 and not row["correct"])) for row in heavy)
    passed=scheduled==seconds*2 and not refused and not late and not failures and not heavy_invalid and all(row["correct"] for row in legitimate) and p95 is not None and p95<=2000
    result=dict(name=name,requested_seconds=seconds,seconds=elapsed,legitimate_rate=2,scheduled=scheduled,completed=len(legitimate),
        passed=passed,unexpected=sum(not row["correct"] for row in legitimate),network_errors=len(failures),error_types=sorted(set(failures)),
        generator_refusals=refused,scheduler_late_over_100ms=late,p50_ms=capacity.percentile([row["scheduled_ms"] for row in legitimate],.5),
        p95_ms=p95,p99_ms=capacity.percentile([row["scheduled_ms"] for row in legitimate],.99),
        heavy_workers=len(burners),heavy_body_bytes=len(body or b""),heavy_attempts=len(heavy),
        heavy_statuses={str(status):sum(row.get("status")==status for row in heavy) for status in {row["status"] for row in heavy if "status" in row}},
        heavy_network_errors=sum("error" in row for row in heavy),heavy_error_types=sorted({row["error"] for row in heavy if "error" in row}),
        heavy_invalid_responses=heavy_invalid,
        before=before,after=after,native_resources=runner.resources(wall,time.time()),
        backend_status=json.loads(runner.api("upstreams")))
    assert not any(after[key]!=before[key] for key in capacity.LOSS), "evidence persistence failure under contention"
    assert after["active_requests"]==0
    runner.report["contention"].append(result)
    runner.save()
    print(f"{name}: passed={passed}; legitimate p95={p95} ms; heavy={result['heavy_statuses']}",flush=True)
    return result


def bound_probe(runner):
    config=json.loads(runner.api("config"))
    probe=next(app for app in config["applications"] if app["application_id"]=="probe")
    probe["traffic_controls"].update(max_concurrent=1,max_client_concurrent=1)
    connection=http.client.HTTPConnection("127.0.0.1",runner.fixture["ports"]["admin"],timeout=10)
    try:
        connection.request("POST","/api/v1/config/apply",body=json.dumps(dict(config=config,reason="Bound CPU-heavy application concurrency for the contention qualification profile")),
            headers={"Authorization":"Bearer "+runner.fixture["token"],"Content-Type":"application/json"})
        response=connection.getresponse()
        data=response.read(1<<20)
        if response.status!=200: raise RuntimeError("contention policy activation failed")
        runner.report["bounded_policy"]=json.loads(data)
    finally: connection.close()


def run():
    if not __debug__:
        raise RuntimeError("qualification must run with Python assertions enabled")
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--fixture",type=Path,required=True)
    parser.add_argument("--package",type=Path,required=True)
    parser.add_argument("--seconds",type=int,default=60)
    args=parser.parse_args()
    if args.seconds<30 or args.seconds>180: parser.error("phase duration must be 30..180 seconds")
    args.smoke=False
    args.max_rate=5
    runner=capacity.Runner(args)
    runner.report.update(experiment="CPU contention, not a general capacity qualification",contention=[],heavy_response_integrity_gate=True,
        legitimate_budget=dict(rate=2,p95_ms=2000,unexpected=0),
        qualified_profile=dict(probe_max_concurrent=1,heavy_workers=4,heavy_body="900-KiB JSON with non-ASCII sentinel"),
        driver_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest())
    (runner.out/"source/scripts/qualify-contention.py").write_bytes(Path(__file__).read_bytes())
    try:
        runner.start()
        ascii_body=runner.bodies[900<<10]
        value="a"*((900<<10)-16)+"é"
        unicode_body=json.dumps(dict(payload=value),ensure_ascii=False,separators=(",",":")).encode()
        assert len(unicode_body)==900<<10
        baseline=measure(runner,"uncontended",args.seconds)
        measure(runner,"ASCII-four-slots",args.seconds,ascii_body)
        measure(runner,"Unicode-four-slots",args.seconds,unicode_body)
        bound_probe(runner)
        bounded=measure(runner,"Unicode-one-slot",args.seconds,unicode_body)
        values=quiesce(runner)
        received=runner.guest("reconcile")
        capacity.validate_delivery(values,received)
        expected=2+sum(row["completed"]+row["network_errors"]+row["heavy_attempts"] for row in runner.report["contention"])
        assert values["requests_total"]==expected, "front-end request accounting mismatch"
        assert all(not row.get("unavailable") and not any(row["metrics"][key] for key in capacity.LOSS) for row in runner.samples)
        assert max(row["metrics"]["active_requests"] for row in runner.samples)<=32
        assert max(row["metrics"]["reserved_buffer_bytes"] for row in runner.samples)<=64<<20
        bounded_uploads=bounded["heavy_statuses"].get("200",0)>0 and bounded["heavy_network_errors"]==0 and bounded["heavy_invalid_responses"]==0
        runner.report.update(passed=baseline["passed"] and bounded["passed"] and bounded_uploads,final_metrics=values,reconciliation=received,
            observed_four_slot_limits=[row["name"] for row in runner.report["contention"] if not row["passed"]])
    except Exception as error:
        runner.report["failure"]=type(error).__name__+": "+str(error)[:300]
        raise
    finally: runner.close()
    if not runner.report["passed"]: raise SystemExit(1)


if __name__=="__main__": run()
