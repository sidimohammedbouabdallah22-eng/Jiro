"""Independently verify bounded CPU-contention schedules and durable evidence."""

import argparse
import hashlib
import importlib.util
import json
from pathlib import Path

spec=importlib.util.spec_from_file_location("evidence",Path(__file__).with_name("check-capacity-evidence.py"))
evidence=importlib.util.module_from_spec(spec)
spec.loader.exec_module(evidence)


def verify(report, source_root):
    if report.get("passed") is not True or report.get("smoke") or report.get("failure"):
        raise ValueError("requires a completed successful contention run")
    if report.get("experiment")!="CPU contention, not a general capacity qualification":
        raise ValueError("unexpected experiment")
    probe=next(app for app in report["bounded_policy"]["applications"] if app["application_id"]=="probe")
    if any(probe["traffic_controls"][key]!=1 for key in ["max_concurrent","max_client_concurrent"]):
        raise ValueError("bounded application policy missing")
    for name,digest in report["source_sha256"].items():
        if name not in {"scripts/qualify-capacity.py","scripts/m4_capacity_guest.py"}:
            raise ValueError("unexpected measurement source")
        if hashlib.sha256((source_root/name).read_bytes()).hexdigest()!=digest:
            raise ValueError("measurement source changed")
    if len(report["source_sha256"])!=2 or hashlib.sha256((source_root/"scripts/qualify-contention.py").read_bytes()).hexdigest()!=report["driver_sha256"]:
        raise ValueError("missing or changed contention source")
    phases=report["contention"]
    if [p["name"] for p in phases]!=["uncontended","ASCII-four-slots","Unicode-four-slots","Unicode-one-slot"]:
        raise ValueError("required comparison phases missing")
    if report["legitimate_budget"]!=dict(rate=2,p95_ms=2000,unexpected=0):
        raise ValueError("unexpected legitimate traffic budget")
    for phase in phases:
        planned=phase["requested_seconds"]*2
        if phase["requested_seconds"]<60 or phase["scheduled"]!=planned or phase["completed"]!=planned:
            raise ValueError("incomplete legitimate schedule")
        # Every phase must retain full accounting, even if its latency gate fails.
        if phase["heavy_attempts"]!=sum(phase["heavy_statuses"].values())+phase["heavy_network_errors"]:
            raise ValueError("incomplete heavy traffic accounting")
        if report.get("heavy_response_integrity_gate") and phase.get("heavy_invalid_responses")!=0:
            raise ValueError("heavy response integrity failed or was not recorded")
        if phase["name"]=="Unicode-one-slot" and (not phase["heavy_statuses"].get("200",0) or phase["heavy_network_errors"]):
            raise ValueError("bounded uploads did not complete without network errors")
        if phase["native_resources"]["processes"]["gateway"]["observed_pids"]!=1:
            raise ValueError("gateway lifecycle changed")
        if phase["name"]!="uncontended":
            if phase["heavy_workers"]!=4 or phase["heavy_body_bytes"]!=900<<10 or not phase["heavy_attempts"]:
                raise ValueError("CPU-heavy workload missing")
            if phase["native_resources"]["processes"]["gateway"]["cpu_percent_of_one_vcpu"]<50:
                raise ValueError("CPU contention was not demonstrated")
        computed=not any(phase[key] for key in ["unexpected","network_errors","generator_refusals","scheduler_late_over_100ms"]) and not phase.get("heavy_invalid_responses",0) and phase["p95_ms"] is not None and phase["p95_ms"]<=2000
        if computed!=phase["passed"] or (phase["name"] in {"uncontended","Unicode-one-slot"} and not computed):
            raise ValueError("legitimate traffic budget failed or verdict differs")
    evidence.capacity.validate_delivery(report["final_metrics"],report["reconciliation"])
    samples=report["metrics_samples"]
    if not samples or any(s.get("unavailable") or any(s["metrics"][key] for key in evidence.capacity.LOSS) for s in samples):
        raise ValueError("monitoring gaps or lost persistence evidence")
    if len({s["metrics"]["start_timestamp_seconds"] for s in samples})!=1:
        raise ValueError("gateway restarted")
    if any(s["metrics"]["active_requests"]>32 or s["metrics"]["reserved_buffer_bytes"]>64<<20 for s in samples):
        raise ValueError("resource envelope exceeded")
    expected=2+sum(p["completed"]+p["network_errors"]+p["heavy_attempts"] for p in phases)
    if report["final_metrics"]["requests_total"]!=expected:
        raise ValueError("front-end request accounting mismatch")
    return dict(verified=True,gateway_requests=expected,receiver_records=report["reconciliation"]["receiver_records"],
                receiver_occurrences=report["reconciliation"]["receiver_occurrences"],
                scope="60-second CPU-contention phases; no hard CPU-time isolation or customer capacity claim")


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument("report",type=Path)
    args=parser.parse_args()
    result=verify(json.loads(args.report.read_text()),args.report.parent/"source")
    evidence.verify_databases(args.report.parent/"databases.tar",result)
    result["report_sha256"]=hashlib.sha256(args.report.read_bytes()).hexdigest()
    result["verifier_sha256"]=hashlib.sha256(Path(__file__).read_bytes()).hexdigest()
    result["database_verifier_sha256"]=hashlib.sha256(Path(__file__).with_name("check-capacity-evidence.py").read_bytes()).hexdigest()
    print(json.dumps(result,indent=2))


if __name__=="__main__":
    main()
