"""Read-only verification of the completed M4 TLS/application transport experiment."""
import argparse
import hashlib
import importlib.util
import json
from pathlib import Path

spec=importlib.util.spec_from_file_location("evidence",Path(__file__).with_name("check-capacity-evidence.py"))
evidence=importlib.util.module_from_spec(spec);spec.loader.exec_module(evidence)


def verify(report,source_root):
    if report.get("passed") is not True or report.get("failure") or report.get("experiment")!="Verified TLS application transports; not a deployment sizing claim":
        raise ValueError("requires a completed successful transport qualification")
    sources=dict(report["source_sha256"],**report["transport_source_sha256"])
    expected={"scripts/qualify-capacity.py","scripts/m4_capacity_guest.py","scripts/qualify-transports.py",
        "tools/transportcheck/main.go","tools/transportcheck/main_test.go","tools/transportcheck/cpu_linux.go","tools/transportcheck/cpu_windows.go","tools/transportcheck/cpu_other.go"}
    if set(sources)!=expected or any(hashlib.sha256((source_root/name).read_bytes()).hexdigest()!=digest for name,digest in sources.items()):
        raise ValueError("missing or changed transport measurement sources")
    measured=report["transport"]
    names=["TLS HTTP1 fresh connections","TLS HTTP1 persistent connections","TLS HTTP2 persistent connections"]
    if not measured["passed"] or [phase["name"] for phase in measured["phases"]]!=names:
        raise ValueError("complete protocol phases missing")
    for index,phase in enumerate(measured["phases"]):
        total=phase["rate"]*phase["requested_seconds"]
        if phase["requested_seconds"]<120 or phase["requested_seconds"]!=report["transport_phase_seconds"] or phase["rate"]!=5:
            raise ValueError("unexpected transport schedule")
        if not phase["passed"] or phase["planned"]!=total or phase["completed"]!=total or any(phase[k] for k in ["generator_refusals","unexpected","network_errors"]):
            raise ValueError("incomplete or incorrect transport outcomes")
        if phase["protocols"]!={str(2 if index==2 else 1):total}:
            raise ValueError("negotiated protocol differs from declared mode")
        if sum(phase["tls_versions"].values())!=total or any(version not in {"771","772"} for version in phase["tls_versions"]):
            raise ValueError("TLS version evidence differs")
        if phase["statuses"]!={"200":total*14//20,"201":total//20,"403":total*5//20}:
            raise ValueError("mixed-workflow outcomes differ")
        if index==0:
            if phase["reused"] or phase["unique_connections"]!=total: raise ValueError("fresh connections were reused")
        elif phase["reused"]<1 or not 1<=phase["unique_connections"]<total:
            raise ValueError("persistent connection reuse missing")
        native=report["transport_native_resources"][index]
        normalized=dict(functional_passed=phase["passed"],planned=total,scheduled=total,completed=phase["completed"],
            scheduled_latency_ms=dict(p95=phase["p95_ms"]),scheduler_late_over_100ms=phase["scheduler_late_over_100ms"],native_resources=native["resources"])
        if native["name"]!=phase["name"] or not evidence.capacity.operating_budget(normalized) or native["resources"]["processes"]["gateway"]["observed_pids"]!=1:
            raise ValueError("transport operating budget or process stability failed")
    checks={row["name"]:row for row in measured["checks"]}
    expected_checks={"TLS12 complete mixed corpus":20,"HTTP1 large body verdicts":4,"HTTP2 large body verdicts":4,
        "HTTP2 simultaneous streams on one verified TLS connection":4,"TLS13 session resumption":10,
        "HTTP1 SNI authority mismatch rejected":1,"HTTP2 SNI authority mismatch rejected":1,
        "Untrusted CA rejected":0,"Wrong certificate hostname rejected":0}
    if set(checks)!=set(expected_checks) or any(not checks[name]["passed"] or checks[name]["requests"]!=count for name,count in expected_checks.items()):
        raise ValueError("required TLS, payload or isolation checks missing")
    mux=checks["HTTP2 simultaneous streams on one verified TLS connection"]
    rows=mux["observations"]
    if len(rows)!=3 or mux["connections"]!=1 or len({row["connection"] for row in rows})!=1:
        raise ValueError("multiplexed streams did not share one connection")
    if any(not row["correct"] or not row["verified"] or row["protocol"]!=2 or not row["reused"] or not 0<row["written"]<row["first_byte"] for row in rows):
        raise ValueError("multiplexed stream evidence invalid")
    overlap=max(sum(b["written"]<=a["written"]<b["first_byte"] for b in rows) for a in rows)
    if overlap<2 or overlap!=mux["overlap"]: raise ValueError("concurrent HTTP2 streams were not demonstrated")
    resume=checks["TLS13 session resumption"]
    if resume["connections"]!=10 or not 1<=resume["resumed"]<=9: raise ValueError("TLS resumption missing")
    total=sum(phase["completed"] for phase in measured["phases"])+sum(expected_checks.values())
    if measured["http_attempts"]!=total or report["final_metrics"]["requests_total"]!=total+2:
        raise ValueError("transport frontend accounting mismatch")
    samples=report["metrics_samples"]
    if not evidence.capacity.complete_coverage(samples,measured["started"],measured["finished"]) or any(row.get("unavailable") or any(row["metrics"][key] for key in evidence.capacity.LOSS) for row in samples):
        raise ValueError("transport monitoring incomplete or persistence failed")
    if len({row["metrics"]["start_timestamp_seconds"] for row in samples})!=1:
        raise ValueError("gateway lifecycle changed")
    if any(row["metrics"]["active_requests"]>32 or row["metrics"]["reserved_buffer_bytes"]>64<<20 for row in samples):
        raise ValueError("transport resource envelope exceeded")
    evidence.capacity.validate_delivery(report["final_metrics"],report["reconciliation"])
    expected_attacks=sum(phase["planned"] for phase in measured["phases"])//4+5
    if report["final_metrics"]["security_occurrences_total"]<expected_attacks+4:
        raise ValueError("known security outcomes were not all recorded")
    return dict(verified=True,gateway_requests=total+2,receiver_records=report["reconciliation"]["receiver_records"],
        receiver_occurrences=report["reconciliation"]["receiver_occurrences"],expected_status_occurrences={"403":expected_attacks,"413":2,"421":2},
        scope="Owned private-CA TLS application fixture; no customer capacity claim")


def main():
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument("report",type=Path);args=parser.parse_args()
    result=verify(json.loads(args.report.read_text()),args.report.parent/"source")
    report=json.loads(args.report.read_text())
    evidence.verify_native_coverage(args.report.parent/"resources.jsonl",[
        dict(name=phase["name"],started=phase["started"],finished=phase["finished"],native_resources=native["resources"])
        for phase,native in zip(report["transport"]["phases"],report["transport_native_resources"])])
    evidence.verify_databases(args.report.parent/"databases.tar",result,result["expected_status_occurrences"])
    result.update(report_sha256=hashlib.sha256(args.report.read_bytes()).hexdigest(),verifier_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
        native_measurement_coverage_verified=True,
        shared_verifier_sha256=hashlib.sha256(Path(__file__).with_name("check-capacity-evidence.py").read_bytes()).hexdigest())
    print(json.dumps(result,indent=2))


if __name__=="__main__": main()
