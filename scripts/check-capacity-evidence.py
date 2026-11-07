"""Read-only verification of a completed full M4 capacity report."""

import argparse
import hashlib
import importlib.util
import json
from pathlib import Path
import sqlite3
import tarfile

REPO=Path(__file__).resolve().parents[1]
spec=importlib.util.spec_from_file_location("capacity",REPO/"scripts/qualify-capacity.py")
capacity=importlib.util.module_from_spec(spec)
spec.loader.exec_module(capacity)


def verify(report, source_root=REPO):
    if not report.get("passed") or report.get("smoke") is not False or report.get("failure"):
        raise ValueError("requires a successful completed full run")
    sources={"scripts/qualify-capacity.py","scripts/m4_capacity_guest.py"}
    if set(report["source_sha256"])!=sources:
        raise ValueError("unexpected measurement sources")
    if not all(hashlib.sha256((source_root/name).read_bytes()).hexdigest()==value for name,value in report["source_sha256"].items()):
        raise ValueError("measurement sources changed")
    phases={phase["name"]:phase for phase in report["phases"]}
    for name,seconds in [("direct-benign",60),("inspected-benign",60),("direct-large",60),("large-bodies",120),("steady",300),("combined-endurance",max(600,report.get("endurance_requested_seconds",600)))]:
        phase=phases[name]
        if not phase["functional_passed"] or phase["requested_seconds"]<seconds or phase["scheduled"]!=phase["planned"]:
            raise ValueError("incomplete required phase: "+name)
        if phase["native_resources"]["processes"]["gateway"]["observed_pids"]!=1:
            raise ValueError("gateway process changed during a required phase")
    for name in ["steady","combined-endurance"]:
        if not capacity.operating_budget(phases[name]):
            raise ValueError("sustained operating budget failed: "+name)
    for phase in phases.values():
        if not phase["functional_passed"] and not (phase["name"].startswith("screen-") and capacity.admission_boundary(phase)):
            raise ValueError("unexplained traffic failure")
    outage=phases["collector-outage"]
    if (not outage["functional_passed"] or outage["requested_seconds"]<30
        or outage["after"]["event_export_pending_records"]<=outage["before"]["event_export_pending_records"]
        or outage["after"]["event_export_failures_total"]<=outage["before"]["event_export_failures_total"]
        or outage["after"]["event_export_healthy"]!=0):
        raise ValueError("collector outage and durable backlog growth were not demonstrated")
    required={"large-body-verdicts","slow-unavailable-recovery","concurrent-admission-fairness"}
    if {check["name"] for check in report["checks"] if check["passed"]}!=required:
        raise ValueError("required resource/fault checks missing")
    capacity.validate_delivery(report["final_metrics"],report["reconciliation"])
    samples=report["metrics_samples"]
    if not samples or not report["monitoring_coverage_passed"] or any(sample.get("unavailable") or any(sample.get("metrics",{}).get(key,0) for key in capacity.LOSS) for sample in samples):
        raise ValueError("monitoring evidence contains gaps")
    if len({sample["metrics"]["start_timestamp_seconds"] for sample in samples})!=1:
        raise ValueError("gateway lifecycle changed during observation")
    if not capacity.complete_coverage(samples,report["phases"][0]["started"],report["phases"][-1]["finished"]):
        raise ValueError("monitoring does not cover the complete workload")
    # Independent total includes setup writes, four body verdicts, four backend
    # checks and the 52-request simultaneous fairness burst.
    expected=62+sum(p["completed"] for p in phases.values() if not p["name"].startswith("direct-"))
    if report["final_metrics"]["requests_total"]!=expected:
        raise ValueError("front-end request accounting differs from the generator")
    return dict(verified=True, selected_lab_rate=report["selected_lab_rate"],
        gateway_requests=expected, receiver_records=report["reconciliation"]["receiver_records"],
        receiver_occurrences=report["reconciliation"]["receiver_occurrences"],
        deployment_capacity_gate=report["deployment_capacity_gate"])


def verify_databases(bundle, result, expected_status_occurrences=None):
    """Reconcile the stopped databases independently of a live guest report."""
    databases=[]
    with tarfile.open(bundle) as archive:
        if set(archive.getnames())!={"events.db","collector.db"}:
            raise ValueError("unexpected database evidence members")
        for name in ["events.db","collector.db"]:
            member=archive.getmember(name)
            if not member.isfile() or member.size>256<<20:
                raise ValueError("invalid database evidence size/type")
            database=sqlite3.connect(":memory:")
            database.deserialize(archive.extractfile(member).read())
            if database.execute("PRAGMA quick_check").fetchone()[0]!="ok":
                raise ValueError("database evidence integrity check failed")
            databases.append(database)
    try:
        local={json.loads(row[0])["id"]:json.loads(row[0]) for row in databases[0].execute("SELECT data FROM events")}
        remote={row[0]:json.loads(row[1]) for row in databases[1].execute("SELECT id,data FROM collected_events")}
        if local!=remote or len(remote)!=result["receiver_records"]:
            raise ValueError("captured database event IDs/payloads do not reconcile")
        totals=databases[1].execute("SELECT records,occurrences FROM collector_totals").fetchone()
        if totals!=(result["receiver_records"],result["receiver_occurrences"]):
            raise ValueError("captured receiver totals differ")
        if sum(max(1,int(row.get("occurrences",1))) for row in remote.values())!=result["receiver_occurrences"]:
            raise ValueError("captured event occurrences differ")
        statuses={}
        for row in remote.values():
            key=str(row["status"])
            statuses[key]=statuses.get(key,0)+max(1,int(row.get("occurrences",1)))
        if expected_status_occurrences is not None and any(statuses.get(key,0)!=count for key,count in expected_status_occurrences.items()):
            raise ValueError("captured security statuses differ from the independent request corpus")
        result["security_status_occurrences"]=statuses
    finally:
        for database in databases:
            database.close()
    result["database_bundle_sha256"]=hashlib.sha256(bundle.read_bytes()).hexdigest()
    result["database_payloads_verified"]=True
    return result


def verify_native_coverage(path, windows):
    if path.stat().st_size>64<<20:
        raise ValueError("native resource evidence exceeds its bounded size")
    rows=[json.loads(line) for line in path.read_text().splitlines() if line.strip()]
    if len(rows)>6000: raise ValueError("native sample budget exceeded")
    for window in windows:
        if window["native_resources"].get("insufficient_duration"): continue
        selected=[row for row in rows if window["started"]<=row["time"]<=window["finished"]]
        if not capacity.complete_coverage(selected,window["started"],window["finished"]):
            raise ValueError("native samples do not cover phase: "+window["name"])
        gateways=[row["processes"]["gateway"] for row in selected]
        if any(row.get("unavailable") for row in gateways) or len({row["pid"] for row in gateways})!=1:
            raise ValueError("native gateway lifecycle gap: "+window["name"])
        span=selected[-1]["monotonic"]-selected[0]["monotonic"]
        if abs(span-window["native_resources"]["interval_seconds"])>.001:
            raise ValueError("native interval summary differs from samples")


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument("report",type=Path)
    args=parser.parse_args()
    report=json.loads(args.report.read_text())
    snapshot=args.report.parent/"source"
    result=verify(report,snapshot if snapshot.is_dir() else REPO)
    verify_native_coverage(args.report.parent/"resources.jsonl",report["phases"])
    attacks=sum(row["completed"] for phase in report["phases"] if not phase["name"].startswith("direct-") for name,row in phase["workflows"].items() if name.startswith("attack-"))
    oversized=1+sum(phase["workflows"].get("body-1048577",{}).get("completed",0) for phase in report["phases"] if not phase["name"].startswith("direct-"))
    verify_databases(args.report.parent/"databases.tar",result,{"403":attacks,"413":oversized})
    result["native_measurement_coverage_verified"]=True
    result["report_sha256"]=hashlib.sha256(args.report.read_bytes()).hexdigest()
    result["verifier_sha256"]=hashlib.sha256(Path(__file__).read_bytes()).hexdigest()
    print(json.dumps(result,indent=2))


if __name__=="__main__":
    main()
