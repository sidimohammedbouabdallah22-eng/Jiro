"""Prevent false qualification when load or durable accounting is incomplete."""

import copy
import importlib.util
import hashlib
import io
import json
import os
from pathlib import Path
import tempfile
import sqlite3
import tarfile
import time
import unittest
from unittest.mock import patch
from types import SimpleNamespace

spec = importlib.util.spec_from_file_location("capacity", Path(__file__).with_name("qualify-capacity.py"))
capacity = importlib.util.module_from_spec(spec)
spec.loader.exec_module(capacity)


class CapacityTests(unittest.TestCase):
    def test_offline_capture_must_contain_the_known_security_outcomes(self):
        spec=importlib.util.spec_from_file_location("capacity_evidence",Path(__file__).with_name("check-capacity-evidence.py"))
        verifier=importlib.util.module_from_spec(spec);spec.loader.exec_module(verifier)
        records=[dict(id="blocked",status=403),dict(id="routing-summary",status=421,occurrences=2)]
        sender=sqlite3.connect(":memory:");receiver=sqlite3.connect(":memory:")
        sender.execute("CREATE TABLE events(data TEXT)")
        receiver.execute("CREATE TABLE collected_events(id TEXT,data TEXT)")
        receiver.execute("CREATE TABLE collector_totals(records INTEGER,occurrences INTEGER)")
        for row in records:
            sender.execute("INSERT INTO events VALUES(?)",(json.dumps(row),))
            receiver.execute("INSERT INTO collected_events VALUES(?,?)",(row['id'],json.dumps(row)))
        receiver.execute("INSERT INTO collector_totals VALUES(2,3)")
        sender.commit();receiver.commit()
        try:
            with tempfile.TemporaryDirectory() as directory:
                bundle=Path(directory)/"databases.tar"
                with tarfile.open(bundle,"w") as archive:
                    for name,db in [('events.db',sender),('collector.db',receiver)]:
                        data=db.serialize();member=tarfile.TarInfo(name);member.size=len(data);archive.addfile(member,io.BytesIO(data))
                result=verifier.verify_databases(bundle,dict(receiver_records=2,receiver_occurrences=3),{'403':1,'421':2})
                self.assertEqual(result['security_status_occurrences'],{'403':1,'421':2})
                with self.assertRaises(ValueError): verifier.verify_databases(bundle,dict(receiver_records=2,receiver_occurrences=3),{'403':2})
        finally: sender.close();receiver.close()

    def test_offline_native_samples_must_cover_the_claimed_interval(self):
        spec=importlib.util.spec_from_file_location("capacity_evidence",Path(__file__).with_name("check-capacity-evidence.py"))
        verifier=importlib.util.module_from_spec(spec);spec.loader.exec_module(verifier)
        rows=[dict(time=t,monotonic=t,processes=dict(gateway=dict(pid=42))) for t in range(0,101,2)]
        with tempfile.TemporaryDirectory() as directory:
            path=Path(directory)/"resources.jsonl"
            path.write_text('\n'.join(json.dumps(row) for row in rows)+'\n')
            windows=[dict(name="measured",started=0,finished=100,native_resources=dict(interval_seconds=100))]
            verifier.verify_native_coverage(path,windows)
            path.write_text('\n'.join(json.dumps(row) for row in rows[:20])+'\n')
            with self.assertRaises(ValueError): verifier.verify_native_coverage(path,windows)
            rows[20]['processes']['gateway']['pid']=43
            path.write_text('\n'.join(json.dumps(row) for row in rows)+'\n')
            with self.assertRaises(ValueError): verifier.verify_native_coverage(path,windows)

    def test_long_run_cannot_pass_with_truncated_or_gapped_measurements(self):
        rows=[dict(time=t) for t in range(0,101,2)]
        self.assertTrue(capacity.complete_coverage(rows,0,100))
        self.assertFalse(capacity.complete_coverage(rows[:20],0,100))
        self.assertFalse(capacity.complete_coverage(rows[20:],0,100))
        self.assertFalse(capacity.complete_coverage([r for r in rows if not 40<=r['time']<=60],0,100))
        self.assertFalse(capacity.complete_coverage([],0,100))
        capacity.validate_plan(5,7200)
        with self.assertRaises(ValueError): capacity.validate_plan(25,7200)

    def test_sustained_latency_cpu_and_generator_budgets_are_required(self):
        result=dict(functional_passed=True,planned=300,scheduled=300,completed=300,
            scheduled_latency_ms=dict(p95=500),scheduler_late_over_100ms=0,
            native_resources=dict(processes=dict(gateway=dict(cpu_percent_of_one_vcpu=20)),host_busy_percent=40))
        self.assertTrue(capacity.operating_budget(result))
        for key,value in [('completed',299),('scheduler_late_over_100ms',4),('functional_passed',False)]:
            self.assertFalse(capacity.operating_budget(dict(result,**{key:value})))
        self.assertFalse(capacity.operating_budget(dict(result,scheduled_latency_ms=dict(p95=2001))))
        self.assertFalse(capacity.operating_budget(dict(result,native_resources=dict(processes=dict(gateway=dict(cpu_percent_of_one_vcpu=86)),host_busy_percent=40))))
        self.assertFalse(capacity.operating_budget(dict(result,native_resources=dict(processes=dict(gateway=dict(cpu_percent_of_one_vcpu=20)),host_busy_percent=91))))

    @unittest.skipIf(os.name=="nt","guest setup runs on Linux")
    def test_guest_refuses_low_disk_before_creating_state(self):
        spec=importlib.util.spec_from_file_location("capacity_guest",Path(__file__).with_name("m4_capacity_guest.py"))
        guest=importlib.util.module_from_spec(spec)
        spec.loader.exec_module(guest)
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory)/"must-not-exist"
            for available in [0,(2<<30)-1]:
                with patch.object(guest.shutil,"disk_usage",return_value=SimpleNamespace(free=available)):
                    with self.assertRaisesRegex(RuntimeError,"2 GiB"):
                        guest.setup(root,{})
                    self.assertFalse(root.exists())

    def test_contention_verifier_rejects_incomplete_or_unmeasured_abuse(self):
        spec=importlib.util.spec_from_file_location("contention_evidence",Path(__file__).with_name("check-contention-evidence.py"))
        verifier=importlib.util.module_from_spec(spec)
        spec.loader.exec_module(verifier)
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory)
            (root/"scripts").mkdir()
            names=["scripts/qualify-capacity.py","scripts/m4_capacity_guest.py","scripts/qualify-contention.py"]
            for name in names: (root/name).write_text("test-source")
            digest=hashlib.sha256((root/names[0]).read_bytes()).hexdigest()
            metrics=dict(event_export_acked_records_total=0,event_export_enqueued_records_total=0,
                event_export_acked_occurrences_total=0,event_export_enqueued_occurrences_total=0,
                security_occurrences_total=0,event_export_pending_records=0,event_pending_writes=0,healthy=1,audit_healthy=1,
                active_requests=0,reserved_buffer_bytes=0,start_timestamp_seconds=1,requests_total=485)
            metrics.update({key:0 for key in capacity.LOSS})
            phase=dict(requested_seconds=60,scheduled=120,completed=120,heavy_attempts=1,heavy_statuses={"200":1},
                heavy_network_errors=0,heavy_workers=4,heavy_body_bytes=900<<10,unexpected=0,network_errors=0,
                generator_refusals=0,scheduler_late_over_100ms=0,p95_ms=100,passed=True,
                native_resources=dict(processes=dict(gateway=dict(observed_pids=1,cpu_percent_of_one_vcpu=80))))
            phases=[dict(copy.deepcopy(phase),name=name) for name in ["uncontended","ASCII-four-slots","Unicode-four-slots","Unicode-one-slot"]]
            phases[0].update(heavy_attempts=0,heavy_statuses={})
            report=dict(passed=True,experiment="CPU contention, not a general capacity qualification",source_sha256={name:digest for name in names[:2]},
                driver_sha256=digest,bounded_policy=dict(applications=[dict(application_id="probe",traffic_controls=dict(max_concurrent=1,max_client_concurrent=1))]),
                legitimate_budget=dict(rate=2,p95_ms=2000,unexpected=0),contention=phases,final_metrics=metrics,metrics_samples=[dict(metrics=metrics)],
                reconciliation=dict(identical_event_ids_and_payloads=True,receiver_records=0,receiver_occurrences=0,receiver_totals=[0,0]))
            self.assertTrue(verifier.verify(report,root)["verified"])
            for key,value in [("requested_seconds",30),("completed",119),("heavy_attempts",0),("p95_ms",2001),("network_errors",1),("heavy_invalid_responses",1)]:
                changed=copy.deepcopy(report)
                changed["contention"][3][key]=value
                with self.subTest(key=key),self.assertRaises(ValueError): verifier.verify(changed,root)
            changed=copy.deepcopy(report)
            changed["contention"][3]["native_resources"]["processes"]["gateway"]["cpu_percent_of_one_vcpu"]=1
            with self.assertRaises(ValueError): verifier.verify(changed,root)
            (root/names[2]).write_text("changed-source")
            with self.assertRaises(ValueError): verifier.verify(report,root)

    def test_only_counted_admission_refusals_can_be_a_screen_boundary(self):
        baseline={key:0 for key in capacity.LOSS}
        baseline["overload_requests_total"]=0
        candidate=dict(capacity_refusals=2,non_capacity_unexpected=0,network_errors=0,generator_refusals=0,
                       before=baseline,after=dict(baseline,overload_requests_total=2))
        self.assertTrue(capacity.admission_boundary(candidate))
        for key in ("non_capacity_unexpected","network_errors","generator_refusals"):
            with self.subTest(key=key):
                self.assertFalse(capacity.admission_boundary(dict(candidate,**{key:1})))
        self.assertFalse(capacity.admission_boundary(dict(candidate,after=baseline)))
        self.assertFalse(capacity.admission_boundary(dict(candidate,after=dict(candidate["after"],event_write_failed_total=1))))

    def test_unacknowledged_or_different_evidence_cannot_pass(self):
        metrics = dict(event_export_acked_records_total=2,event_export_enqueued_records_total=2,
            event_export_acked_occurrences_total=7,event_export_enqueued_occurrences_total=7,
            security_occurrences_total=7,event_export_pending_records=0,event_pending_writes=0,healthy=1,audit_healthy=1)
        metrics.update({key:0 for key in capacity.LOSS})
        received = dict(identical_event_ids_and_payloads=True,receiver_records=2,receiver_occurrences=7,receiver_totals=[2,7])
        capacity.validate_delivery(metrics,received)
        for key,value in [("event_export_pending_records",1),("event_pending_writes",1),("security_occurrences_total",8),
                          ("event_export_acked_records_total",1),("event_export_acked_occurrences_total",6),
                          ("event_ingest_timeouts_total",1),("event_queue_dropped_total",1),("healthy",0)]:
            with self.subTest(key=key),self.assertRaises(RuntimeError):
                capacity.validate_delivery(dict(metrics,**{key:value}),received)
        changed=copy.deepcopy(received)
        changed["receiver_totals"][1]=8
        with self.assertRaises(RuntimeError):
            capacity.validate_delivery(metrics,changed)
        with self.assertRaises(RuntimeError):
            capacity.validate_delivery(metrics,dict(received,identical_event_ids_and_payloads=False))

    def test_generator_queue_refusal_and_waiting_latency_are_visible(self):
        runner=capacity.Runner.__new__(capacity.Runner)
        runner.scheduled_budget=0
        runner.report={"phases":[]}
        runner.metrics=lambda:{key:0 for key in capacity.LOSS}
        runner.resources=lambda *args:{"samples":1}
        runner.case=lambda *args:("unused","GET","/",None,"bounded-test",{},200)
        runner.save=lambda:None
        def respond(*args):
            time.sleep(.15)
            return 200,True
        runner.perform=respond
        result=runner.phase("synthetic-generator-saturation",1000,1)
        self.assertFalse(result["functional_passed"])
        self.assertGreater(result["generator_refusals"],0)
        self.assertLess(result["scheduled"],result["planned"])
        self.assertEqual(result["scheduled"],result["completed"]+result["generator_refusals"])
        self.assertGreater(result["scheduled_latency_ms"]["p95"],result["service_latency_ms"]["p95"])


if __name__=="__main__":
    unittest.main()
