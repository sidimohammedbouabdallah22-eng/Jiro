"""Prevent false transport qualification from fallback, reuse or missing evidence."""
import copy
import hashlib
import importlib.util
from pathlib import Path
import tempfile
import unittest

spec=importlib.util.spec_from_file_location("transport_evidence",Path(__file__).with_name("check-transport-evidence.py"))
verifier=importlib.util.module_from_spec(spec);spec.loader.exec_module(verifier)


class TransportEvidenceTests(unittest.TestCase):
    def test_protocol_fallback_false_multiplexing_and_missing_events_are_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory)
            sources=["scripts/qualify-capacity.py","scripts/m4_capacity_guest.py","scripts/qualify-transports.py",
                "tools/transportcheck/main.go","tools/transportcheck/main_test.go","tools/transportcheck/cpu_linux.go","tools/transportcheck/cpu_windows.go","tools/transportcheck/cpu_other.go"]
            for name in sources:
                path=root/name;path.parent.mkdir(parents=True,exist_ok=True);path.write_bytes(b"measurement-source")
            digest=hashlib.sha256(b"measurement-source").hexdigest()
            names=["TLS HTTP1 fresh connections","TLS HTTP1 persistent connections","TLS HTTP2 persistent connections"]
            phases=[dict(name=name,passed=True,rate=5,requested_seconds=120,planned=600,completed=600,generator_refusals=0,
                unexpected=0,network_errors=0,protocols={str(2 if index==2 else 1):600},tls_versions={"772":600},
                statuses={"200":420,"201":30,"403":150},reused=0 if index==0 else 597,unique_connections=600 if index==0 else 3,
                p95_ms=100,scheduler_late_over_100ms=0) for index,name in enumerate(names)]
            requests={"TLS12 complete mixed corpus":20,"HTTP1 large body verdicts":4,"HTTP2 large body verdicts":4,
                "HTTP2 simultaneous streams on one verified TLS connection":4,"TLS13 session resumption":10,
                "HTTP1 SNI authority mismatch rejected":1,"HTTP2 SNI authority mismatch rejected":1,
                "Untrusted CA rejected":0,"Wrong certificate hostname rejected":0}
            checks=[dict(name=name,passed=True,requests=count) for name,count in requests.items()]
            next(c for c in checks if c['name'].startswith('TLS13')).update(connections=10,resumed=9)
            next(c for c in checks if c['name'].startswith('HTTP2 simultaneous')).update(connections=1,overlap=3,
                observations=[dict(connection=1,correct=True,verified=True,protocol=2,reused=True,written=1+i/100,first_byte=2) for i in range(3)])
            resources=dict(processes=dict(gateway=dict(observed_pids=1,cpu_percent_of_one_vcpu=10)),host_busy_percent=20)
            metrics=dict(event_export_acked_records_total=459,event_export_enqueued_records_total=459,
                event_export_acked_occurrences_total=459,event_export_enqueued_occurrences_total=459,
                security_occurrences_total=459,event_export_pending_records=0,event_pending_writes=0,healthy=1,audit_healthy=1,
                requests_total=1846,start_timestamp_seconds=1,active_requests=0,reserved_buffer_bytes=0)
            metrics.update({key:0 for key in verifier.evidence.capacity.LOSS})
            report=dict(passed=True,experiment="Verified TLS application transports; not a deployment sizing claim",
                source_sha256={name:digest for name in sources[:2]},transport_source_sha256={name:digest for name in sources[2:]},
                transport_phase_seconds=120,transport=dict(passed=True,phases=phases,checks=checks,http_attempts=1844,started=0,finished=366),
                transport_native_resources=[dict(name=name,resources=copy.deepcopy(resources)) for name in names],
                final_metrics=metrics,metrics_samples=[dict(time=t,metrics=metrics) for t in range(0,367,2)],
                reconciliation=dict(identical_event_ids_and_payloads=True,receiver_records=459,receiver_occurrences=459,receiver_totals=[459,459]))
            self.assertTrue(verifier.verify(report,root)['verified'])
            for target,key,value in [(2,'protocols',{'1':600}),(0,'reused',1),(1,'unique_connections',600),(0,'statuses',{'200':600}), (0,'p95_ms',2500)]:
                changed=copy.deepcopy(report);changed['transport']['phases'][target][key]=value
                with self.subTest(key=key),self.assertRaises(ValueError): verifier.verify(changed,root)
            changed=copy.deepcopy(report)
            next(c for c in changed['transport']['checks'] if c['name'].startswith('HTTP2 simultaneous'))['observations'][0]['connection']=2
            with self.assertRaises(ValueError): verifier.verify(changed,root)
            changed=copy.deepcopy(report);changed['metrics_samples']=changed['metrics_samples'][:10]
            with self.assertRaises(ValueError): verifier.verify(changed,root)
            changed=copy.deepcopy(report);changed['final_metrics']['requests_total']-=1
            with self.assertRaises(ValueError): verifier.verify(changed,root)
            changed=copy.deepcopy(report)
            for key in ['event_export_acked_records_total','event_export_enqueued_records_total','event_export_acked_occurrences_total',
                        'event_export_enqueued_occurrences_total','security_occurrences_total']: changed['final_metrics'][key]=0
            changed['reconciliation'].update(receiver_records=0,receiver_occurrences=0,receiver_totals=[0,0])
            with self.assertRaises(ValueError): verifier.verify(changed,root)
            (root/sources[-1]).write_bytes(b"changed")
            with self.assertRaises(ValueError): verifier.verify(report,root)


if __name__=="__main__": unittest.main()
