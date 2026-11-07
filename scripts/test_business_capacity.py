"""Adverse accounting tests; synthetic rows never count as capacity evidence."""
import copy
import importlib.util
from pathlib import Path
import unittest

spec=importlib.util.spec_from_file_location('capacity',Path(__file__).with_name('qualify-business-capacity.py'))
capacity=importlib.util.module_from_spec(spec);spec.loader.exec_module(capacity)


class ResourceTests(unittest.TestCase):
    def rows(self):
        return [dict(monotonic=float(t),time=18000+t,
            processes={name:dict(pid=n+1,cpu_seconds=t*.1,rss_kib=1024) for n,name in enumerate(['gateway','collector','relay'])},
            containers={name:dict(cpu_seconds=t*.05,memory_bytes=1024) for name in ['app','db']},
            host_cpu_ticks=[t*10,0,0,t*90,0,0,0,0],host_available_kib=1024*1024) for t in range(0,61,2)]

    def test_clock_skew_does_not_discard_native_measurements(self):
        rows=self.rows();result=capacity.resource_summary(rows,0,60)
        for row in rows:row['time']-=36000
        self.assertEqual(result,capacity.resource_summary(rows,0,60))
        self.assertAlmostEqual(result['host_busy_percent'],10)
        self.assertAlmostEqual(result['processes']['gateway']['cpu_percent_one_vcpu'],10)

    def test_missing_measurement_interval_rejected(self):
        rows=[row for row in self.rows() if not 10<row['monotonic']<30]
        with self.assertRaises(AssertionError):capacity.resource_summary(rows,0,60)

    def test_gateway_restart_not_hidden_by_aggregate_cpu(self):
        rows=self.rows();rows[-1]['processes']['gateway']['pid']=999
        with self.assertRaises(AssertionError):capacity.resource_summary(rows,0,60)

    def test_missing_container_sample_rejected(self):
        rows=self.rows();rows[10]['containers']['app']={'unavailable':True}
        with self.assertRaises(AssertionError):capacity.resource_summary(rows,0,60)

    def test_latency_and_headroom_fail_even_with_correct_http_statuses(self):
        phase=dict(functional_passed=True,p95_scheduled_ms=100,late_over_100ms=0,planned=100,resources=capacity.resource_summary(self.rows(),0,60))
        self.assertTrue(capacity.accepted(phase))
        bad=copy.deepcopy(phase);bad['p95_scheduled_ms']=2001;self.assertFalse(capacity.accepted(bad))
        bad=copy.deepcopy(phase);bad['resources']['host_busy_percent']=86;self.assertFalse(capacity.accepted(bad))
        bad=copy.deepcopy(phase);bad['resources']['min_host_available_kib']=100;self.assertFalse(capacity.accepted(bad))

    def test_generator_scheduling_delay_cannot_claim_supported_rate(self):
        phase=dict(functional_passed=True,p95_scheduled_ms=100,late_over_100ms=2,planned=100,resources=capacity.resource_summary(self.rows(),0,60))
        self.assertFalse(capacity.accepted(phase))

    def test_low_guest_busy_cannot_hide_high_component_accounting(self):
        resources=capacity.resource_summary(self.rows(),0,60)
        resources['containers']['app']['cpu_percent_one_vcpu']=80
        phase=dict(functional_passed=True,p95_scheduled_ms=100,late_over_100ms=0,planned=100,resources=resources)
        self.assertLess(resources['host_busy_percent'],85)
        self.assertFalse(capacity.accepted(phase))


if __name__=='__main__':unittest.main()
