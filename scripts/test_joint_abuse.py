"""Adverse accounting checks; synthetic samples are never qualification evidence."""
import importlib.util
import json
from pathlib import Path
import unittest

from joint_business_lab import resources

spec=importlib.util.spec_from_file_location('abuse',Path(__file__).with_name('qualify-joint-abuse.py'))
abuse=importlib.util.module_from_spec(spec);spec.loader.exec_module(abuse)


class AbuseAccountingTests(unittest.TestCase):
    def rows(self):
        return [dict(monotonic=float(t),time=9000+t,
                     processes={name:dict(pid=i+1,cpu_seconds=t*.1,rss_kib=1024) for i,name in enumerate(['gateway','collector'])},
                     containers={name:dict(cpu_seconds=t*.1,memory_bytes=2048,oom_kill=0) for name in ['erp','erp-db','shop','shop-db']},
                     host_cpu_ticks=[t*10,0,0,t*90,0,0,0,0],host_available_kib=1024*1024)
                for t in range(0,61,2)]

    def measure(self,rows):
        return resources('\n'.join(json.dumps(r) for r in rows),dict(monotonic=0),dict(monotonic=60))

    def test_clock_skew_and_low_busy_do_not_hide_components(self):
        rows=self.rows();first=self.measure(rows)
        for row in rows:row['time']-=36000
        self.assertEqual(first,self.measure(rows))
        self.assertAlmostEqual(first['observed_cpu_percent'],60)
        self.assertAlmostEqual(first['guest_busy_percent'],10)

    def test_restart_rejected(self):
        rows=self.rows();rows[-1]['processes']['gateway']['pid']=99
        with self.assertRaises(AssertionError):self.measure(rows)

    def test_oom_rejected(self):
        rows=self.rows();rows[10]['containers']['erp']['oom_kill']=1
        with self.assertRaises(AssertionError):self.measure(rows)

    def test_sample_gap_rejected(self):
        rows=[r for r in self.rows() if not 10<r['monotonic']<24]
        with self.assertRaises(AssertionError):self.measure(rows)

    def test_counter_reset_rejected(self):
        rows=self.rows();rows[-1]['containers']['shop']['cpu_seconds']=0
        with self.assertRaises(AssertionError):self.measure(rows)

    def test_disappearing_container_rejected(self):
        rows=self.rows();rows[5]['containers']['shop']={'unavailable':True}
        with self.assertRaises(AssertionError):self.measure(rows)

    def test_same_size_raw_and_escaped_unicode_reach_decoded_value(self):
        for size in [1024,32<<10,64<<10,900<<10]:
            for kind in ['ascii','unicode','escaped','attack']:
                body=abuse.body_bytes(size,kind);self.assertEqual(len(body),size)
                value=json.loads(body);self.assertNotIn('name',value)
                if kind=='unicode':self.assertIn(b'\xc3\xa9',body)
                if kind=='escaped':
                    self.assertIn(b'\\u00e9',body);self.assertIn('é',value['payload'])


if __name__=='__main__':unittest.main()
