"""Owned-environment and bounded-allocation regression checks."""
import json
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import Mock, patch

import owned_lab_environment as owned
from wsl_fair_lab import WSLFairLab,acquire_lease


class OwnedEnvironmentTests(unittest.TestCase):
    def test_virtualbox_retains_existing_environment_boundary(self):
        with patch.object(owned.subprocess,'check_output',return_value='oracle\n'):
            self.assertEqual(owned.environment(), 'virtualbox')
            with self.assertRaises(AssertionError):
                owned.environment(dict(lab_environment='wsl2'))

    def test_wsl_requires_owned_marker_and_matching_fixture(self):
        with tempfile.TemporaryDirectory() as directory:
            marker=Path(directory)/'owner.json'
            with patch.object(owned,'OWNERSHIP_MARKER',marker), patch.object(
                    owned.subprocess,'check_output',return_value='wsl\n'):
                with self.assertRaises(FileNotFoundError):
                    owned.environment()
                marker.write_text(json.dumps(dict(scope='owned-jiro-m4-lab',lab_id='a'*32)))
                self.assertEqual(owned.environment(dict(lab_environment='wsl2',lab_id='a'*32)), 'wsl2')
                with self.assertRaises(AssertionError):
                    owned.environment(dict(lab_environment='wsl2',lab_id='b'*32))
                marker.write_text(json.dumps(dict(scope='unowned',lab_id='a'*32)))
                with self.assertRaises(AssertionError):
                    owned.environment()

    def test_other_environments_are_rejected(self):
        with patch.object(owned.subprocess,'check_output',return_value='kvm\n'):
            with self.assertRaises(AssertionError):
                owned.environment()

    def test_allocation_requires_actual_cpu_and_memory_bounds(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory)
            values={'cpu.max':'400000 100000','memory.max':str(4<<30),
                'cpuset.cpus.effective':'0-3','cpu.stat':'usage_usec 1000\n',
                'memory.events':'oom_kill 0\n','memory.current':'4096'}
            for name,value in values.items():
                (root/name).write_text(value)
            with patch.object(owned,'ALLOCATION',root):
                sample=owned.allocation_sample()
                self.assertEqual(sample['cpu_usage_usec'],1000)
                self.assertEqual(sample['memory_current'],4096)
                for name,value in [('cpu.max','max 100000'),('memory.max',str(8<<30)),
                                   ('cpuset.cpus.effective','0-7')]:
                    with self.subTest(resource=name):
                        (root/name).write_text(value)
                        with self.assertRaises(AssertionError):
                            owned.allocation()
                        (root/name).write_text(values[name])


class WSLShutdownTests(unittest.TestCase):
    def test_lab_lease_excludes_overlap_and_releases_on_close(self):
        with tempfile.TemporaryDirectory() as directory:
            path=Path(directory)/'qualification.lock'
            first=acquire_lease(path)
            try:
                with self.assertRaisesRegex(RuntimeError,'holds the owned WSL2 lab lease'):
                    acquire_lease(path)
            finally:
                first.close()
            acquire_lease(path).close()

    def make_lab(self):
        lab=WSLFairLab.__new__(WSLFairLab)
        lab.wsl=dict(distribution='Jiro-M4-20261108')
        lab.owned=True
        lab.keepalive=Mock()
        lab.lease=None
        lab.report=dict(passed=True)
        lab.run=Mock()
        return lab

    def test_shutdown_targets_only_owned_distribution(self):
        lab=self.make_lab()
        listing=Mock(stdout='Ubuntu-24.04\r\n'.encode('utf-16-le'))
        with patch('wsl_fair_lab.subprocess.run',return_value=listing):
            lab.shutdown()
        lab.run.assert_any_call(['wsl','--terminate','Jiro-M4-20261108'])
        self.assertFalse(any('--shutdown' in call.args[0] for call in lab.run.call_args_list))
        self.assertTrue(lab.report['lab_stopped'])
        self.assertNotIn('lab_shutdown_forced',lab.report)

    def test_failed_graceful_stop_invalidates_run(self):
        lab=self.make_lab()
        lab.run.side_effect=[RuntimeError('flush failed'),None]
        listing=Mock(stdout='Ubuntu-24.04\r\n'.encode('utf-16-le'))
        with patch('wsl_fair_lab.subprocess.run',return_value=listing):
            lab.shutdown()
        self.assertTrue(lab.report['lab_shutdown_forced'])
        self.assertFalse(lab.report['passed'])

    def test_bom_cannot_hide_a_still_running_owned_distribution(self):
        lab=self.make_lab()
        listing=Mock(stdout='\ufeffJiro-M4-20261108\r\nUbuntu-24.04\r\n'.encode('utf-16-le'))
        with patch('wsl_fair_lab.subprocess.run',return_value=listing):
            with self.assertRaisesRegex(AssertionError,'did not stop'):
                lab.shutdown()
        self.assertFalse(lab.report['passed'])

    def test_unowned_distribution_is_never_stopped(self):
        lab=self.make_lab()
        lab.owned=False
        lab.shutdown()
        lab.run.assert_not_called()
        self.assertFalse(lab.report['lab_stopped'])


if __name__ == '__main__':
    unittest.main()
