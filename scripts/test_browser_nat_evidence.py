"""Browser evidence validity and owned-lab shutdown regression checks."""
import importlib.util
import contextlib
import io
import json
import subprocess
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

from joint_business_lab import Lab

spec = importlib.util.spec_from_file_location('browser_check', Path(__file__).with_name('check-browser-nat-evidence.py'))
checker = importlib.util.module_from_spec(spec)
spec.loader.exec_module(checker)


class BrowserEvidenceTests(unittest.TestCase):
    def test_shutdown_error_still_saves_failed_cleanup_state(self):
        lab=Lab.__new__(Lab)
        lab.attempted=False
        lab.tunnel=None
        lab.report=dict(passed=True)
        lab.out=Path('synthetic-output')
        lab.save=Mock()
        lab.shutdown=Mock(side_effect=RuntimeError('synthetic shutdown failure'))
        with contextlib.redirect_stdout(io.StringIO()):
            with self.assertRaisesRegex(RuntimeError,'synthetic shutdown failure'):
                lab.close()
        lab.save.assert_called_once()
        self.assertFalse(lab.report['passed'])

    def test_failed_runner_retains_completed_file_manifest(self):
        spec=importlib.util.spec_from_file_location('browser_phase_test',
            Path(__file__).with_name('qualify-browser-nat.py'))
        qualifier=importlib.util.module_from_spec(spec)
        spec.loader.exec_module(qualifier)
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory)
            source=root/'tools/application-check/browser-nat.cjs'
            source.parent.mkdir(parents=True)
            source.write_bytes(b'synthetic frozen browser source')
            flow=dict(name='completed-file.csv',committed=True,exact=True)
            lab=SimpleNamespace(repo=root,out=root,files=[],records=[],browser_fixture={},
                report=dict(browser_source_sha256=checker.sha(source.read_bytes())),
                fixture=dict(prestashop=dict(routes=dict(product='http://shop.test/product'))),
                admin=Mock(return_value=dict(applications=[])),drain=Mock(return_value={}),
                guest=Mock(return_value=dict(monotonic=0,time=0)),save=Mock())

            def runner(arguments, **options):
                Path(arguments[-1]).write_text(json.dumps(
                    dict(initial_uploads=[flow],waves=[])))
                return SimpleNamespace(stdout='',stderr='synthetic failure',returncode=1)

            with patch.object(qualifier.subprocess,'run',side_effect=runner), patch.object(
                    qualifier.fair.abuse,'body_bytes',return_value=b'body'):
                with self.assertRaisesRegex(AssertionError,'browser harness failed'):
                    qualifier.phase(lab,[],'failed-profile',{},True,1)
            self.assertEqual(lab.files,[flow])
            self.assertEqual(json.loads((root/'files.json').read_text()),[flow])

    def test_optional_journal_timeout_keeps_primary_capture(self):
        with tempfile.TemporaryDirectory() as directory:
            lab = Lab.__new__(Lab)
            lab.out = Path(directory)
            lab.tag = '12345678'
            lab.ssh = ['synthetic-ssh']
            lab.scp = ['synthetic-scp']
            lab.root = '/synthetic-owned-root'
            lab.report = {}
            payloads = {'databases.tar':b'databases','resources.jsonl':b'resources'}
            capture = {'sha256':checker.sha(payloads['databases.tar']),
                       'resources_sha256':checker.sha(payloads['resources.jsonl'])}
            lab.guest = Mock(return_value=capture)

            def run(arguments, **options):
                if arguments[0] == 'synthetic-ssh':
                    raise subprocess.TimeoutExpired(arguments,30)
                destination = Path(arguments[-1])
                destination.write_bytes(payloads[destination.name])

            lab.run = Mock(side_effect=run)
            lab.capture()
            lab.guest.assert_called_once_with('capture')
            self.assertEqual(lab.report['gateway_journal_error'],'TimeoutExpired')
            self.assertEqual(lab.report['capture'],capture)

    def test_invalidated_run_cannot_be_qualified(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root/'measurement-invalid.json').write_text('{"reason":"source changed during measurement"}')
            with self.assertRaisesRegex(AssertionError, 'measurement invalidated'):
                checker.check(root/'result.json', root/'candidate.tar.gz')

    def test_forced_shutdown_cannot_be_qualified(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root/'result.json').write_text('{"shutdown_forced":true}')
            with self.assertRaisesRegex(AssertionError, 'forced lab shutdown'):
                checker.check(root/'result.json', root/'candidate.tar.gz')

    def test_stalled_shutdown_powers_off_owned_vm_and_invalidates_run(self):
        lab = Lab.__new__(Lab)
        lab.attempted = True
        lab.report = dict(passed=True,capture={})
        lab.guest = Mock(return_value=dict(restored=True))
        lab.tunnel = None
        lab.ssh = ['synthetic-ssh']
        lab.vbox = 'synthetic-vbox'
        lab.vm = Path('owned-test-vm')
        lab.out = Path('synthetic-output')
        lab.save = Mock()
        state = 'running'

        def run(arguments, **options):
            nonlocal state
            if arguments == ['synthetic-vbox','controlvm','owned-test-vm','poweroff']:
                state = 'poweroff'

        lab.run = Mock(side_effect=run)
        lab.info = lambda: 'VMState="'+state+'"'
        with patch('joint_business_lab.time.sleep'), contextlib.redirect_stdout(io.StringIO()):
            lab.close()
        lab.run.assert_any_call(['synthetic-vbox','controlvm','owned-test-vm','poweroff'])
        self.assertTrue(lab.report['shutdown_forced'])
        self.assertTrue(lab.report['vm_powered_off'])
        self.assertFalse(lab.report['passed'])
        lab.save.assert_called_once()


if __name__ == '__main__':
    unittest.main()
