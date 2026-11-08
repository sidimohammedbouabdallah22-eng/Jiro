"""Browser evidence validity and owned-lab shutdown regression checks."""
import importlib.util
import contextlib
import io
from pathlib import Path
import tempfile
import unittest
from unittest.mock import Mock, patch

from joint_business_lab import Lab

spec = importlib.util.spec_from_file_location('browser_check', Path(__file__).with_name('check-browser-nat-evidence.py'))
checker = importlib.util.module_from_spec(spec)
spec.loader.exec_module(checker)


class BrowserEvidenceTests(unittest.TestCase):
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
