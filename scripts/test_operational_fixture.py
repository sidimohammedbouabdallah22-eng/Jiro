"""Keep qualification fixture replacement confined to owned service identities."""
import json
import os
from pathlib import Path
import sys
import unittest
from unittest.mock import Mock, patch

if os.name == 'nt':
    # Only the path/service validator runs here. Guest account operations are
    # exercised by the native Linux drill.
    with patch.dict(sys.modules, pwd=Mock()):
        import m2_guest
else:
    import m2_guest


class OperationalFixtureTests(unittest.TestCase):
    def fixture(self, kind='fresh', units=None):
        root = '/var/lib/owaf-' + kind + '-1234abcd'
        override = Mock()
        override.read_text.return_value = 'ExecStart=waf-server -config=' + root + '/restored/state/policy.json'
        document = dict(units=units if units is not None else [
            f'openwaf-{kind}-{name}-1234abcd.service' for name in ['backend', 'events', 'audit']])
        return root, override, document

    def resolve(self, kind='fresh', units=None):
        root, override, document = self.fixture(kind, units)
        with patch.object(Path, 'read_text', return_value=json.dumps(document)):
            actual, old = m2_guest.previous_fixture(override)
        self.assertEqual(actual.as_posix(), root)
        self.assertEqual(old, document)

    def test_fresh_host_layout(self):
        self.resolve()

    def test_original_operational_layout(self):
        self.resolve('m2')

    def test_external_path_refused(self):
        override = Mock()
        override.read_text.return_value = '-config=/srv/customer/state/policy.json'
        with self.assertRaises(RuntimeError):
            m2_guest.previous_fixture(override)

    def test_other_fixture_service_refused(self):
        with self.assertRaises(RuntimeError):
            self.resolve(units=['openwaf-fresh-backend-99999999.service',
                'openwaf-fresh-events-1234abcd.service', 'openwaf-fresh-audit-1234abcd.service'])

    def test_other_layout_service_refused(self):
        with self.assertRaises(RuntimeError):
            self.resolve(units=[f'openwaf-m2-{kind}-1234abcd.service'
                for kind in ['backend', 'events', 'audit']])

    def test_duplicate_service_refused(self):
        with self.assertRaises(RuntimeError):
            self.resolve(units=['openwaf-fresh-backend-1234abcd.service'] * 3)


if __name__ == '__main__':
    unittest.main()
