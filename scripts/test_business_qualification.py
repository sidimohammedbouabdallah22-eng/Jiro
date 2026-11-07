"""Guard against mutating a low-space fixture or waiting on a dead installer."""
import importlib.util
from pathlib import Path
from types import SimpleNamespace
import unittest
from unittest.mock import patch

spec=importlib.util.spec_from_file_location('business_guest',Path(__file__).with_name('m4_business_guest.py'))
guest=importlib.util.module_from_spec(spec)
spec.loader.exec_module(guest)


class QualificationGuards(unittest.TestCase):
    def test_only_owned_packaged_dependencies_are_stopped(self):
        values='network.target ssh.service openwaf-m2-events-1234abcd.service foreign.service'
        with patch.object(guest,'command',side_effect=[values,'']) as command:
            guest.stop_packaged_fixture()
            self.assertEqual(command.call_args_list[1].args[0],
                ['systemctl','stop','openwaf.service','openwaf-m2-events-1234abcd.service'])

    def test_low_disk_refused_before_fixture_creation(self):
        root=Path('/var/lib/owaf-business-00000000')
        with patch.object(guest.shutil,'disk_usage',return_value=SimpleNamespace(free=1024)), \
                patch.object(Path,'exists',return_value=False), patch.object(Path,'mkdir') as mkdir:
            with self.assertRaisesRegex(RuntimeError,'headroom'): guest.setup(root,{})
            mkdir.assert_not_called()

    def test_installer_exit_fails_before_http_wait(self):
        with patch.object(guest,'command',return_value='false'), patch.object(guest.urllib.request,'build_opener') as opener, \
                patch.object(guest.time,'sleep') as sleep:
            with self.assertRaisesRegex(RuntimeError,'exited'): guest.wait('http://127.0.0.1/',600,'owned-app')
            opener.return_value.open.assert_not_called(); sleep.assert_not_called()


if __name__=='__main__': unittest.main()
