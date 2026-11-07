"""Fail before service/filesystem mutations on unsafe qualification inputs."""
import importlib.util
from pathlib import Path
from types import SimpleNamespace
import unittest
from unittest.mock import patch

spec=importlib.util.spec_from_file_location('application_guest',Path(__file__).with_name('m4_guest.py'))
guest=importlib.util.module_from_spec(spec);spec.loader.exec_module(guest)


class ApplicationGuards(unittest.TestCase):
    def test_low_space_refused_before_guest_mutation(self):
        with patch.object(Path,'exists',return_value=False), patch.object(Path,'mkdir') as mkdir, \
             patch.object(guest.shutil,'disk_usage',return_value=SimpleNamespace(free=1024)), patch.object(guest,'command') as command:
            with self.assertRaisesRegex(RuntimeError,'free guest disk'):
                guest.setup(Path('/var/lib/owaf-m4-00000000'),{},'/tmp/package.tar.gz')
            mkdir.assert_not_called();command.assert_not_called()

    def test_tampered_archive_refused_before_service_changes(self):
        with patch.object(Path,'exists',return_value=False), patch.object(Path,'mkdir') as mkdir, \
             patch.object(Path,'read_bytes',return_value=b'tampered'), \
             patch.object(guest.shutil,'disk_usage',return_value=SimpleNamespace(free=10<<30)), patch.object(guest,'command') as command:
            with self.assertRaisesRegex(RuntimeError,'checksum mismatch'):
                guest.setup(Path('/var/lib/owaf-m4-00000000'),{'package_sha256':'0'*64},'/tmp/package.tar.gz')
            mkdir.assert_not_called();command.assert_not_called()


if __name__=='__main__':unittest.main()
