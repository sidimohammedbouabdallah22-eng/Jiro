"""Archive boundaries and exact metadata/content checks for the owned drill."""
import io
import hashlib
import json
import sys
import subprocess
from pathlib import Path
import tarfile
import tempfile
import unittest
from types import SimpleNamespace
from unittest.mock import patch

from m4_business_recovery_guest import await_database, await_executable, restore, restore_volume, verify_checkpoint, volume_inventory
from joint_business_lab import Lab


def archive_member(name='file.csv', data=b'owned fixture', kind=tarfile.REGTYPE, link='', uid=33):
    stream = io.BytesIO()
    with tarfile.open(fileobj=stream, mode='w') as archive:
        member = tarfile.TarInfo(name)
        member.type, member.linkname = kind, link
        member.uid, member.gid, member.mode = uid, uid, 0o640
        member.size = len(data) if kind == tarfile.REGTYPE else 0
        archive.addfile(member, io.BytesIO(data) if member.size else None)
    stream.seek(0)
    return stream


class BusinessRecoveryTests(unittest.TestCase):
    def test_fresh_host_entrypoints_refuse_optimized_python(self):
        for name in ['qualify-fresh-business-recovery.py', 'm4_fresh_business_guest.py',
                     'check-fresh-business-evidence.py']:
            with self.subTest(script=name):
                result = subprocess.run([sys.executable, '-O', str(Path(__file__).with_name(name)), '--help'],
                    capture_output=True, text=True, timeout=20)
                self.assertNotEqual(result.returncode, 0)
                self.assertIn('requires assertions', result.stderr)

    def test_fresh_host_rejects_invalid_preconditions_before_mutation(self):
        baseline = dict(clean_os=True, empty_docker=True, machine_id='target',
                        source_machine_id='source', checkpoint_sha256='checkpoint')
        for changed in [dict(clean_os=False), dict(empty_docker=False),
                        dict(source_machine_id='target'), dict(checkpoint_sha256='different')]:
            with self.subTest(changed=changed), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                (root / 'fresh-host-preconditions.json').write_text(json.dumps(dict(baseline, **changed)))
                with patch.dict(sys.modules, pwd=SimpleNamespace(), m4_business_guest=SimpleNamespace(wait=None)), \
                     patch('m4_business_recovery_guest.verify_checkpoint', return_value=(root, {})), \
                     patch('m4_business_recovery_guest.digest', return_value='target'), \
                     patch('m4_business_recovery_guest.run') as command:
                    with self.assertRaises(AssertionError):
                        restore(root, {}, 'checkpoint', fresh_host=True)
                    command.assert_not_called()

    def test_exact_bytes_and_ownership_affect_inventory(self):
        first = volume_inventory(archive_member())
        changed = volume_inventory(archive_member(data=b'changed'))
        self.assertNotEqual(first['sha256'], changed['sha256'])
        self.assertEqual(first['entries']['file.csv']['uid'], 33)
        self.assertEqual(first['entries']['file.csv']['mode'], 0o640)
        self.assertEqual(first['bytes'], len(b'owned fixture'))

    def test_traversal_and_special_members_are_rejected(self):
        for name in ['../escape', '/absolute', 'a/../../escape', 'a\\escape']:
            with self.subTest(name=name), self.assertRaises(ValueError):
                volume_inventory(archive_member(name=name))
        for kind in [tarfile.CHRTYPE, tarfile.BLKTYPE, tarfile.FIFOTYPE]:
            with self.subTest(kind=kind), self.assertRaises(ValueError):
                volume_inventory(archive_member(kind=kind))

    def test_links_must_stay_inside_archive(self):
        for target in ['../escape', '/etc/shadow']:
            with self.subTest(target=target), self.assertRaises(ValueError):
                volume_inventory(archive_member(kind=tarfile.SYMTYPE, link=target))
        self.assertEqual(volume_inventory(archive_member(kind=tarfile.SYMTYPE, link='target'))
                         ['entries']['file.csv']['target'], 'target')

    def test_corrupted_checkpoint_is_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            checkpoint = root / 'business-checkpoint'
            checkpoint.mkdir()
            data = b'owned database snapshot'
            (checkpoint / 'database.sql').write_bytes(data)
            manifest = dict(format=1, apps=dict(dolibarr={}, prestashop={}), files={
                'database.sql':dict(bytes=len(data), sha256=hashlib.sha256(data).hexdigest())})
            raw = json.dumps(manifest).encode()
            (checkpoint / 'manifest.private.json').write_bytes(raw)
            expected = hashlib.sha256(raw).hexdigest()
            self.assertEqual(verify_checkpoint(root, expected)[1], manifest)
            (checkpoint / 'database.sql').write_bytes(b'changed')
            with self.assertRaises(AssertionError):
                verify_checkpoint(root, expected)
            with self.assertRaises(AssertionError):
                verify_checkpoint(root, '0' * 64)

    def test_duplicate_archive_names_are_rejected(self):
        stream = io.BytesIO()
        with tarfile.open(fileobj=stream, mode='w') as archive:
            for _ in range(2):
                archive.addfile(tarfile.TarInfo('duplicate'))
        stream.seek(0)
        with self.assertRaises(ValueError):
            volume_inventory(stream)

    def test_top_directory_ownership_is_part_of_recovery(self):
        source = volume_inventory(archive_member(name='.', kind=tarfile.DIRTYPE))
        changed = volume_inventory(archive_member(name='.', kind=tarfile.DIRTYPE, uid=0))
        self.assertNotEqual(source['sha256'], changed['sha256'])

    def test_restore_uses_numeric_owners_in_isolated_root_utility(self):
        with patch('m4_business_recovery_guest.transfer') as transfer:
            restore_volume('owned-image', 'owned-volume', Path('volume.tar'), 'owned-label', Path('restore.log'))
        arguments = transfer.call_args.args[0]
        self.assertEqual(arguments[arguments.index('--user') + 1], '0:0')
        self.assertEqual(arguments[arguments.index('--network') + 1], 'none')
        self.assertIn('--read-only', arguments)
        self.assertIn('--numeric-owner', arguments)

    def test_database_readiness_requires_network_server(self):
        with patch('m4_business_recovery_guest.run', return_value=SimpleNamespace(returncode=0)) as command:
            await_database('owned-db')
        self.assertIn('--protocol=tcp', command.call_args.args[0][-1])

    def test_service_identity_waits_for_exec_transition(self):
        expected = Path('/restored/waf-server')
        with (patch('m4_business_recovery_guest.run', return_value=SimpleNamespace(stdout='123\n')),
                patch('m4_business_recovery_guest.Path.resolve', side_effect=[Path('/systemd-executor'), expected]),
                patch('m4_business_recovery_guest.digest', return_value='owned-hash'),
                patch('m4_business_recovery_guest.time.sleep') as sleep):
            self.assertEqual(await_executable('owned.service', expected, 'owned-hash'), 123)
        sleep.assert_called_once()

    def test_cleanup_failure_keeps_primary_diagnostics(self):
        with tempfile.TemporaryDirectory() as directory:
            lab = Lab.__new__(Lab)
            lab.out = Path(directory)
            results = [SimpleNamespace(returncode=1, stdout='', stderr='original failure'),
                       SimpleNamespace(returncode=1, stdout='', stderr='cleanup failure')]
            with patch('joint_business_lab.subprocess.run', side_effect=results):
                for _ in range(2):
                    with self.assertRaises(RuntimeError):
                        lab.run(['owned-command'])
            saved = (lab.out / 'failure.private.txt').read_text()
            self.assertLess(saved.index('original failure'), saved.index('cleanup failure'))


if __name__ == '__main__':
    unittest.main()
