"""Owned WSL2 transport for the existing business qualification workflows."""
import json
import os
from pathlib import Path
import re
import subprocess
import time

from joint_fair_lab import FairLab


def acquire_lease(path):
    lease=path.open('a+b')
    try:
        if os.name == 'nt':
            import msvcrt
            lease.seek(0,2)
            if lease.tell() == 0:
                lease.write(b'\0')
                lease.flush()
            lease.seek(0)
            msvcrt.locking(lease.fileno(),msvcrt.LK_NBLCK,1)
        else:
            import fcntl
            fcntl.flock(lease.fileno(),fcntl.LOCK_EX|fcntl.LOCK_NB)
    except OSError as error:
        lease.close()
        raise RuntimeError('another qualification holds the owned WSL2 lab lease') from error
    return lease


class WSLFairLab(FairLab):
    def __init__(self,package,sources,manifest,vcpus=4,lane_connections=64):
        manifest=manifest.resolve(strict=True)
        repo=Path(__file__).resolve().parents[1]
        assert manifest.parent.parent == repo/'artifacts'
        assert re.fullmatch(r'm4-wsl-qualification-\d{8}',manifest.parent.name)
        assert manifest.name == 'fixture.private.json'
        config=json.loads(manifest.read_text())
        assert config['fixture_prepared']
        assert re.fullmatch(r'[a-f0-9]{64}',config['snapshot_sha256'])
        assert re.fullmatch(r'Jiro-M4-\d{8}',config['distribution'])
        assert config['distribution'] == 'Jiro-M4-'+manifest.parent.name.removeprefix('m4-wsl-qualification-')
        assert re.fullmatch(r'[a-f0-9]{32}',config['lab_id'])
        assert 1024 <= config['ssh_port'] <= 65535
        assert config['ssh_user'] == 'qualifier'
        assert Path(config['identity']).resolve(strict=True) == manifest.parent/'identity'
        assert Path(config['known_hosts']).resolve(strict=True) == manifest.parent/'known_hosts'
        assert config['resources'] == dict(cpus=4,memory_bytes=4<<30)
        assert vcpus == 4
        super().__init__(package,sources,vcpus=vcpus,lane_connections=lane_connections)
        self.wsl=config
        self.lease_path=manifest.parent/'qualification.lock'
        self.lease=None
        self.keepalive=None
        self.owned=False
        self.fixture.update(lab_environment='wsl2',lab_id=config['lab_id'])
        self.report.update(lab_environment='wsl2',lab_id=config['lab_id'],
            fixture_snapshot_sha256=config['snapshot_sha256'],
            scope='one WSL2 Linux lab, bounded four-CPU/four-GiB service slice, real ERP/storefront')

    def connect(self):
        self.lease=acquire_lease(self.lease_path)
        distribution=self.wsl['distribution']
        marker=json.loads(self.run(['wsl','-d',distribution,'-u','root','--exec',
            'cat','/etc/jiro-m4-owned-lab.json']).stdout)
        assert marker == dict(lab_id=self.wsl['lab_id'],scope='owned-jiro-m4-lab')
        self.owned=True
        self.keepalive=subprocess.Popen(['wsl','-d',distribution,'-u','root','--exec','sleep','3600'],
            stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
        self.configure_ssh(self.wsl['ssh_port'],self.wsl['identity'],self.wsl['known_hosts'])
        for _ in range(90):
            if self.run([*self.ssh,'true'],check=False).returncode == 0:
                break
            time.sleep(2)
        else:
            raise RuntimeError('owned WSL2 lab SSH startup deadline exceeded')
        marker=json.loads(self.run([*self.ssh,'sudo cat /etc/jiro-m4-owned-lab.json']).stdout)
        assert marker == dict(lab_id=self.wsl['lab_id'],scope='owned-jiro-m4-lab')
        self.report['guest_logical_cpus']=int(self.run([*self.ssh,'getconf _NPROCESSORS_ONLN']).stdout)
        assert self.report['guest_logical_cpus'] >= self.vcpus
        self.report['allocated_cpus']=self.vcpus

    def create_tunnel(self, forwarding):
        # WSL2 forwards its loopback listeners directly to Windows localhost.
        return None

    def shutdown(self):
        try:
            if not self.owned:
                self.report['lab_stopped']=False
                return
            try:
                self.run(['wsl','-d',self.wsl['distribution'],'-u','root','--exec','sh','-c',
                    'systemctl stop docker.socket docker.service containerd.service && sync'],timeout=90)
            except (OSError,subprocess.TimeoutExpired,RuntimeError) as error:
                self.report['lab_shutdown_forced']=True
                self.report['lab_shutdown_error']=type(error).__name__
                self.report['passed']=False
            self.run(['wsl','--terminate',self.wsl['distribution']])
            if self.keepalive is not None:
                self.keepalive.wait(timeout=30)
            raw=subprocess.run(['wsl','--list','--running','--quiet'],capture_output=True,check=True).stdout
            listing=raw.decode('utf-16-le') if b'\x00' in raw[:100] else raw.decode('utf-8')
            running={line.strip().casefold() for line in listing.lstrip('\ufeff').splitlines() if line.strip()}
            self.report['lab_stopped']=self.wsl['distribution'].casefold() not in running
            if not self.report['lab_stopped']:
                self.report['passed']=False
            assert self.report['lab_stopped'], 'owned WSL2 lab did not stop'
        finally:
            if self.lease is not None:
                self.lease.close()
                self.lease=None
