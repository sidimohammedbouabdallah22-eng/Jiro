"""Environment and resource boundaries for the owned Linux qualification lab."""
import json
from pathlib import Path
import re
import subprocess


OWNERSHIP_MARKER = Path('/etc/jiro-m4-owned-lab.json')
ALLOCATION = Path('/sys/fs/cgroup/jiro.slice/jiro-m4.slice')


def environment(fixture=None):
    detected = subprocess.check_output(['systemd-detect-virt'], text=True).strip()
    if detected == 'oracle':
        assert not fixture or fixture.get('lab_environment', 'virtualbox') == 'virtualbox'
        return 'virtualbox'
    assert detected == 'wsl', 'requires the owned VirtualBox or dedicated WSL2 lab'
    marker = json.loads(OWNERSHIP_MARKER.read_text())
    assert marker['scope'] == 'owned-jiro-m4-lab'
    assert re.fullmatch(r'[a-f0-9]{32}', marker['lab_id'])
    if fixture is not None:
        assert fixture.get('lab_environment') == 'wsl2'
        assert fixture.get('lab_id') == marker['lab_id']
    return 'wsl2'


def allocation():
    cpu_max = (ALLOCATION/'cpu.max').read_text().strip()
    memory_max = int((ALLOCATION/'memory.max').read_text())
    cpuset = (ALLOCATION/'cpuset.cpus.effective').read_text().strip()
    assert cpu_max == '400000 100000'
    assert memory_max == 4 << 30
    assert cpuset == '0-3'
    return dict(slice='jiro-m4.slice', cpu_max=cpu_max,
                memory_max=memory_max, cpuset=cpuset, allocated_cpus=4)


def allocation_sample():
    result = allocation()
    cpu = dict(line.split() for line in (ALLOCATION/'cpu.stat').read_text().splitlines())
    events = dict(line.split() for line in (ALLOCATION/'memory.events').read_text().splitlines())
    result.update(cpu_usage_usec=int(cpu['usage_usec']),
                  memory_current=int((ALLOCATION/'memory.current').read_text()),
                  oom_kill=int(events['oom_kill']))
    return result
