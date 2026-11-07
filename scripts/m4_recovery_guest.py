"""Restore the owned operational fixture into a new deployment directory.

Run through qualify-m4-recovery.py; never prints deployment credentials.
The independent audit receiver deliberately keeps its current receipts.
"""
import json
import os
from pathlib import Path
import pwd
import re
import shutil
import sys

root = Path(sys.argv[1])
if os.geteuid() != 0 or not re.fullmatch(r"/var/lib/owaf-m2-[a-f0-9]{8}", str(root)):
    raise RuntimeError("requires an owned operational fixture and root")
sys.path.insert(0, str(root))
import guest as helper

if helper.command(["systemd-detect-virt", "--vm"]).strip() != "oracle":
    raise RuntimeError("requires the disposable VirtualBox guest")
fixture = json.loads((root / "fixture.json").read_text())
if fixture["active_version"] != "current":
    raise RuntimeError("current candidate must be running")
destination = root / "replacement"
if destination.exists():
    raise RuntimeError("replacement already exists")
expected = helper.snapshot(fixture)
helper.command(["systemctl", "stop", "openwaf.service", fixture["events_unit"]])
destination.mkdir(mode=0o755)
assets = destination / "deployment"
assets.mkdir(mode=0o750)
identity = pwd.getpwnam("openwaf")
os.chown(assets, 0, identity.pw_gid)
paths = {"admin-token": Path("/etc/openwaf/admin-token"),
         "event-token": root / "event-token", "audit-token": root / "audit-token",
         "tls/cert.pem": root / "tls/cert.pem", "tls/key.pem": root / "tls/key.pem",
         "authentication.json": root / "authentication.json"}
assets_report = {}
for name, source in paths.items():
    target = assets / name
    target.parent.mkdir(exist_ok=True, mode=0o750)
    os.chown(target.parent, 0, identity.pw_gid)
    shutil.copyfile(source, target)
    os.chown(target, 0, identity.pw_gid)
    target.chmod(0o640 if name.startswith("tls/") or name == "authentication.json" else 0o600)
    assert helper.digest(source) == helper.digest(target)
    assets_report[name] = dict(sha256=helper.digest(target), mode=oct(target.stat().st_mode & 0o777))
# Preserve service/environment definitions as private recovery evidence. The
# running replacement uses the packaged base unit and a newly rendered override.
definitions = destination / "service-definitions"
definitions.mkdir(mode=0o700)
unit_path = Path(helper.command(["systemctl", "show", "openwaf.service", "-p", "FragmentPath", "--value"]).strip())
if not unit_path.is_absolute() or not unit_path.is_file():
    raise RuntimeError("systemd did not identify the packaged service unit")
for number, source in enumerate([unit_path,
        Path("/etc/openwaf/openwaf.env"),
        Path("/etc/systemd/system/openwaf.service.d/99-m2-operational.conf"),
        *[Path("/etc/systemd/system") / name for name in fixture["units"]]]):
    if not source.is_file():
        raise RuntimeError("missing required deployment definition: " + str(source))
    target = definitions / str(number)
    shutil.copyfile(source, target)
    target.chmod(0o600)
    assert helper.digest(target) == helper.digest(source)
backup = destination / "checkpoint"
state = Path(fixture["state"])
administrator = root / "bin/current/waf-admin"
helper.command([administrator, "backup", "-config", state / "policy.json", "-event-db", state / "events.db",
                "-collector-db", fixture["receiver"], "-binary", root / "bin/current/waf-server",
                "-admin-token-file", assets / "admin-token", "-out", backup])
restored = destination / "restored"
helper.command([administrator, "restore", "-backup", backup, "-out", restored])
restored.chmod(0o755)
for path in [restored / "state", *(restored / "state").rglob("*")]:
    os.chown(path, identity.pw_uid, identity.pw_gid)
shutil.copytree(root / "bin", destination / "bin")
assert helper.digest(restored / "bin/waf-server") == helper.digest(destination / "bin/current/waf-server")
# Start the executable actually returned by restore, not the source installation.
shutil.copyfile(restored / "bin/waf-server", destination / "bin/current/waf-server")
(destination / "bin/current/waf-server").chmod(0o755)
fixture.update(deployment_assets=str(assets), binary_root=str(destination / "bin"))
helper.set_services(root, fixture, "current", restored / "state", restored / "state/collector.db")
helper.command(["systemctl", "reset-failed", "openwaf.service"])
helper.command(["systemctl", "start", fixture["events_unit"], "openwaf.service"])
helper.wait_ready(fixture, drain=True)
verified = helper.verify(fixture, expected)
pid = helper.command(["systemctl", "show", "openwaf.service", "-p", "MainPID", "--value"]).strip()
executable = Path(os.readlink(f"/proc/{pid}/exe"))
assert executable == destination / "bin/current/waf-server"
report = dict(passed=True, scope="replacement directories on the same VM, not a fresh-host restore",
              executable_sha256=helper.digest(executable), assets=assets_report,
              verification=verified, audit_receiver_retained=True,
              definitions_preserved=len(list(definitions.iterdir())))
(root / "replacement-report.json").write_text(json.dumps(report, indent=2))
print(json.dumps(report))
