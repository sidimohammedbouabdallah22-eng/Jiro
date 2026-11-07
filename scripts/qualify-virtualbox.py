"""Run fresh-install qualification in a new, disposable VirtualBox guest.

Requires pycdlib, OpenSSH, VirtualBox and a downloaded Ubuntu VMDK with its
official SHA256SUMS. Guest disks and private SSH credentials stay in artifacts.
"""

import argparse
import hashlib
import importlib.util
import json
from pathlib import Path
import shlex
import socket
import shutil
import subprocess
import time
import uuid

import pycdlib


def run():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--release", choices=["22.04", "24.04"], required=True)
    parser.add_argument("--image", type=Path, required=True)
    parser.add_argument("--checksums", type=Path, required=True)
    parser.add_argument("--package", type=Path, required=True)
    parser.add_argument("--disposable-vm", action="store_true", required=True)
    parser.add_argument("--cpus", type=int, choices=[1, 2], default=1)
    parser.add_argument("--prepare-only", action="store_true", help="Prepare a clean OS only; does not pass fresh-install qualification")
    parser.add_argument("--vbox", default=r"C:\Program Files\Oracle\VirtualBox\VBoxManage.exe")
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[1]
    image = args.image.resolve(strict=True)
    package = args.package.resolve(strict=True)
    if hashlib.sha256(package.read_bytes()).hexdigest()!=Path(str(package)+'.sha256').read_text().split()[0]:
        raise RuntimeError('package checksum mismatch')
    if shutil.disk_usage(root/'artifacts').free<8<<30:
        raise RuntimeError('new VM preparation requires at least 8 GiB free host storage')
    filename = f"ubuntu-{args.release}-server-cloudimg-amd64.vmdk"
    expected = next(line.split()[0] for line in args.checksums.read_text().splitlines()
                    if line.split()[-1].lstrip("*") == filename)
    with image.open("rb") as source:
        actual = hashlib.file_digest(source, "sha256").hexdigest()
    if actual != expected:
        raise RuntimeError("Ubuntu image checksum mismatch")
    name = f"openwaf-m2-{args.release}-{uuid.uuid4().hex[:8]}"
    stage = root / "artifacts" / "m2-vms" / name
    stage.mkdir(parents=True)
    spec=importlib.util.spec_from_file_location('qualification_permissions',root/'scripts/qualify-applications.py')
    permissions=importlib.util.module_from_spec(spec);spec.loader.exec_module(permissions)
    permissions.restrict_artifacts(stage)
    (stage/'provisioner.py').write_bytes(Path(__file__).read_bytes())
    log = (stage / "qualification.log").open("w", encoding="utf-8", buffering=1)

    def command(arguments, timeout=180, check=True):
        result = subprocess.run([str(value) for value in arguments], stdout=log,
                                stderr=subprocess.STDOUT, timeout=timeout)
        if check and result.returncode:
            raise RuntimeError(f"{Path(arguments[0]).name} failed, see {stage / 'qualification.log'}")
        return result.returncode

    def vbox(*arguments, **kwargs):
        return command([args.vbox, *arguments], **kwargs)

    with socket.socket() as listener:
        listener.bind(("127.0.0.1", 0))
        port = listener.getsockname()[1]
    key = stage / "identity"
    command(["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", key])
    public = key.with_suffix(".pub").read_text().strip()
    (stage / "user-data").write_text(
        "#cloud-config\n"
        f"hostname: {name}\n"
        "users:\n  - name: qualifier\n    shell: /bin/bash\n"
        "    sudo: ALL=(ALL) NOPASSWD:ALL\n    lock_passwd: true\n"
        f"    ssh_authorized_keys:\n      - {public}\n"
        "ssh_pwauth: false\ndisable_root: true\n", encoding="utf-8")
    (stage / "meta-data").write_text(f"instance-id: {name}\n", encoding="utf-8")
    iso = pycdlib.PyCdlib()
    iso.new(interchange_level=3, joliet=3, rock_ridge="1.09", vol_ident="cidata")
    for source, iso_name in [("user-data", "USERDATA.;1"), ("meta-data", "METADATA.;1")]:
        iso.add_file(str(stage / source), iso_path="/" + iso_name,
                     rr_name=source, joliet_path="/" + source)
    iso.write(str(stage / "seed.iso"))
    iso.close()
    registered = False
    started = False
    report = dict(vm=name, release=args.release, architecture="amd64", image_sha256=actual,
                  package_sha256=hashlib.sha256(package.read_bytes()).hexdigest(), cpus=args.cpus,
                  script_sha256=hashlib.sha256((root / "scripts" / "qualify-fresh-vm.sh").read_bytes()).hexdigest(),
                  service_script_sha256=hashlib.sha256((root / "scripts" / "qualify-linux-service.sh").read_bytes()).hexdigest(),
                  passed=False,prepared=False,qualification_performed=not args.prepare_only,
                  memory_mib=2048,provisioner_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest())
    try:
        vbox("createvm", "--name", name, "--ostype", "Ubuntu_64", "--basefolder", stage, "--register")
        registered = True
        # A private copy avoids VirtualBox assigning a transient UUID to the
        # shared cloud image and making later runs conflict with its registry.
        source_copy = stage / "source.vmdk"
        shutil.copyfile(image, source_copy)
        vbox("clonemedium", "disk", source_copy, stage / "system.vdi", "--format", "VDI")
        vbox("closemedium", "disk", source_copy)
        vbox("modifymedium", "disk", stage / "system.vdi", "--resize", "12288")
        vbox("modifyvm", name, "--memory", "2048", "--cpus", str(args.cpus), "--nic1", "nat",
             "--natpf1", f"ssh,tcp,127.0.0.1,{port},,22", "--audio-enabled", "off",
             "--uart1", "0x3F8", "4", "--uartmode1", "file", stage / "serial.log")
        vbox("storagectl", name, "--name", "SATA", "--add", "sata", "--controller", "IntelAhci")
        vbox("storageattach", name, "--storagectl", "SATA", "--port", "0", "--device", "0",
             "--type", "hdd", "--medium", stage / "system.vdi")
        vbox("storageattach", name, "--storagectl", "SATA", "--port", "1", "--device", "0",
             "--type", "dvddrive", "--medium", stage / "seed.iso")
        vbox("startvm", name, "--type", "headless")
        started = True
        ssh_options = ["-i", str(key), "-o", "BatchMode=yes", "-o", "ConnectTimeout=5",
                       "-o", "StrictHostKeyChecking=accept-new", "-o", f"UserKnownHostsFile={stage / 'known_hosts'}"]
        ssh = ["ssh", *ssh_options, "-p", str(port), "qualifier@127.0.0.1"]
        deadline = time.monotonic() + 600
        while time.monotonic() < deadline:
            if command([*ssh, "true"], timeout=15, check=False) == 0:
                break
            time.sleep(5)
        else:
            raise RuntimeError("Guest SSH did not become available within ten minutes")
        command([*ssh, "sudo cloud-init status --wait && uname -a && cat /etc/os-release && systemd-detect-virt && systemctl --version && findmnt -no OPTIONS /run"], timeout=300)
        scp = ["scp", *ssh_options, "-P", str(port)]
        command([*scp, package, root / "scripts" / "qualify-fresh-vm.sh",
                 root / "scripts" / "qualify-linux-service.sh", "qualifier@127.0.0.1:/tmp/"], timeout=300)
        guest_package = shlex.quote(f"/tmp/{package.name}")
        if args.prepare_only:
            command([*ssh,"sudo python3 -c \"import os,pwd,subprocess; paths=['/etc/openwaf','/var/lib/openwaf','/usr/lib/openwaf']; assert not any(os.path.lexists(p) for p in paths); assert subprocess.run(['getent','passwd','openwaf'],stdout=subprocess.DEVNULL).returncode!=0; assert subprocess.run(['systemctl','cat','openwaf.service'],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL).returncode!=0; print('Clean OS preconditions passed')\""])
            report['prepared']=True
        else:
            command([*ssh, f"sudo bash /tmp/qualify-fresh-vm.sh {guest_package} --disposable-vm"], timeout=600)
            command([*ssh, f"sudo bash /tmp/qualify-linux-service.sh {guest_package}"], timeout=600)
            report["passed"] = True
    finally:
        if started:
            try:
                command(["ssh", "-i", key, "-o", "BatchMode=yes", "-o", "ConnectTimeout=5",
                         "-o", f"UserKnownHostsFile={stage / 'known_hosts'}", "-p", str(port),
                         "qualifier@127.0.0.1", "sudo poweroff"], check=False, timeout=20)
            except subprocess.TimeoutExpired:
                pass
            time.sleep(5)
        if registered:
            state = subprocess.run([args.vbox, "showvminfo", name, "--machinereadable"],
                                   capture_output=True, text=True, timeout=30)
            log.write(state.stdout)
            if 'VMState="poweroff"' not in state.stdout:
                vbox("controlvm", name, "poweroff", check=False)
        (stage / "result.json").write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
        log.close()
        print(stage / "result.json", flush=True)


if __name__ == "__main__":
    run()
