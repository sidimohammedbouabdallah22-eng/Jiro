"""Fixed identity-provider fault controls for the private, owned M4 lab only."""

import argparse
import json
import os
from pathlib import Path
import re
import shlex
import subprocess
import sys
import time
import urllib.parse
import urllib.request
import uuid

OPERATIONS = ["rotate", "short-ttl", "disable", "restore", "stop", "start"]


def guest(root, operation):
    if os.getuid() != 0 or not re.fullmatch(r"/var/lib/owaf-m4-[a-f0-9]{8}", str(root)):
        raise ValueError("requires an owned lab root")
    if subprocess.check_output(["systemd-detect-virt", "--vm"], text=True).strip() != "oracle":
        raise ValueError("requires the owned VirtualBox guest")
    fixture = json.loads((root / "fixture.json").read_text())
    container = fixture["containers"]["keycloak"]
    info = json.loads(subprocess.check_output(["docker", "inspect", container]))[0]
    if info["Config"]["Labels"].get("openwaf.qualification") != fixture["tag"]:
        raise ValueError("container ownership mismatch")
    if operation == "stop":
        subprocess.run(["docker", "stop", "--time", "10", container], check=True, capture_output=True, timeout=30)
        return {"provider_stopped": True}
    if operation in ("start", "restore"):
        subprocess.run(["docker", "start", container], check=True, capture_output=True, timeout=30)
    base = fixture["idp_origin"]
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))

    def call(path, method="GET", body=None, bearer=None, form=False):
        headers = {}
        if bearer:
            headers["Authorization"] = "Bearer " + bearer
        data = None
        if body is not None:
            data = urllib.parse.urlencode(body).encode() if form else json.dumps(body).encode()
            headers["Content-Type"] = "application/x-www-form-urlencoded" if form else "application/json"
        with opener.open(urllib.request.Request(base + path, data=data, method=method, headers=headers), timeout=5) as response:
            raw = response.read(1 << 20)
            return json.loads(raw) if raw else None

    deadline = time.monotonic() + 180
    while True:
        try:
            call("/realms/openwaf-lab/.well-known/openid-configuration")
            break
        except OSError:
            if time.monotonic() >= deadline:
                raise RuntimeError("provider recovery deadline")
            time.sleep(1)
    if operation == "start":
        return {"provider_started": True}
    token = call("/realms/master/protocol/openid-connect/token", "POST", {
        "client_id": "admin-cli", "grant_type": "password", "username": "lab-admin",
        "password": fixture["password"]}, form=True)["access_token"]
    realm_path = "/admin/realms/openwaf-lab"
    representation = call(realm_path, bearer=token)
    original_path = root / "lifecycle-original.json"
    if not original_path.exists():
        original_path.write_text(json.dumps({"accessTokenLifespan": representation["accessTokenLifespan"]}))
        original_path.chmod(0o600)
    if operation == "rotate":
        before = call(realm_path + "/keys", bearer=token)["active"]["RS256"]
        components = call(realm_path + "/components?type=org.keycloak.keys.KeyProvider", bearer=token)
        if len(components) >= 32:
            raise ValueError("retained lab key component bound reached")
        priority = max(int(item.get("config", {}).get("priority", ["0"])[0]) for item in components) + 1
        call(realm_path + "/components", "POST", {
            "name": "qualification-" + uuid.uuid4().hex[:8], "parentId": representation["id"],
            "providerId": "rsa-generated", "providerType": "org.keycloak.keys.KeyProvider",
            "config": {"priority": [str(priority)], "enabled": ["true"], "active": ["true"], "algorithm": ["RS256"]}}, token)
        after = call(realm_path + "/keys", bearer=token)["active"]["RS256"]
        if before == after:
            raise ValueError("signing key did not change")
        return {"before_kid": before, "after_kid": after, "changed": True}
    if operation == "short-ttl":
        call(realm_path, "PUT", {"accessTokenLifespan": 30}, token)
        return {"token_lifespan_seconds": 30}
    if operation == "disable":
        call(realm_path + "/users/" + fixture["subject"], "PUT", {"enabled": False}, token)
        return {"provider_user_disabled": True}
    if operation == "restore":
        original = json.loads(original_path.read_text())
        call(realm_path, "PUT", original, token)
        call(realm_path + "/users/" + fixture["subject"], "PUT", {"enabled": True}, token)
        return {"provider_settings_restored": True}
    raise ValueError("unsupported operation")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("operation", choices=OPERATIONS)
    parser.add_argument("--fixture", type=Path)
    parser.add_argument("--guest", action="store_true")
    parser.add_argument("--root", type=Path)
    args = parser.parse_args()
    if args.guest:
        print(json.dumps(guest(args.root, args.operation)))
        return
    repo = Path(__file__).resolve().parents[1]
    fixture_path = args.fixture.resolve(strict=True)
    if (repo / "artifacts").resolve() not in fixture_path.parents:
        raise ValueError("requires a private qualification fixture")
    fixture = json.loads(fixture_path.read_text())
    vm = Path(fixture["vm_dir"]).resolve(strict=True)
    if vm.parent != (repo / "artifacts/m2-vms").resolve() or not re.fullmatch(r"openwaf-m2-24\.04-[a-f0-9]{8}", vm.name):
        raise ValueError("requires an owned qualification VM")
    info = subprocess.check_output([r"C:\Program Files\Oracle\VirtualBox\VBoxManage.exe", "showvminfo", vm.name, "--machinereadable"], text=True)
    port = re.search(r'Forwarding\(0\)="ssh,tcp,127\.0\.0\.1,(\d+),,22"', info)[1]
    remote = shlex.join(["sudo", "python3", "-", args.operation, "--guest", "--root", fixture["root"]])
    result = subprocess.run(["ssh", "-i", str(vm / "identity"), "-o", "BatchMode=yes", "-o", "ConnectTimeout=5",
                             "-o", "UserKnownHostsFile=" + str(vm / "known_hosts"), "-p", port,
                             "qualifier@127.0.0.1", remote], input=Path(__file__).read_text(),
                            text=True, capture_output=True, timeout=220)
    if result.returncode:
        raise RuntimeError("owned provider control failed")
    print(result.stdout.strip())


if __name__ == "__main__":
    try:
        main()
    except Exception:
        print("M4 provider control failed; inspect the owned lab state.", file=sys.stderr)
        sys.exit(1)
