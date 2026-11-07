"""Guest-side operational qualification helpers for an owned disposable VM."""

import argparse
import hashlib
import http.cookiejar
import json
import os
from pathlib import Path
import pwd
import re
import secrets
import shutil
import socket
import sqlite3
import subprocess
import sys
import tarfile
import time
import urllib.request


def command(arguments):
    return subprocess.check_output([str(value) for value in arguments], stderr=subprocess.STDOUT, text=True)


def digest(path):
    with Path(path).open("rb") as source:
        return hashlib.file_digest(source, "sha256").hexdigest() if hasattr(hashlib, "file_digest") else hashlib.sha256(source.read()).hexdigest()


def api(fixture, path, data=None, credential=None):
    token = credential or Path("/etc/openwaf/admin-token").read_text().strip()
    request = urllib.request.Request(
        f"http://127.0.0.1:{fixture['admin']}/api/v1/{path}",
        data=None if data is None else json.dumps(data).encode(),
        headers={"Authorization": "Bearer " + token, "Content-Type": "application/json"})
    with urllib.request.urlopen(request, timeout=15) as response:
        return json.load(response)


def wait_ready(fixture, drain=False):
    deadline = time.monotonic() + 90
    while time.monotonic() < deadline:
        try:
            health = api(fixture, "health")
            status = api(fixture, "status")
            empty = status["storage"]["export"]["pending_records"] == 0 and status["audit_export"]["pending_records"] == 0
            if health["healthy"] and (empty or not drain):
                return status
        except (OSError, ValueError):
            pass
        time.sleep(.2)
    raise RuntimeError("service did not reach the required healthy/drained state")


def save_fixture(root, fixture):
    path = root / "fixture.json"
    temporary = root / "fixture.next"
    temporary.write_text(json.dumps(fixture))
    temporary.chmod(0o600)
    temporary.replace(path)


def unpack(package, destination):
    destination.mkdir()
    with tarfile.open(package) as archive:
        for name in ["waf-server", "waf-admin", "event-collector"]:
            data = archive.extractfile("usr/lib/openwaf/" + name).read()
            target = destination / name
            target.write_bytes(data)
            target.chmod(0o755)


def set_services(root, fixture, version, state=None, receiver=None):
    state = Path(state or fixture["state"])
    receiver = Path(receiver or fixture["receiver"])
    assets = Path(fixture.get("deployment_assets", root))
    binary = Path(fixture.get("binary_root", root / "bin")) / version
    unit = Path("/etc/systemd/system/openwaf.service.d/99-m2-operational.conf")
    arguments = [str(binary / "waf-server"), f"-config={state / 'policy.json'}", f"-event-db={state / 'events.db'}",
                 "-admin-token-file=${CREDENTIALS_DIRECTORY}/admin-token", f"-admin=127.0.0.1:{fixture['admin']}",
                 f"-listen=127.0.0.1:{fixture['proxy']}", f"-tls-cert={assets / 'tls/cert.pem'}", f"-tls-key={assets / 'tls/key.pem'}",
                 "-tls-hostnames=application.test,portal.test", "-max-concurrent=64", "-max-connections=256", "-buffer-mib=256",
                 "-request-timeout=10s", f"-event-export-url=http://127.0.0.1:{fixture['collector']}/v1/events",
                 "-event-export-token-file=${CREDENTIALS_DIRECTORY}/event-token",
                 f"-audit-export-url=http://127.0.0.1:{fixture['audit_collector']}/v1/events",
                 "-audit-export-token-file=${CREDENTIALS_DIRECTORY}/audit-token"]
    if version == "current" and fixture.get("m3_origin"):
        arguments.append(f"-auth-config={assets / 'authentication.json'}")
    unit.write_text("[Unit]\nRequires=" + " ".join(fixture["units"]) + "\nAfter=" + " ".join(fixture["units"]) +
                    "\n[Service]\nLoadCredential=event-token:" + str(assets / "event-token") +
                    "\nLoadCredential=audit-token:" + str(assets / "audit-token") +
                    ("\nLoadCredential=admin-token:" + str(assets / "admin-token") if fixture.get("deployment_assets") else "") +
                    "\nExecStart=\nExecStart=" + " ".join(arguments) +
                    f"\nReadWritePaths={state}\n")
    for kind, port, database, budget in [("events", fixture["collector"], receiver, 512),
                                         ("audit", fixture["audit_collector"], Path(fixture["audit_receiver"]), 128)]:
        token = "event-token" if kind == "events" else "audit-token"
        # The independent audit receiver retains its current binary and receipts.
        executable = binary / "event-collector" if kind == "events" else root / "bin/current/event-collector"
        text = ("[Unit]\nAfter=network.target\n[Service]\nUser=openwaf\nGroup=openwaf\n"
                f"LoadCredential={token}:{assets / token}\nExecStart={executable} -listen=127.0.0.1:{port} "
                f"-db={database} -db-mib={budget} -token-file=${{CREDENTIALS_DIRECTORY}}/{token}\n"
                f"ProtectSystem=strict\nReadWritePaths={database.parent}\nNoNewPrivileges=yes\nRestart=on-failure\n"
                "[Install]\nWantedBy=multi-user.target\n")
        Path(f"/etc/systemd/system/{fixture[kind + '_unit']}").write_text(text)
    fixture.update(active_version=version, state=str(state), receiver=str(receiver))
    save_fixture(root, fixture)
    command(["systemctl", "daemon-reload"])


def setup(root, current, previous):
    if root.exists():
        raise RuntimeError("operational fixture already exists")
    override = Path("/etc/systemd/system/openwaf.service.d/99-m2-operational.conf")
    if override.exists():
        match = re.search(r"-config=(/var/lib/owaf-m2-[a-f0-9]{8})/", override.read_text())
        if not match:
            raise RuntimeError("existing override is outside the owned qualification fixture")
        old_root = Path(match[1])
        old = json.loads((old_root / "fixture.json").read_text())
        if not all(re.fullmatch(r"openwaf-m2-(backend|events|audit)-[a-f0-9]{8}\.service", unit) for unit in old["units"]):
            raise RuntimeError("existing fixture has unexpected service identities")
        command(["systemctl", "stop", "openwaf.service", *old["units"]])
        command(["systemctl", "disable", *old["units"]])
        archive = override.with_name("98-m2-archived-" + old_root.name.rsplit("-", 1)[1] + ".disabled")
        if archive.exists():
            raise RuntimeError("archived fixture override already exists")
        override.rename(archive)
    root.mkdir(mode=0o755)
    (root / "bin").mkdir()
    unpack(current, root / "bin/current")
    unpack(previous, root / "bin/previous")
    (root / "guest.py").write_bytes(Path(__file__).read_bytes())
    (root / "guest.py").chmod(0o600)
    identity = pwd.getpwnam("openwaf")
    for name in ["state", "collector", "audit"]:
        path = root / name
        path.mkdir(mode=0o700)
        os.chown(path, identity.pw_uid, identity.pw_gid)
    (root / "tls").mkdir(mode=0o750)
    os.chown(root / "tls", 0, identity.pw_gid)
    command(["openssl", "req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-256", "-nodes",
             "-days", "90", "-subj", "/CN=application.test", "-addext", "subjectAltName=DNS:application.test,DNS:portal.test",
             "-addext", "basicConstraints=critical,CA:FALSE", "-addext", "extendedKeyUsage=serverAuth", "-addext", "keyUsage=digitalSignature",
             "-keyout", root / "tls/key.pem", "-out", root / "tls/cert.pem"])
    for name in ["cert.pem", "key.pem"]:
        os.chown(root / "tls" / name, 0, identity.pw_gid)
        (root / "tls" / name).chmod(0o640)
    for name in ["event-token", "audit-token"]:
        (root / name).write_text(secrets.token_hex(32))
        (root / name).chmod(0o600)
    listeners = [socket.socket() for _ in range(5)]
    for listener in listeners:
        listener.bind(("127.0.0.1", 0))
    ports = [listener.getsockname()[1] for listener in listeners]
    for listener in listeners:
        listener.close()
    tag = root.name.rsplit("-", 1)[1]
    fixture = dict(zip(["admin", "proxy", "backend", "collector", "audit_collector"], ports))
    fixture.update(state=str(root / "state"), receiver=str(root / "collector/events.db"),
                   audit_receiver=str(root / "audit/events.db"), events_unit=f"openwaf-m2-events-{tag}.service",
                   audit_unit=f"openwaf-m2-audit-{tag}.service", backend_unit=f"openwaf-m2-backend-{tag}.service",
                   password=secrets.token_urlsafe(32))
    fixture["units"] = [fixture["backend_unit"], fixture["events_unit"], fixture["audit_unit"]]
    (root / "backend.py").write_text("""import http.server

class Handler(http.server.BaseHTTPRequestHandler):
    protocol_version = 'HTTP/1.1'

    def do_GET(self):
        self.rfile.read(int(self.headers.get('Content-Length', 0)))
        self.send_response(200)
        self.send_header('Content-Length', '10')
        self.end_headers()
        self.wfile.write(b'backend-ok')

    do_POST = do_GET

    def log_message(self, *args):
        pass

""" + f"http.server.ThreadingHTTPServer(('127.0.0.1', {fixture['backend']}), Handler).serve_forever()\n")
    Path(f"/etc/systemd/system/{fixture['backend_unit']}").write_text(
        f"[Service]\nDynamicUser=yes\nExecStart=/usr/bin/python3 {root / 'backend.py'}\nRestart=on-failure\n"
        "[Install]\nWantedBy=multi-user.target\n")
    policy = dict(mode="enforcing", paranoia=1, inbound_threshold=5, outbound_threshold=4, request_limit=1048576,
                  response_limit=1048576, inspect_response=False, exclusions=[], custom_rules="", scoped_exceptions=[])
    applications = [dict(application_id=f"qa-{index}", name=f"Application {index}", hosts=[host],
                         upstream=f"http://127.0.0.1:{fixture['backend']}", policy=policy.copy())
                    for index, host in enumerate(["application.test", "portal.test"])]
    path = root / "state/policy.json"
    path.write_text(json.dumps(dict(schema_version=2, revision=1, applications=applications)))
    os.chown(path, identity.pw_uid, identity.pw_gid)
    path.chmod(0o600)
    command(["systemctl", "stop", "openwaf.service"])
    set_services(root, fixture, "current")
    command(["systemctl", "enable", *fixture["units"], "openwaf.service"])
    # Establish a durable fixture before creating any acknowledged workload state.
    # No global synchronization is performed between workload ACKs and power cuts.
    command(["sync"])
    command(["systemctl", "start", *fixture["units"], "openwaf.service"])
    wait_ready(fixture)
    for username, role in [("qa-admin", "administrator"), ("qa-viewer", "viewer")]:
        directory = api(fixture, "accounts")
        api(fixture, "accounts", dict(revision=directory["revision"], username=username, role=role, disabled=False,
                                      password=fixture["password"], reason="Operational qualification account"))
    return dict(admin=fixture["admin"], proxy=fixture["proxy"], state=fixture["state"],
                current_sha256=digest(root / "bin/current/waf-server"), previous_sha256=digest(root / "bin/previous/waf-server"))


def sample(fixture):
    pid = int(command(["systemctl", "show", "openwaf.service", "-p", "MainPID", "--value"]).strip())
    fields = Path(f"/proc/{pid}/stat").read_text().rsplit(")", 1)[1].split()
    status = dict(line.split(":", 1) for line in Path(f"/proc/{pid}/status").read_text().splitlines() if ":" in line)
    process = dict(pid=pid, start_ticks=int(fields[19]), cpu_seconds=(int(fields[11]) + int(fields[12])) / os.sysconf("SC_CLK_TCK"),
                   rss_bytes=int(status["VmRSS"].split()[0]) * 1024, peak_rss_bytes=int(status["VmHWM"].split()[0]) * 1024,
                   threads=int(status["Threads"]), descriptors=len(list(Path(f"/proc/{pid}/fd").iterdir())))
    return dict(process=process, status=api(fixture, "status"), health=api(fixture, "health"))


def snapshot(fixture):
    wait_ready(fixture, drain=True)
    state = Path(fixture["state"])
    with sqlite3.connect(f"file:{state / 'events.db'}?mode=ro", uri=True) as db:
        events = [dict(id=row[0], sha256=hashlib.sha256(row[1]).hexdigest()) for row in db.execute("SELECT id,data FROM events ORDER BY seq DESC LIMIT 100")]
    audit = [json.loads(line) for line in (state / "policy.json.audit.jsonl").read_text().splitlines()]
    pid = command(["systemctl", "show", "openwaf.service", "-p", "MainPID", "--value"]).strip()
    return dict(policy=api(fixture, "config"), events=events, audit=audit, executable_sha256=digest(f"/proc/{pid}/exe"),
                accounts_sha256=digest(state / "policy.json.accounts.json"), status=api(fixture, "status"))


def verify(fixture, expected):
    actual = snapshot(fixture)
    assert actual["policy"]["revision"] >= expected["policy"]["revision"]
    assert actual["accounts_sha256"] == expected["accounts_sha256"]
    state = Path(fixture["state"])
    with sqlite3.connect(f"file:{state / 'events.db'}?mode=ro", uri=True) as db, sqlite3.connect(f"file:{fixture['receiver']}?mode=ro", uri=True) as receiver:
        assert db.execute("PRAGMA quick_check").fetchone()[0] == "ok"
        source = actual["status"]["storage"]["export"]["source_id"]
        for event in expected["events"]:
            data = db.execute("SELECT data FROM events WHERE id=?", (event["id"],)).fetchone()
            assert data and hashlib.sha256(data[0]).hexdigest() == event["sha256"]
            remote = receiver.execute("SELECT data FROM collected_events WHERE source_id=? AND id=?", (source, event["id"])).fetchone()
            assert remote and remote[0] == data[0]
    local = {record["id"]: record for record in actual["audit"]}
    audit_source = expected["audit"][0]["hash"][:32]
    with sqlite3.connect(f"file:{fixture['audit_receiver']}?mode=ro", uri=True) as db:
        for record in expected["audit"]:
            assert local.get(record["id"]) == record
            remote = db.execute("SELECT data FROM collected_events WHERE source_id=? AND id=?", (audit_source, record["id"])).fetchone()
            assert remote and json.loads(remote[0]) == record
    return dict(verified_events=len(expected["events"]), verified_audit_records=len(expected["audit"]), revision=actual["policy"]["revision"])


def change(fixture, label):
    config = api(fixture, "config")
    config["applications"][0]["name"] = label
    return api(fixture, "config/apply", dict(config=config, reason="Operational qualification policy activation"))


def activate_m3(root, fixture, origin):
    if not re.fullmatch(r"http://localhost:[0-9]{1,5}", origin):
        raise ValueError("requires a loopback browser origin")
    listener = socket.socket()
    listener.bind(("127.0.0.1", 0))
    port = listener.getsockname()[1]
    listener.close()
    backend = root / "backend.py"
    original = backend.read_text()
    if "import threading" in original:
        raise ValueError("M3 already activated")
    original = original.replace("import http.server", "import http.server\nimport threading")
    original = original.replace("http.server.ThreadingHTTPServer(('127.0.0.1', " + str(fixture["backend"]),
        f"threading.Thread(target=http.server.ThreadingHTTPServer(('127.0.0.1', {port}), Handler).serve_forever, daemon=True).start()\nhttp.server.ThreadingHTTPServer(('127.0.0.1', " + str(fixture["backend"]))
    backend.write_text(original)
    command(["systemctl", "stop", "openwaf.service"])
    command(["systemctl", "restart", fixture["backend_unit"]])
    command(["systemctl", "start", "openwaf.service"])
    wait_ready(fixture)
    config = api(fixture, "config")
    for application in config["applications"]:
        application["upstream_pool"] = dict(backends=[dict(id="primary", url=application["upstream"]),
            dict(id="secondary", url=f"http://127.0.0.1:{port}")], failure_threshold=2, cooldown_seconds=5, header_timeout_seconds=2)
    api(fixture, "config/apply", dict(config=config, reason="M3 multi-backend qualification"))
    # Deliberately unreachable provider proves startup and local auth independence.
    authentication = dict(origin=origin, passkey_rp_id="localhost", oidc=dict(issuer="https://issuer.invalid", client_id="native-fixture", required_acr="fixture-mfa"))
    path = root / "authentication.json"
    path.write_text(json.dumps(authentication))
    path.chmod(0o640)
    os.chown(path, 0, pwd.getpwnam("openwaf").pw_gid)
    fixture["m3_origin"] = origin
    command(["systemctl", "stop", "openwaf.service"])
    set_services(root, fixture, "current")
    # This fixture deliberately performs several clean activations within seconds.
    # Clear their accumulated start count without altering the packaged unit limit.
    command(["systemctl", "reset-failed", "openwaf.service"])
    command(["systemctl", "start", "openwaf.service"])
    wait_ready(fixture)
    directory = api(fixture, "accounts")
    api(fixture, "accounts/oidc", dict(revision=directory["revision"], username="qa-viewer", subject="native-viewer", reason="M3 binding persistence"))
    directory = api(fixture, "accounts")
    api(fixture, "accounts", dict(revision=directory["revision"], username="qa-viewer", role="viewer", disabled=False,
        password="", access=dict(application_ids=["qa-0"]), reason="M3 application assignment"))
    directory = api(fixture, "accounts")
    issued = api(fixture, "tokens", dict(revision=directory["revision"], owner="qa-viewer", name="Native scoped reader",
        scopes=["policy:read"], lifetime_hours=24, reason="M3 persistent scoped automation"))
    fixture["automation_token"] = issued["secret"]
    save_fixture(root, fixture)
    return dict(pools=True, provider_unavailable=True, origin=origin)


def check_m3(fixture):
    config = api(fixture, "config", credential=fixture["automation_token"])
    assert [app["application_id"] for app in config["applications"]] == ["qa-0"]
    try:
        api(fixture, "audit", credential=fixture["automation_token"])
        raise AssertionError("automation escaped scope")
    except urllib.error.HTTPError as error:
        assert error.code == 403
    pools = api(fixture, "upstreams")
    assert len(pools["applications"]) == 2
    for pool in pools["applications"]:
        assert len(pool["backends"]) == 2
        assert all(backend["state"] == "observed_healthy" for backend in pool["backends"])
    return dict(scoped_token=True, assignment_isolated=True)


def upgrade(root, fixture, stage):
    administrator = root / "bin/current/waf-admin"
    checkpoint = root / "checkpoint"
    if stage == "previous":
        wait_ready(fixture, drain=True)
        command(["systemctl", "stop", "openwaf.service", fixture["events_unit"]])
        set_services(root, fixture, "previous")
        command(["systemctl", "start", fixture["events_unit"], "openwaf.service"])
        wait_ready(fixture)
        change(fixture, "Previous binary qualified")
        return snapshot(fixture)
    wait_ready(fixture, drain=True)
    command(["systemctl", "stop", "openwaf.service", fixture["events_unit"]])
    if stage == "current":
        backup = command([administrator, "backup", "-config", Path(fixture["state"]) / "policy.json", "-event-db", Path(fixture["state"]) / "events.db",
                          "-collector-db", fixture["receiver"], "-binary", root / "bin/previous/waf-server", "-out", checkpoint])
        (root / "backup-report.json").write_text(backup)
        rehearsal = command([administrator, "upgrade-check", "-backup", checkpoint, "-candidate", root / "bin/current/waf-server"])
        (root / "upgrade-report.json").write_text(rehearsal)
        fixture["checkpoint_manifest_sha256"] = digest(checkpoint / "manifest.json")
        set_services(root, fixture, "current")
    elif stage == "rollback":
        # Preserve the newer timeline before the explicit recovery-point switch.
        command([administrator, "backup", "-config", Path(fixture["state"]) / "policy.json", "-event-db", Path(fixture["state"]) / "events.db",
                 "-collector-db", fixture["receiver"], "-binary", root / "bin/current/waf-server", "-out", root / "post-upgrade"])
        rollback = root / "rollback"
        report = command([administrator, "rollback", "-backup", checkpoint, "-out", rollback])
        (root / "rollback-report.json").write_text(report)
        assert digest(rollback / "bin/waf-server") == digest(root / "bin/previous/waf-server")
        identity = pwd.getpwnam("openwaf")
        rollback.chmod(0o755)
        for path in [rollback / "state", *(rollback / "state").rglob("*")]:
            os.chown(path, identity.pw_uid, identity.pw_gid)
        set_services(root, fixture, "previous", rollback / "state", rollback / "state/collector.db")
        assert digest(checkpoint / "manifest.json") == fixture["checkpoint_manifest_sha256"]
    command(["systemctl", "start", fixture["events_unit"], "openwaf.service"])
    wait_ready(fixture)
    pid = command(["systemctl", "show", "openwaf.service", "-p", "MainPID", "--value"]).strip()
    running = digest(f"/proc/{pid}/exe")
    assert running == digest(root / f"bin/{fixture['active_version']}/waf-server")
    return dict(version=fixture["active_version"], executable_sha256=running,
                checkpoint_manifest_sha256=fixture["checkpoint_manifest_sha256"])


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("operation", choices=["setup", "sample", "snapshot", "verify", "change", "arm", "disarm", "journal", "upgrade", "login", "stop", "m3", "m3-check"])
    parser.add_argument("--root", required=True, type=Path)
    parser.add_argument("--current")
    parser.add_argument("--previous")
    parser.add_argument("--label", default="Qualification change")
    parser.add_argument("--origin")
    parser.add_argument("--stage", choices=["previous", "current", "rollback"])
    parser.add_argument("--disposable-vm", required=True, action="store_true")
    args = parser.parse_args()
    if os.geteuid() != 0 or command(["systemd-detect-virt", "--vm"]).strip() != "oracle" or not re.fullmatch(r"/var/lib/owaf-m2-[a-f0-9]{8}", str(args.root)):
        raise RuntimeError("requires root in an owned disposable VirtualBox guest")
    if args.operation == "setup":
        result = setup(args.root, args.current, args.previous)
    else:
        fixture = json.loads((args.root / "fixture.json").read_text())
        if args.operation == "sample":
            result = sample(fixture)
        elif args.operation == "snapshot":
            result = snapshot(fixture)
        elif args.operation == "verify":
            result = verify(fixture, json.load(sys.stdin))
        elif args.operation == "change":
            result = change(fixture, args.label)
        elif args.operation == "m3":
            result = activate_m3(args.root, fixture, args.origin)
        elif args.operation == "m3-check":
            result = check_m3(fixture)
        elif args.operation in ["arm", "disarm"]:
            with sqlite3.connect(Path(fixture["state"]) / "events.db", timeout=10) as db:
                db.execute("DROP TRIGGER IF EXISTS m2_inflight")
                if args.operation == "arm":
                    db.execute("CREATE TRIGGER m2_inflight AFTER INSERT ON events BEGIN SELECT sum(x) FROM (WITH RECURSIVE n(x) AS (VALUES(0) UNION ALL SELECT x+1 FROM n WHERE x<1000000000) SELECT x FROM n); END")
            result = dict(armed=args.operation == "arm")
        elif args.operation == "journal":
            path = Path(fixture["state"]) / "events.db-journal"
            result = dict(active=path.exists() and path.stat().st_size > 0)
        elif args.operation == "upgrade":
            result = upgrade(args.root, fixture, args.stage)
        elif args.operation == "login":
            jar = http.cookiejar.CookieJar()
            opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(jar))
            request = urllib.request.Request(f"http://127.0.0.1:{fixture['admin']}/api/v1/login",
                data=json.dumps(dict(username="qa-viewer", password=fixture["password"])).encode(), headers={"Content-Type": "application/json"})
            with opener.open(request) as response:
                assert response.status == 200
            result = dict(viewer_login=True)
        elif args.operation == "stop":
            command(["systemctl", "stop", "openwaf.service", *fixture["units"]])
            result = dict(stopped=True)
    print(json.dumps(result), flush=True)


if __name__ == "__main__":
    main()
