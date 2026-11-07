"""Bounded pilot evidence collector. This does not certify a deployment for production."""

import argparse
from contextlib import closing
from datetime import datetime, timedelta, timezone
import hashlib
import json
import math
import multiprocessing
import os
from pathlib import Path
import re
import sqlite3
import sys
import time
import urllib.error
import urllib.parse
import urllib.request

DAY = 86400
MAX_GAP = 180
MAX_BODY = 1 << 20
METRICS = {
    "openwaf_requests_total", "openwaf_blocked_requests_total",
    "openwaf_gateway_errors_total", "openwaf_overload_requests_total",
    "openwaf_event_persistence_errors_total", "openwaf_event_queue_dropped_total",
    "openwaf_event_write_failed_total", "openwaf_event_ingest_timeouts_total",
    "openwaf_event_export_pending_records", "openwaf_audit_export_pending_records",
    "openwaf_policy_revision",
}


def utc_day(timestamp):
    return datetime.fromtimestamp(timestamp, timezone.utc).date().isoformat()


def digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def url(value):
    parsed = urllib.parse.urlsplit(value)
    if (parsed.scheme not in ("http", "https") or not parsed.hostname or
            parsed.username or parsed.password or parsed.fragment or parsed.query):
        raise ValueError("use an HTTP(S) URL without credentials, query or fragment")
    if parsed.scheme == "http" and parsed.hostname not in ("localhost", "127.0.0.1", "::1"):
        raise ValueError("HTTP is permitted only on loopback; remote probes require HTTPS")
    return value.rstrip("/")


def load_manifest(path):
    config = json.loads(path.read_text(encoding="utf-8"))
    required = {"schema", "pilot_id", "owner", "host", "qualification_evidence",
                "capacity_evidence", "management_url", "token_file", "canaries"}
    if set(config) - required - {"oidc_issuer"} or required - set(config) or config["schema"] != 1:
        raise ValueError("invalid pilot manifest schema")
    for name in ("pilot_id", "owner", "host", "qualification_evidence", "capacity_evidence"):
        value = config[name]
        if not isinstance(value, str) or not value.strip() or len(value) > 500 or "REPLACE" in value:
            raise ValueError("supply a concrete " + name)
    url(config["management_url"])
    if config.get("oidc_issuer"):
        url(config["oidc_issuer"])
    credential = Path(config["token_file"])
    if not credential.is_absolute():
        raise ValueError("token_file must be an absolute path to a restricted monitoring credential")
    canaries = config["canaries"]
    if not isinstance(canaries, list) or not 1 <= len(canaries) <= 8:
        raise ValueError("supply 1..8 representative business canaries")
    names = set()
    for item in canaries:
        if set(item) != {"name", "url", "status", "sha256"}:
            raise ValueError("canaries require name, url, status and expected body sha256")
        if not re.fullmatch(r"[a-z0-9_-]{1,64}", item["name"]) or item["name"] in names:
            raise ValueError("canary names must be unique safe identifiers")
        names.add(item["name"])
        url(item["url"])
        if type(item["status"]) is not int or not 200 <= item["status"] < 300:
            raise ValueError("business canaries must expect a successful response")
        if not re.fullmatch(r"[a-f0-9]{64}", item["sha256"]):
            raise ValueError("canaries require a reviewed expected SHA-256 body digest")
    return config


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        return None


def get(target, token=None):
    """No proxy environment, redirects or credentials forwarded to other origins."""
    headers = {"Accept": "application/json, text/plain, */*", "User-Agent": "OpenWAF-pilot/1"}
    if token:
        headers["Authorization"] = "Bearer " + token
    request = urllib.request.Request(target, headers=headers)
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect())
    try:
        with opener.open(request, timeout=3) as response:
            body = response.read(MAX_BODY + 1)
            if len(body) > MAX_BODY:
                raise ValueError("probe body limit exceeded")
            return response.status, body
    except urllib.error.HTTPError as error:
        # Never retain error pages, URLs, cookies or authorization data.
        error.close()
        return error.code, b""


def probe(config):
    token_path = Path(config["token_file"])
    if os.name != "nt" and token_path.stat().st_mode & 0o077:
        raise ValueError("monitoring token file must deny group and other access")
    if token_path.stat().st_size > 4096:
        raise ValueError("monitoring credential exceeds its bound")
    token = token_path.read_text(encoding="utf-8").strip()
    if not token or any(char.isspace() for char in token):
        raise ValueError("invalid monitoring credential")
    detail = {"checks": {}, "metrics": {}}
    base = config["management_url"].rstrip("/")

    def check(name, operation):
        started = time.monotonic()
        try:
            ok = bool(operation())
            detail["checks"][name] = {"ok": ok}
        except Exception:
            detail["checks"][name] = {"ok": False}
        detail["checks"][name]["duration_ms"] = round((time.monotonic() - started) * 1000)

    def identity():
        status, body = get(base + "/api/v1/me", token)
        value = json.loads(body)
        return (status == 200 and bool(value.get("automation_id")) and not value.get("bootstrap")
                and value.get("scopes") == ["monitoring:read"])

    def health():
        status, body = get(base + "/api/v1/health", token)
        value = json.loads(body)
        revision = value.get("revision")
        if type(revision) is not int or revision < 1:
            return False
        detail["revision"] = revision
        return (status == 200 and value.get("ready") is True and value.get("healthy") is True
                and value.get("mode") == "enforcing" and bool(value.get("checks"))
                and all(item is True for item in value["checks"].values()))

    def metrics():
        status, body = get(base + "/api/v1/metrics", token)
        for line in body.decode("utf-8").splitlines():
            fields = line.split()
            if len(fields) == 2 and fields[0] in METRICS:
                number = float(fields[1])
                if not math.isfinite(number) or number < 0:
                    return False
                detail["metrics"][fields[0]] = number
        return status == 200 and "openwaf_requests_total" in detail["metrics"]

    check("monitoring_credential", identity)
    check("gateway_health", health)
    check("metrics", metrics)
    for item in config["canaries"]:
        def canary(item=item):
            status, body = get(item["url"])
            return status == item["status"] and hashlib.sha256(body).hexdigest() == item["sha256"]
        check("canary_" + item["name"], canary)
    if config.get("oidc_issuer"):
        def provider():
            status, body = get(config["oidc_issuer"].rstrip("/") + "/.well-known/openid-configuration")
            return status == 200 and json.loads(body).get("issuer") == config["oidc_issuer"]
        check("identity_provider", provider)
    return all(value["ok"] for value in detail["checks"].values()), detail


def probe_worker(config, sender):
    try:
        sender.send(probe(config))
    except Exception:
        sender.send((False, {"checks": {"collector_configuration": {"ok": False}}}))
    finally:
        sender.close()


def bounded_probe(config, timeout=45):
    """Supervise DNS, slow headers and trickled bodies with an overall deadline."""
    context = multiprocessing.get_context("spawn")
    receiver, sender = context.Pipe(duplex=False)
    worker = context.Process(target=probe_worker, args=(config, sender), daemon=True)
    worker.start()
    sender.close()
    try:
        if receiver.poll(timeout):
            return receiver.recv()
        return False, {"checks": {"collector_deadline": {"ok": False}}}
    except (EOFError, OSError):
        return False, {"checks": {"collector_worker": {"ok": False}}}
    finally:
        receiver.close()
        if worker.is_alive():
            worker.terminate()
        worker.join(timeout=2)
        if worker.is_alive():
            worker.kill()
            worker.join(timeout=2)
        worker.close()


def connect(path):
    connection = sqlite3.connect(path, timeout=5)
    connection.execute("PRAGMA synchronous=FULL")
    connection.execute("PRAGMA journal_mode=DELETE")
    connection.execute("PRAGMA max_page_count=131072")  # <=512 MiB at the fixed 4-KiB page size.
    if connection.execute("PRAGMA page_size").fetchone()[0] != 4096:
        connection.close()
        raise ValueError("unexpected evidence database page size")
    return connection


def initialize(path, config, now):
    # Exclusive creation prevents replacing an earlier observation window.
    descriptor = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
    os.close(descriptor)
    with closing(connect(path)) as db:
        db.executescript("""
          CREATE TABLE meta (config_hash TEXT NOT NULL, started REAL NOT NULL);
          CREATE TABLE samples (started REAL PRIMARY KEY, finished REAL NOT NULL,
            healthy INTEGER NOT NULL, detail TEXT NOT NULL);
          CREATE TABLE reviews (recorded REAL PRIMARY KEY, day TEXT NOT NULL,
            reviewer TEXT NOT NULL, clear INTEGER NOT NULL, evidence TEXT NOT NULL);
        """)
        db.execute("INSERT INTO meta VALUES (?,?)", (digest(config), now))
        db.commit()


def verify(db, config):
    if db.execute("SELECT config_hash FROM meta").fetchone()[0] != digest(config):
        raise ValueError("manifest changed; use a new evidence database for a new pilot window")


def sample(db, config):
    # Hold a write transaction through probes so overlapping timers cannot race.
    db.execute("BEGIN IMMEDIATE")
    started = time.time()
    latest = db.execute("SELECT MAX(finished) FROM samples").fetchone()[0]
    if latest is not None and started <= latest:
        raise ValueError("wall clock moved backwards; reconcile time before continuing")
    monotonic = time.monotonic()
    try:
        healthy, detail = bounded_probe(config)
    except Exception:
        healthy, detail = False, {"checks": {"collector_configuration": {"ok": False}}}
    finished = time.time()
    if abs((finished - started) - (time.monotonic() - monotonic)) > 2 or finished < started:
        healthy = False
        detail["clock_jump"] = True
    db.execute("INSERT INTO samples VALUES (?,?,?,?)", (started, finished, int(healthy), json.dumps(detail)))
    db.commit()
    return {"healthy": healthy, "checks": detail.get("checks", {})}


def assessment(db, now):
    started = db.execute("SELECT started FROM meta").fetchone()[0]
    previous, window, count, failures, gaps = started, None, 0, 0, 0
    for begin, end, healthy in db.execute("SELECT started,finished,healthy FROM samples ORDER BY started"):
        count += 1
        if begin < previous or end < begin or end > now:
            raise ValueError("invalid evidence time ordering")
        if begin - previous > MAX_GAP:
            gaps += 1
            window = None
        if not healthy or end - begin > 60:
            failures += 1
            window = None
        elif window is None:
            window = begin
        previous = end
    fresh = count > 0 and 0 <= now - previous <= MAX_GAP
    elapsed = max(0, previous - window) if window is not None else 0
    reviews = dict(db.execute("SELECT day,clear FROM reviews ORDER BY recorded"))
    required = []
    if window is not None:
        first = datetime.fromtimestamp(window, timezone.utc).date()
        last = datetime.fromtimestamp(previous, timezone.utc).date()
        required = [(first + timedelta(days=offset)).isoformat() for offset in range((last - first).days + 1)]
    missing = [day for day in required if reviews.get(day) != 1]
    ready = fresh and elapsed >= 30 * DAY and not missing
    return {"observation_ready_for_review": ready, "samples": count, "failed_samples": failures,
            "coverage_gaps": gaps, "fresh": fresh, "continuous_healthy_days": round(elapsed / DAY, 4),
            "missing_or_blocked_review_days": missing,
            "note": "Human review, application tuning, recovery/rollback evidence and independent security review remain M4 gates."}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("operation", choices=["start", "sample", "review", "status"])
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument("--database", type=Path, required=True)
    parser.add_argument("--day")
    parser.add_argument("--reviewer")
    parser.add_argument("--evidence", help="Reference to the reviewed workflows/events/findings; no secrets")
    parser.add_argument("--clear", action="store_true", help="No unresolved blocking finding in this review")
    args = parser.parse_args()
    config = load_manifest(args.manifest)
    if args.operation == "start":
        initialize(args.database, config, time.time())
    if not args.database.is_file():
        raise ValueError("initialize an evidence database with start first")
    with closing(connect(args.database)) as db:
        verify(db, config)
        if args.operation in ("start", "sample"):
            result = sample(db, config)
        elif args.operation == "review":
            now = time.time()
            if args.day not in (utc_day(now), utc_day(now - DAY)):
                raise ValueError("daily review must cover today or yesterday in UTC; historical backfill is unavailable")
            if not args.reviewer or not args.evidence or len(args.reviewer) > 100 or len(args.evidence) > 1000:
                raise ValueError("supply a named reviewer and a bounded evidence reference")
            db.execute("INSERT INTO reviews VALUES (?,?,?,?,?)", (now, args.day, args.reviewer, int(args.clear), args.evidence))
            db.commit()
            result = {"review_recorded": True, "day": args.day, "clear": args.clear}
        else:
            result = assessment(db, time.time())
    print(json.dumps(result, indent=2))
    if args.operation in ("start", "sample") and not result["healthy"]:
        return 1
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except (OSError, ValueError, sqlite3.Error, KeyError, TypeError):
        # Configuration and transport exceptions can contain credential-bearing paths/URLs.
        print("Pilot operation failed; check the manifest, restricted files, database and system clock.", file=sys.stderr)
        sys.exit(2)
