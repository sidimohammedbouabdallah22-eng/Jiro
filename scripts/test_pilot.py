"""Synthetic collector tests; these never constitute a 30-day pilot record."""

import hashlib
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
from pathlib import Path
import sqlite3
import tempfile
import threading
import unittest
from unittest.mock import patch

import pilot


class PilotTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.token = self.root / "token"
        self.token.write_text("private-monitoring-secret")
        self.token.chmod(0o600)
        self.config = dict(schema=1, pilot_id="synthetic-test", owner="Test operator", host="Test host",
                           qualification_evidence="Test fixture", capacity_evidence="Test fixture",
                           management_url="http://localhost:1234", token_file=str(self.token),
                           canaries=[dict(name="business", url="http://localhost:2345/canary",
                                         status=200, sha256=hashlib.sha256(b"canary").hexdigest())])
        self.database = self.root / "evidence.db"
        self.start = 1767225600.0  # Fixed UTC midnight, exclusively synthetic.
        pilot.initialize(self.database, self.config, self.start)
        self.db = pilot.connect(self.database)

    def tearDown(self):
        self.db.close()
        self.temporary.cleanup()

    def month(self):
        rows = [(self.start + offset, self.start + offset + 1, 1, "{}")
                for offset in range(0, 30 * pilot.DAY + 1, 120)]
        self.db.executemany("INSERT INTO samples VALUES (?,?,?,?)", rows)
        self.now = rows[-1][1]
        for offset in range(31):
            day = pilot.utc_day(self.start + offset * pilot.DAY)
            self.db.execute("INSERT INTO reviews VALUES (?,?,?,?,?)", (self.start + offset + 1, day, "Operator", 1, "review-reference"))
        self.db.commit()

    def test_month_requires_coverage_freshness_and_all_daily_reviews(self):
        self.month()
        self.assertTrue(pilot.assessment(self.db, self.now)["observation_ready_for_review"])
        self.assertFalse(pilot.assessment(self.db, self.now + 181)["observation_ready_for_review"])
        self.db.execute("DELETE FROM reviews WHERE day=?", (pilot.utc_day(self.start + 10 * pilot.DAY),))
        self.assertFalse(pilot.assessment(self.db, self.now)["observation_ready_for_review"])

    def test_failure_or_missing_samples_restart_continuous_window(self):
        self.month()
        middle = self.start + 15 * pilot.DAY
        self.db.execute("UPDATE samples SET healthy=0 WHERE started=?", (middle,))
        result = pilot.assessment(self.db, self.now)
        self.assertFalse(result["observation_ready_for_review"])
        self.assertEqual(result["failed_samples"], 1)
        self.assertLess(result["continuous_healthy_days"], 15)
        self.db.execute("UPDATE samples SET healthy=1 WHERE started=?", (middle,))
        self.db.execute("DELETE FROM samples WHERE started=?", (middle,))
        self.assertEqual(pilot.assessment(self.db, self.now)["coverage_gaps"], 1)
        self.assertFalse(pilot.assessment(self.db, self.now)["observation_ready_for_review"])

    def test_blocking_review_prevents_exit_and_changes_cannot_rewrite_identity(self):
        self.month()
        self.db.execute("INSERT INTO reviews VALUES (?,?,?,?,?)", (self.now, pilot.utc_day(self.now), "Reviewer", 0, "unresolved finding"))
        self.assertFalse(pilot.assessment(self.db, self.now)["observation_ready_for_review"])
        changed = dict(self.config, host="Another host")
        with self.assertRaises(ValueError):
            pilot.verify(self.db, changed)
        with self.assertRaises(FileExistsError):
            pilot.initialize(self.database, self.config, self.now)

    def test_failed_probe_is_committed_without_secret_or_exception_text(self):
        with patch.object(pilot, "bounded_probe", side_effect=ValueError("private-monitoring-secret")):
            self.assertFalse(pilot.sample(self.db, self.config)["healthy"])
        stored = self.db.execute("SELECT healthy,detail FROM samples").fetchone()
        self.assertEqual(stored[0], 0)
        self.assertNotIn("private", stored[1])
        self.assertEqual(self.db.execute("PRAGMA synchronous").fetchone()[0], 2)
        self.assertEqual(self.db.execute("PRAGMA max_page_count").fetchone()[0], 131072)

    def test_scoped_identity_and_expected_business_body_required(self):
        def response(target, token=None):
            if target.endswith("/me"):
                return 200, json.dumps(dict(automation_id="scoped", scopes=["monitoring:read"], bootstrap=False)).encode()
            if target.endswith("/health"):
                return 200, json.dumps(dict(ready=True, healthy=True, mode="enforcing", revision=1, checks={"events": True})).encode()
            if target.endswith("/metrics"):
                return 200, b"openwaf_requests_total 12\n"
            self.assertIsNone(token)
            return 200, b"canary"
        with patch.object(pilot, "get", side_effect=response):
            self.assertTrue(pilot.probe(self.config)[0])
            self.config["canaries"][0]["sha256"] = "0" * 64
            self.assertFalse(pilot.probe(self.config)[0])
        with patch.object(pilot, "get", return_value=(200, b'{"bootstrap":true}')):
            self.assertFalse(pilot.probe(self.config)[0])

    def test_http_bounds_and_redirect_do_not_forward_credential(self):
        seen = []
        class Handler(BaseHTTPRequestHandler):
            def do_GET(self):
                seen.append(self.path)
                if self.path == "/redirect":
                    self.send_response(302)
                    self.send_header("Location", "/credential-sink")
                    self.end_headers()
                else:
                    self.send_response(200)
                    self.end_headers()
                    self.wfile.write(b"x" * 33)
            def log_message(self, *args):
                pass
        server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            base = "http://127.0.0.1:" + str(server.server_port)
            self.assertEqual(pilot.get(base + "/redirect", "private-monitoring-secret")[0], 302)
            self.assertEqual(seen, ["/redirect"])
            with patch.object(pilot, "MAX_BODY", 32):
                with self.assertRaises(ValueError):
                    pilot.get(base + "/large")
        finally:
            server.shutdown()
            server.server_close()
            thread.join()

    def test_remote_cleartext_and_embedded_secrets_rejected(self):
        for value in ("http://example.invalid", "https://user:secret@example.invalid", "https://example.invalid/?token=secret"):
            with self.assertRaises(ValueError):
                pilot.url(value)

    def test_worker_deadline_persists_failure_instead_of_hanging(self):
        healthy, detail = pilot.bounded_probe(self.config, timeout=0)
        self.assertFalse(healthy)
        self.assertFalse(detail["checks"]["collector_deadline"]["ok"])


if __name__ == "__main__":
    unittest.main()
