"""Independently check the retained functional/replacement recovery reports."""
import argparse
import hashlib
import json
from pathlib import Path


def check(full_path, replacement_path):
    full = json.loads(full_path.read_text())
    replacement = json.loads(replacement_path.read_text())
    for report in [full, replacement]:
        assert report["passed"] and not report["sizing_performed"]
        if 'package_inputs' in report:
            inputs=report['package_inputs']
            assert inputs['current']['remote']!=inputs['previous']['remote']
            assert inputs['current']['executable_sha256']!=inputs['previous']['executable_sha256']
            for label in ['current','previous']:
                assert inputs[label]['executable_sha256']==report['binaries'][label+'_sha256']
        assert report["platform"] == "linux-amd64"
        assert all(report[key]["viewer_login"] for key in ["previous_login", "upgraded_login", "rollback_login"])
        assert report["upgrade"]["executable_sha256"] == report["binaries"]["current_sha256"]
        assert report["rollback"]["executable_sha256"] == report["binaries"]["previous_sha256"]
        assert report["post_upgrade_revision"] > report["rollback_verification"]["revision"]
        for interruption in report["power_cuts"]:
            assert interruption["journal_observed"] and 0 < interruption["recovery_seconds"] < 180
            assert interruption["verified_events"] > 0 and interruption["verified_audit_records"] > 0
        for proof in report["passkey_proofs"]:
            assert proof["totp"] and proof["scoped_token"] and proof["assignment_isolated"]
    assert not full["smoke"] and len(full["power_cuts"]) == 3
    assert len(full["passkey_proofs"]) >= 4
    assert full["binaries"] == replacement["binaries"]
    restored = replacement["replacement_recovery"]
    assert restored["passed"] and restored["audit_receiver_retained"]
    assert restored["executable_sha256"] == full["binaries"]["current_sha256"]
    assert restored["verification"]["verified_events"] > 0
    assert restored["verification"]["verified_audit_records"] > 0
    assert restored["definitions_preserved"] == 6
    assert set(restored["assets"]) == {"admin-token", "event-token", "audit-token", "tls/cert.pem", "tls/key.pem", "authentication.json"}
    for name, value in restored["assets"].items():
        assert len(value["sha256"]) == 64
        assert value["mode"] == ("0o640" if name.startswith("tls/") or name == "authentication.json" else "0o600")
    assert len(replacement["passkey_proofs"]) >= len(replacement["power_cuts"]) + 2
    sources = replacement["recovery_source_sha256"]
    assert set(sources) == {"qualify-m4-recovery.py", "m4_recovery_guest.py", "qualify-m2-operational.py", "m2_guest.py"}
    for name, expected in sources.items():
        assert hashlib.sha256((replacement_path.parent / "source" / name).read_bytes()).hexdigest() == expected
    return dict(passed=True, full=str(full_path), replacement=str(replacement_path),
                fresh_host_restore_qualified=False, capacity_claim=False)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("full", type=Path)
    parser.add_argument("replacement", type=Path)
    args = parser.parse_args()
    print(json.dumps(check(args.full, args.replacement), indent=2))
