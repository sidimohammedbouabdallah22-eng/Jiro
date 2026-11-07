"""Exact-build operational rehearsal with replacement-deployment recovery."""
import importlib.util
from pathlib import Path
import shlex
import hashlib
import sys

spec = importlib.util.spec_from_file_location("operational", Path(__file__).with_name("qualify-m2-operational.py"))
operational = importlib.util.module_from_spec(spec)
spec.loader.exec_module(operational)


class RecoveryQualification(operational.Qualification):
    def __init__(self, args):
        super().__init__(args)
        source = self.out / "source"
        source.mkdir()
        self.report["recovery_source_sha256"] = {}
        for name in ["qualify-m4-recovery.py", "m4_recovery_guest.py", "qualify-m2-operational.py", "m2_guest.py"]:
            data = (self.repo / "scripts" / name).read_bytes()
            (source / name).write_bytes(data)
            self.report["recovery_source_sha256"][name] = hashlib.sha256(data).hexdigest()

    def power_cuts(self):
        super().power_cuts()
        helper = self.repo / "scripts/m4_recovery_guest.py"
        self.execute(["scp", *self.options, "-P", str(self.ssh_port), helper,
                      "qualifier@127.0.0.1:/tmp/m4_recovery_guest.py"])
        import json
        result = self.execute([*self.ssh, shlex.join(["sudo", "python3", "/tmp/m4_recovery_guest.py", self.root])], timeout=600)
        self.report["replacement_recovery"] = json.loads(result.stdout)
        for sequence in range(10):
            assert self.request(sequence, marker="replacement-recovery")[1]
        self.passkey_proof()
        self.save()
        print("Replacement deployment and authentication verified", flush=True)


if __name__ == "__main__":
    if "--m3" not in sys.argv or "--functional-only" not in sys.argv:
        raise RuntimeError("requires --m3 --functional-only; this is not a sizing run")
    operational.Qualification = RecoveryQualification
    operational.main()
