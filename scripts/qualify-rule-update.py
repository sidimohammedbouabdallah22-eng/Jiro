"""Build and qualify explicitly pinned rule/engine candidates in an isolated source copy."""

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import time
import uuid


MODULES = {
    "engine": "github.com/corazawaf/coraza/v3",
    "crs": "github.com/corazawaf/coraza-coreruleset/crs/v4",
    "configuration": "github.com/corazawaf/coraza-coreruleset/coraza/v3",
}


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def run():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--engine", required=True)
    parser.add_argument("--crs", required=True)
    parser.add_argument("--configuration", required=True)
    parser.add_argument("--review", type=Path, help="Optional explicit review manifest matching candidate pins and adaptation digest")
    args = parser.parse_args()
    pins = {name: getattr(args, name) for name in MODULES}
    if any(not re.fullmatch(r"v\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?", value) for value in pins.values()):
        raise ValueError("supply exact semantic/pseudo versions, never branch names or latest")
    downstream_path = Path(__file__).resolve().parents[1] / "third_party/coraza/OPENWAF-UPSTREAM.json"
    downstream = json.loads(downstream_path.read_text())
    if pins["engine"] != downstream["version"]:
        raise ValueError("rebase/review the local Coraza patch before selecting a different engine pin")
    review = None
    if args.review:
        if not args.review.is_file() or args.review.stat().st_size > 64 << 10:
            raise ValueError("review manifest must be a file of at most 64 KiB")
        review = json.loads(args.review.read_text(encoding="utf-8"))
        if not isinstance(review, dict):
            raise ValueError("review manifest must be an object")
        for field, limit in [("reviewer", 100), ("reason", 500)]:
            value = review.get(field)
            if not isinstance(value, str) or not value.strip() or len(value) > limit:
                raise ValueError("review requires bounded reviewer and reason strings")
    repo = Path(__file__).resolve().parents[1]
    out = repo / "artifacts" / ("rule-candidate-" + uuid.uuid4().hex[:12])
    out.mkdir(parents=True)
    source = out / "source"
    source.mkdir()
    report = dict(pins=pins, passed=False, activation_approved=False, phases=[], source_sha256={},
                  engine_downstream=downstream["patch_identity"],pipeline_sha256=digest(Path(__file__).resolve()))
    report_path = out / "result.json"
    env = os.environ.copy()
    for key in ["GOOS", "GOARCH", "CGO_ENABLED"]:
        env.pop(key, None)

    def save():
        report_path.write_text(json.dumps(report, indent=2), encoding="utf-8")

    def command(label, arguments, cwd=source, timeout=1800):
        started = time.monotonic()
        with (out / (label + ".log")).open("w", encoding="utf-8") as log:
            result = subprocess.run(arguments, cwd=cwd, env=env, stdout=log, stderr=subprocess.STDOUT, timeout=timeout)
        report["phases"].append(dict(name=label, seconds=time.monotonic()-started, exit_code=result.returncode))
        save()
        if result.returncode:
            raise RuntimeError(f"{label} failed, inspect its retained log")

    try:
        # Copy source/build inputs only. Runtime configuration, credentials, reference
        # checkouts, node_modules, binaries and prior artifacts never enter the candidate.
        roots = ["cmd", "internal", "ui", "deploy", "docs", "THIRD_PARTY_LICENSES", "third_party/coraza", "tools/crscheck", "tools/edgecheck", "tools/recoverycheck", "tools/transportcheck"]
        files = [repo / name for name in ["go.mod", "go.sum", "LICENSE", "NOTICE"]]
        for name in roots:
            root = repo / name
            for path in root.rglob("*"):
                if path.is_symlink():
                    raise ValueError("source symlinks are refused")
                if path.is_file():
                    files.append(path)
        total = 0
        for path in files:
            relative = path.relative_to(repo)
            size = path.stat().st_size
            total += size
            if size > 16 << 20 or total > 128 << 20 or len(files) > 10000:
                raise ValueError("source copy exceeds candidate bounds")
            target = source / relative
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(path, target)
            report["source_sha256"][relative.as_posix()] = digest(path)
        report["adaptations_sha256"] = digest(source / "tools/crscheck/compatibility.go")
        save()
        command("go-version", ["go", "version"])
        for index, module_dir in enumerate([source, source / "tools/crscheck", source / "tools/edgecheck", source / "tools/recoverycheck"]):
            requested = [module + "@" + pins[name] for name, module in MODULES.items()]
            if module_dir.name == "crscheck":
                requested.append("github.com/corazawaf/coraza-coreruleset/crs/tests/v4@" + pins["crs"])
            command(f"pin-{index}", ["go", "get", *requested], module_dir)
            command(f"tidy-{index}", ["go", "mod", "tidy"], module_dir)
            for name, module in MODULES.items():
                actual = subprocess.check_output(["go", "list", "-m", "-f", "{{.Version}}", module], cwd=module_dir, env=env, text=True).strip()
                if actual != pins[name]:
                    raise ValueError("module selection drifted from requested pins")
        with (out / "modules.json").open("w", encoding="utf-8") as stream:
            subprocess.run(["go", "list", "-m", "-json", "all"], cwd=source, env=env, stdout=stream, check=True)
        notice = (source / "NOTICE").read_text(encoding="utf-8")
        for label, name, url in [
            ("OWASP Coraza", "engine", "https://github.com/corazawaf/coraza"),
            ("Coraza recommended configuration", "configuration", "https://github.com/corazawaf/coraza-coreruleset"),
            ("OWASP CRS", "crs", "https://github.com/corazawaf/coraza-coreruleset"),
        ]:
            notice = re.sub(r"(?m)^- " + re.escape(label) + r" .*$",
                            f"- {label} {pins[name]} — {url} — Apache-2.0", notice)
        (source / "NOTICE").write_text(notice, encoding="utf-8")
        (source / "bin").mkdir()
        suffix = ".exe" if os.name == "nt" else ""
        candidate = source / "bin" / ("waf-server" + suffix)
        admin = source / "bin" / ("waf-admin" + suffix)
        legacy = source / "bin" / ("schema1-fixture" + suffix)
        for label, target, package, cwd in [
            ("server", candidate, "./cmd/waf-server", source),
            ("administrator", admin, "./cmd/waf-admin", source),
            ("legacy-fixture", legacy, ".", source / "tools/recoverycheck"),
        ]:
            command("build-" + label, ["go", "build", "-trimpath", "-o", str(target), package], cwd)
        env.update(OPENWAF_RECOVERY_CANDIDATE=str(candidate), OPENWAF_RECOVERY_ADMIN=str(admin), OPENWAF_RECOVERY_LEGACY=str(legacy))
        command("unit-integration", ["go", "test", "-p", "1", "./..."])
        command("vet", ["go", "vet", "./..."])
        command("dependency-vulnerabilities", ["go", "run", "golang.org/x/vuln/cmd/govulncheck@v1.9.0", "./..."])
        command("connector-comparison", ["go", "test", "-v", "./..."], source / "tools/edgecheck")
        crs_report = out / "crs-regression.json"
        command("full-crs", ["go", "run", ".", "-out", str(crs_report)], source / "tools/crscheck")
        corpus = json.loads(crs_report.read_text(encoding="utf-8"))
        if corpus["Total"] != corpus["Passed"] or any(corpus[key] for key in ["Failed", "Errors", "Skipped", "Ignored"]):
            raise ValueError("corpus accounting has failures or unevaluated cases")
        report["corpus"] = {key: value for key, value in corpus.items() if key != "cases"}
        report["candidate_sha256"] = digest(candidate)
        # Copy license/notice files for the actually selected module graph.
        decoder = json.JSONDecoder()
        remaining = (out / "modules.json").read_text(encoding="utf-8").lstrip()
        while remaining:
            module, consumed = decoder.raw_decode(remaining)
            remaining = remaining[consumed:].lstrip()
            if module.get("Main") or not module.get("Dir"):
                continue
            root = Path(module["Dir"])
            destination = source / "THIRD_PARTY_LICENSES" / (module["Path"].replace("/", "_") + "@" + module["Version"])
            destination.mkdir(exist_ok=True)
            for path in root.iterdir():
                if path.is_file() and re.match(r"^(LICENSE|LICENCE|NOTICE|COPYING)", path.name, re.I):
                    shutil.copyfile(path, destination / path.name)
        report["review_required"] = dict(pins=pins, adaptations_sha256=report["adaptations_sha256"], candidate_sha256=report["candidate_sha256"])
        if review is not None:
            if any(review.get(key) != value for key, value in report["review_required"].items()):
                raise ValueError("review does not match this exact candidate and adaptation table")
            report["activation_approved"] = True
            report["review"] = review
        # A passing regression candidate is still separate from live activation.
        command("package", ["go", "run", "./cmd/waf-package", "-version", "rule-candidate", "-arch", "amd64", "-out", str(out)])
        report["passed"] = True
    except Exception as error:
        report["error"] = str(error)
        raise
    finally:
        save()
        print(report_path, flush=True)


if __name__ == "__main__":
    run()
