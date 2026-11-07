"""Prepare a private, source-only GitHub review snapshot and disclosure-safe audit."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import uuid


ROOTS = ['cmd','internal','ui','deploy','third_party/coraza','THIRD_PARTY_LICENSES',
         'tools','scripts','docs','.github']
FILES = ['go.mod','go.sum','LICENSE','NOTICE','.gitignore','.gitattributes','README.md','ARCHITECTURE.md',
         'ROADMAP.md','CONTRIBUTING.md','SECURITY.md']
SKIP_DIRS = {'.git','node_modules','__pycache__','.pytest_cache','.venv'}
BLOCKED_SUFFIXES = {'.exe','.zip','.tar','.gz','.db','.sqlite','.pem','.key','.pfx',
                    '.p12','.vdi','.vmdk','.pcap','.pcapng','.log','.pyc'}
OLD_MODULE = 'github.com/openwaf/openwaf'
NEW_MODULE = 'github.com/sidimohammedbouabdallah22-eng/Jiro'

README = '''# OpenWAF

A self-hosted Go reverse proxy integrating OWASP Coraza and the OWASP Core Rule
Set with an embedded security administration console.

**Development preview.** Application, capacity, operational and independent-review
qualification remains open. The thirty-day pilot has yet to begin.

![Security console](docs/images/dashboard.png)

## Current capabilities

- Hostname-routed applications with separate policies and bounded upstream pools.
- Real CRS inspection for supported HTTP bodies, with manual policy configuration.
- Application/client request rates, body-byte budgets, buffer shares and admission controls.
- Scoped rule exceptions, policy validation, revision history and rollback.
- Local roles, scoped automation tokens, MFA, passkeys and optional OIDC sign-in.
- Durable security events, acknowledged export and administration auditing.
- Linux service packaging, certificate reloads, backups and recovery tooling.

## Build and try locally

The currently qualified toolchain is Go 1.27.3. The module declares Go 1.26 as
its minimum. Building and running the server requires Go.

On Windows, run the launcher from the repository root.

```powershell
./scripts/start.ps1
```

The launcher generates a local administrator token and prints the console URL.
The console defaults to http://127.0.0.1:8081 and the protected listener to
http://127.0.0.1:8080. Start an application at http://127.0.0.1:3000 or configure
its upstream in the console. A new installation creates a local policy file.

On Linux, build the server and configure a fresh administrator token.

```sh
go build -o bin/openwaf ./cmd/waf-server
export OPENWAF_ADMIN_TOKEN="$(openssl rand -hex 32)"
printf 'Local administrator token: %s\\n' "$OPENWAF_ADMIN_TOKEN"
./bin/openwaf -config config/policy.json
```

## Evidence and operating boundaries

[Public evidence summary](docs/PUBLIC-EVIDENCE.json) records selected local
qualification results, toolchain/build identity and failed operating profiles.
Its associated [publication notes](PUBLICATION.md) describe provenance and
the private-artifact boundary. These are maintainer-run synthetic lab results.

Windows and Linux full checks include 5,193 CRS cases each. Resource pressure,
latency tails, VM scheduling gaps and same-source contention remain explicit
findings. Select an operating envelope using representative application traffic.

The bundled Coraza source contains a documented downstream ASCII-presence
performance patch. [Patch provenance](third_party/coraza/OPENWAF-UPSTREAM.json)
and [third-party notices](NOTICE) identify its origin and licensing.

## Documentation

- [Architecture](ARCHITECTURE.md) and [roadmap](ROADMAP.md)
- [Applications and migration](docs/APPLICATIONS.md)
- [Body-byte controls](docs/CLIENT-BODY-RATE.md)
- [Shared-NAT abuse and endurance](docs/M4-NAT-ABUSE.md)
- [Linux operations](docs/LINUX-OPERATIONS.md)
- [Backup and recovery](docs/BACKUP-RESTORE-UPGRADES.md)
- [Contributing](CONTRIBUTING.md) and [security reporting](SECURITY.md)

## Maintainer and licensing

Maintained by [sidimohammedbouabdallah22-eng](https://github.com/sidimohammedbouabdallah22-eng).
Development uses AI-assisted coding. Qualification records distinguish measured
results from outstanding review and release gates.

OpenWAF is licensed under [Apache-2.0](LICENSE). Upstream components retain
their own licenses and notices.
'''


def sha(data):
    return hashlib.sha256(data).hexdigest()


def known_private_values(repo):
    values = set()
    token = repo/'config/admin-token.txt'
    if token.is_file():
        values.add(token.read_text().strip())
    paths = []
    for directory in (repo/'artifacts').iterdir():
        if directory.is_dir():
            paths.extend(directory.glob('*private*.json'))

    def collect(value):
        if isinstance(value,dict):
            for key,item in value.items():
                if re.search(r'(token|password|api_key|client_secret|private_key)$',key,re.I) and isinstance(item,str) and len(item)>=16:
                    values.add(item)
                else:
                    collect(item)
        elif isinstance(value,list):
            for item in value:
                collect(item)

    for path in paths:
        if path.stat().st_size > 1 << 20:
            continue
        try:
            collect(json.loads(path.read_text()))
        except (UnicodeError,json.JSONDecodeError):
            pass
    return {value.encode() for value in values if value}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.parse_args()
    repo = Path(__file__).resolve().parents[1]
    (repo/'artifacts').mkdir(exist_ok=True)
    out = repo/'artifacts'/('publication-20261107-'+uuid.uuid4().hex[:8])
    out.mkdir()
    source = out/'source'
    source.mkdir()
    private_values = known_private_values(repo)
    paths = [repo/name for name in FILES]
    paths.extend((repo/'config').glob('*.example.json'))
    for name in ROOTS:
        root = repo/name
        for directory,dirs,names in os.walk(root,followlinks=False):
            dirs[:] = sorted(d for d in dirs if d not in SKIP_DIRS)
            paths.extend(Path(directory)/name for name in sorted(names))
    findings,excluded,changes,manifest = [],[],[],{}
    credentials = re.compile(rb'(?:gh[pousr]_[A-Za-z0-9]{30,}|github_pat_[A-Za-z0-9_]{40,}|sk-ant-[A-Za-z0-9_-]{30,}|sk-proj-[A-Za-z0-9_-]{40,})')
    private_key = re.compile(rb'-----BEGIN (?:[A-Z]+ )?PRIVATE KEY-----[\r\n]+(?:[A-Za-z0-9+/=]{32,}[\r\n]+){2,}-----END (?:[A-Z]+ )?PRIVATE KEY-----')
    for path in sorted(set(paths)):
        relative = path.relative_to(repo)
        name = relative.as_posix()
        if path.is_symlink():
            raise ValueError('source symlink requires review: '+name)
        if (path.suffix.lower() in BLOCKED_SUFFIXES or '.private' in path.name or
            path.name == '.env' or path.name.startswith('.env.') or path.name in ['.npmrc','.pypirc','.netrc'] or
            path.name in ['identity','known_hosts'] or path.name.startswith('SESSION-CHECKPOINT-')):
            excluded.append(name)
            continue
        data = path.read_bytes()
        if len(data) > 16 << 20:
            raise ValueError('oversized source requires review: '+name)
        if any(secret in data for secret in private_values):
            findings.append(dict(path=name,kind='known private fixture credential'))
        if credentials.search(data):
            findings.append(dict(path=name,kind='credential-shaped string'))
        if private_key.search(data) and not (path.name.endswith('_test.go') or name.startswith('third_party/')):
            findings.append(dict(path=name,kind='private-key marker requires review'))
        original = sha(data)
        if path.suffix in ['.go','.mod'] and not name.startswith('third_party/'):
            data = data.replace(OLD_MODULE.encode(),NEW_MODULE.encode())
        if path.suffix == '.md' and not name.startswith('third_party/'):
            try:
                text = data.decode('utf-8-sig')
            except UnicodeDecodeError:
                text = data.decode('cp1252')
            text = re.sub(r'(?<!!)\[([^\]\n]+)\]\((?:\.\./)*artifacts/[^)\n]+\)',
                          r'\1 (private lab artifact)',text)
            data = text.encode()
        if name == 'README.md':
            data = README.encode()
        destination = source/relative
        destination.parent.mkdir(parents=True,exist_ok=True)
        destination.write_bytes(data)
        manifest[name] = sha(data)
        if original != sha(data):
            changes.append(dict(path=name,workspace_sha256=original,export_sha256=sha(data)))
    audit = dict(passed=not findings,files=len(manifest),bytes=sum((source/name).stat().st_size for name in manifest),
        known_private_values_checked=len(private_values),findings=findings,excluded=excluded,
        transformations=changes,proposed_repository=NEW_MODULE,license_confirmation_pending=False,license='Apache-2.0',
        remote_publication_performed=False,source_sha256=manifest)
    (out/'audit.json').write_text(json.dumps(audit,indent=2)+'\n')
    print(out,flush=True)
    if findings:
        raise RuntimeError('publication scan needs review; see audit.json, which contains no secret values')


if __name__ == '__main__':
    main()
