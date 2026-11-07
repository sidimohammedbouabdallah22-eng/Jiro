"""Bounded, durable pilot alert webhook delivery. Run independently of sampling.

Receivers must deduplicate event_id and acknowledge {accepted:true,event_id:...}.
Payloads contain fixed reasons/check names, never probe responses or secrets.
"""
import argparse
from contextlib import closing
import hashlib
import json
import multiprocessing
import os
from pathlib import Path
import re
import sqlite3
import sys
import time
import urllib.request
import uuid

import pilot

MAX_PENDING = 1024


def load(path):
    config = json.loads(path.read_text())
    if set(config) != {'schema', 'deployment', 'pilot_manifest', 'pilot_database', 'webhook_url', 'webhook_token_file'} or config['schema'] != 1:
        raise ValueError('invalid alert configuration')
    if not re.fullmatch(r'[a-zA-Z0-9_-]{1,64}', config['deployment']):
        raise ValueError('invalid deployment identifier')
    for name in ['pilot_manifest', 'pilot_database', 'webhook_token_file']:
        if not Path(config[name]).is_absolute():
            raise ValueError('absolute paths required')
    pilot.url(config['webhook_url'])
    return config


def initialize(path, config):
    descriptor = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
    os.close(descriptor)
    with closing(sqlite3.connect(path)) as db:
        db.execute('PRAGMA synchronous=FULL')
        db.executescript('''
          CREATE TABLE meta(config TEXT NOT NULL,cursor REAL NOT NULL,active TEXT NOT NULL,last_poll REAL NOT NULL);
          CREATE TABLE outbox(seq INTEGER PRIMARY KEY AUTOINCREMENT,id TEXT UNIQUE NOT NULL,payload TEXT NOT NULL,acked INTEGER NOT NULL DEFAULT 0);
        ''')
        db.execute('INSERT INTO meta VALUES (?,-1,\'null\',0)', (pilot.digest(config),))
        db.commit()


def observe(config, cursor, now):
    try:
        manifest = pilot.load_manifest(Path(config['pilot_manifest']))
        path = Path(config['pilot_database'])
        if path.stat().st_size > 512 << 20:
            raise ValueError('oversized pilot database')
        with closing(sqlite3.connect(path.as_uri() + '?mode=ro', uri=True, timeout=2)) as db:
            pilot.verify(db, manifest)
            rows = db.execute('SELECT started,finished,healthy,detail FROM samples WHERE started>? ORDER BY started LIMIT 257', (cursor,)).fetchall()
            latest = db.execute('SELECT started,finished,healthy,detail FROM samples ORDER BY started DESC LIMIT 1').fetchone()
        def condition(row):
            begin, end, healthy, detail = row
            if not 0 <= begin <= end <= now or end - begin > 60:
                return dict(reason='sample_time_invalid', checks=[])
            if healthy:
                return None
            if len(detail) > 65536:
                raise ValueError('oversized detail')
            checks = json.loads(detail).get('checks', {})
            names = sorted(name for name,value in checks.items() if value.get('ok') is not True and re.fullmatch(r'[a-zA-Z0-9_-]{1,64}', name))[:16]
            return dict(reason='sample_failed', checks=names)
        changes = [(row[0], condition(row)) for row in rows[:256]]
        new_cursor = rows[min(len(rows), 256)-1][0] if rows else cursor
        if len(rows) > 256:
            final = dict(reason='evidence_backlog', checks=[])
        elif latest is None or now - latest[1] > pilot.MAX_GAP:
            final = dict(reason='samples_missing', checks=[])
        else:
            final = condition(latest)
        changes.append((now, final))
        return new_cursor, changes
    except (OSError, ValueError, sqlite3.Error, KeyError, TypeError, AttributeError):
        return cursor, [(now, dict(reason='evidence_unavailable', checks=[]))]


def enqueue(db, config, event, condition, now):
    # Retain a bounded acknowledged history; never discard pending delivery.
    db.execute('DELETE FROM outbox WHERE acked=1 AND seq NOT IN (SELECT seq FROM outbox ORDER BY seq DESC LIMIT 128)')
    if db.execute('SELECT count(*) FROM outbox WHERE acked=0').fetchone()[0] >= MAX_PENDING:
        raise ValueError('alert outbox full')
    identity = uuid.uuid4().hex
    payload = dict(schema=1, event_id=identity, deployment=config['deployment'], event=event,
                   reason=condition['reason'], checks=condition['checks'], observed_at=now)
    db.execute('INSERT INTO outbox(id,payload) VALUES (?,?)', (identity, json.dumps(payload, separators=(',', ':'))))


def record(db, config, now):
    db.execute('BEGIN IMMEDIATE')
    pinned, cursor, encoded, previous = db.execute('SELECT config,cursor,active,last_poll FROM meta').fetchone()
    if pinned != pilot.digest(config):
        raise ValueError('alert configuration changed; use a new state database')
    active = json.loads(encoded)
    if now < previous:
        changes = [(now, dict(reason='watchdog_clock_invalid', checks=[]))]
    else:
        cursor, changes = observe(config, cursor, now)
    for observed, condition in changes:
        if condition != active:
            if active is not None:
                enqueue(db, config, 'resolved', active, observed)
            if condition is not None:
                enqueue(db, config, 'firing', condition, observed)
            active = condition
    db.execute('UPDATE meta SET cursor=?,active=?,last_poll=?', (cursor, json.dumps(active), max(now, previous)))
    db.commit()
    return active


def post_worker(config, payload, sender):
    try:
        path = Path(config['webhook_token_file'])
        if (os.name != 'nt' and path.stat().st_mode & 0o077) or path.stat().st_size > 4096:
            raise ValueError('unsafe webhook credential')
        token = path.read_text().strip()
        if not token or any(char.isspace() for char in token):
            raise ValueError('invalid credential')
        opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), pilot.NoRedirect())
        request = urllib.request.Request(config['webhook_url'], data=payload.encode(), headers={'Authorization':'Bearer ' + token, 'Content-Type':'application/json'})
        with opener.open(request, timeout=3) as response:
            body = response.read(4097)
            ack = json.loads(body) if len(body) <= 4096 else {}
            ok = response.status == 200 and ack.get('accepted') is True and ack.get('event_id') == json.loads(payload)['event_id']
        sender.send(ok)
    except Exception:
        sender.send(False)
    finally:
        sender.close()


def deliver_one(config, payload):
    context = multiprocessing.get_context('spawn')
    receiver, sender = context.Pipe(duplex=False)
    worker = context.Process(target=post_worker, args=(config, payload, sender))
    worker.start()
    sender.close()
    try:
        return bool(receiver.recv()) if receiver.poll(5) else False
    except EOFError:
        return False
    finally:
        receiver.close()
        if worker.is_alive():
            worker.terminate()
        worker.join(timeout=1)
        if worker.is_alive():
            worker.kill()
            worker.join(timeout=1)
        worker.close()


def run(path, config):
    if not path.exists():
        try:
            initialize(path, config)
        except FileExistsError:
            pass  # Another invocation won exclusive creation.
    with closing(sqlite3.connect(path, timeout=5)) as db:
        # Verify identity before changing pragmas on an existing database.
        if db.execute('SELECT config FROM meta').fetchone()[0] != pilot.digest(config):
            raise ValueError('configuration mismatch')
        db.execute('PRAGMA synchronous=FULL')
        db.execute('PRAGMA max_page_count=8192')  # 32 MiB at 4-KiB pages.
        if db.execute('PRAGMA page_size').fetchone()[0] != 4096:
            raise ValueError('unexpected page size')
        active = record(db, config, time.time())
        deadline = time.monotonic() + 20
        delivered = 0
        for identity, payload in db.execute('SELECT id,payload FROM outbox WHERE acked=0 ORDER BY seq LIMIT 8').fetchall():
            if time.monotonic() >= deadline or not deliver_one(config, payload):
                break
            db.execute('UPDATE outbox SET acked=1 WHERE id=?', (identity,))
            db.commit()
            delivered += 1
        pending = db.execute('SELECT count(*) FROM outbox WHERE acked=0').fetchone()[0]
        return dict(healthy=active is None, delivered=delivered, pending=pending)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--config', type=Path, required=True)
    parser.add_argument('--state', type=Path, required=True)
    args = parser.parse_args()
    result = run(args.state, load(args.config))
    print(json.dumps(result))
    return 0 if result['healthy'] and result['pending'] == 0 else 1


if __name__ == '__main__':
    try:
        sys.exit(main())
    except (OSError, ValueError, sqlite3.Error, KeyError, TypeError):
        print('Alert watchdog failed; inspect protected configuration, state and supervisor status.', file=sys.stderr)
        sys.exit(2)
