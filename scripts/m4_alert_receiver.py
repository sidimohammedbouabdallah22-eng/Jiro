"""Isolated qualification-only acknowledged webhook receiver, never a notifier."""
import hmac
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
from pathlib import Path
import sqlite3
import sys

root, port = Path(sys.argv[1]), int(sys.argv[2])
with sqlite3.connect(root / 'receipts.db') as db:
    db.executescript('CREATE TABLE IF NOT EXISTS receipts(id TEXT PRIMARY KEY,payload BLOB NOT NULL); CREATE TABLE IF NOT EXISTS attempts(id TEXT NOT NULL,mode TEXT NOT NULL);')


class Handler(BaseHTTPRequestHandler):
    def do_POST(self):
        if not hmac.compare_digest(self.headers.get('Authorization',''), 'Bearer ' + (root/'token').read_text().strip()):
            self.send_error(401);return
        size=int(self.headers.get('Content-Length','0'))
        if not 0<size<4096:
            self.send_error(413);return
        payload=self.rfile.read(size)
        value=json.loads(payload)
        mode=(root/'mode').read_text().strip()
        with sqlite3.connect(root/'receipts.db') as db:
            existing=db.execute('SELECT payload FROM receipts WHERE id=?',(value['event_id'],)).fetchone()
            if existing and existing[0]!=payload:
                self.send_error(409);return
            db.execute('INSERT OR IGNORE INTO receipts VALUES (?,?)',(value['event_id'],payload))
            db.execute('INSERT INTO attempts VALUES (?,?)',(value['event_id'],mode))
        body=json.dumps(dict(accepted=True,event_id=value['event_id'] if mode=='normal' else 'wrong-identity')).encode()
        self.send_response(200);self.send_header('Content-Length',str(len(body)));self.end_headers();self.wfile.write(body)

    def log_message(self,*args): pass


ThreadingHTTPServer(('127.0.0.1',port),Handler).serve_forever()
