"""Synthetic watchdog tests; never count these as business pilot evidence."""
import hashlib
from contextlib import closing
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
from pathlib import Path
import sqlite3
import tempfile
import threading
import time
import unittest
from unittest.mock import patch

import pilot
import pilot_alerts as alerts


class AlertTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.manifest = dict(schema=1, pilot_id='synthetic', owner='Test', host='Test', qualification_evidence='Test', capacity_evidence='Test', management_url='http://localhost:1234', token_file=str(self.root/'monitor-token'), canaries=[dict(name='test',url='http://localhost:1234/canary',status=200,sha256=hashlib.sha256(b'ok').hexdigest())])
        (self.root/'manifest.json').write_text(json.dumps(self.manifest))
        (self.root/'webhook-token').write_text('webhook-private-secret')
        (self.root/'webhook-token').chmod(0o600)
        self.config = dict(schema=1,deployment='synthetic',pilot_manifest=str(self.root/'manifest.json'),pilot_database=str(self.root/'pilot.db'),webhook_url='http://localhost:1234/alerts',webhook_token_file=str(self.root/'webhook-token'))
        pilot.initialize(self.root/'pilot.db', self.manifest, time.time())
        self.state = self.root/'alerts.db'
        alerts.initialize(self.state,self.config)

    def tearDown(self):
        self.temp.cleanup()

    def sample(self, begin, healthy):
        with closing(sqlite3.connect(self.root/'pilot.db')) as db, db:
            db.execute('INSERT INTO samples VALUES (?,?,?,?)',(begin,begin+.01,int(healthy),json.dumps({'checks':{'gateway_health':{'ok':healthy}},'private':'must-never-leak'})))

    def record(self, now):
        with closing(sqlite3.connect(self.state)) as db, db:
            return alerts.record(db,self.config,now)

    def events(self):
        with closing(sqlite3.connect(self.state)) as db, db:
            return [(identity,json.loads(payload),acked) for identity,payload,acked in db.execute('SELECT id,payload,acked FROM outbox ORDER BY seq')]

    def test_failure_and_recovery_between_ticks_are_both_retained_and_deduplicated(self):
        now=time.time()
        self.sample(now-3,False);self.sample(now-1,True)
        self.assertIsNone(self.record(now))
        self.record(now+1)
        rows=self.events()
        self.assertEqual([r[1]['event'] for r in rows],['firing','resolved'])
        self.assertNotIn('must-never-leak',json.dumps(rows))
        self.assertNotIn('webhook-private-secret',json.dumps(rows))

    def test_stale_and_unavailable_evidence_alert_without_running_sampler(self):
        now=time.time();self.sample(now-200,True)
        self.assertEqual(self.record(now)['reason'],'samples_missing')
        changed=dict(self.config,pilot_database=str(self.root/'missing.db'))
        cursor,changes=alerts.observe(changed,-1,now)
        self.assertEqual(changes[-1][1]['reason'],'evidence_unavailable')
        self.assertFalse((self.root/'missing.db').exists())

    def test_pending_survives_process_restart_and_wrong_ack(self):
        now=time.time();self.sample(now-1,False);self.record(now)
        identity=self.events()[0][0]
        with patch.object(alerts,'deliver_one',return_value=False):
            self.assertEqual(alerts.run(self.state,self.config)['pending'],1)
        self.assertEqual(self.events()[0][0],identity)
        with patch.object(alerts,'deliver_one',return_value=True):
            self.assertEqual(alerts.run(self.state,self.config)['pending'],0)
        self.assertEqual(self.events()[0][2],1)

    def test_outbox_capacity_refuses_without_losing_cursor_or_pending(self):
        now=time.time();self.sample(now-1,False)
        with closing(sqlite3.connect(self.state)) as db, db:
            for number in range(alerts.MAX_PENDING):
                db.execute('INSERT INTO outbox(id,payload) VALUES (?,?)',(str(number),'{}'))
        with self.assertRaises(ValueError): self.record(now)
        self.assertEqual(len(self.events()),alerts.MAX_PENDING)
        with closing(sqlite3.connect(self.state)) as db, db:
            self.assertEqual(db.execute('SELECT cursor FROM meta').fetchone()[0],-1)

    def test_configuration_change_rejected(self):
        with self.assertRaises(ValueError):
            alerts.run(self.state,dict(self.config,deployment='different'))

    def test_real_ack_identity_and_redirect_checks(self):
        mode={'ack':'wrong'}
        class Receiver(BaseHTTPRequestHandler):
            def do_POST(self):
                value=json.loads(self.rfile.read(int(self.headers['Content-Length'])))
                if mode['ack']=='redirect':
                    self.send_response(307);self.send_header('Location','http://localhost:1/private');self.end_headers();return
                body=json.dumps({'accepted':True,'event_id':value['event_id'] if mode['ack']=='correct' else 'different'}).encode()
                self.send_response(200);self.send_header('Content-Length',str(len(body)));self.end_headers();self.wfile.write(body)
            def log_message(self,*args): pass
        server=ThreadingHTTPServer(('127.0.0.1',0),Receiver)
        thread=threading.Thread(target=server.serve_forever,daemon=True);thread.start()
        try:
            config=dict(self.config,webhook_url=f'http://127.0.0.1:{server.server_port}/alerts')
            self.assertFalse(alerts.deliver_one(config,json.dumps({'event_id':'sample'})))
            mode['ack']='redirect'
            self.assertFalse(alerts.deliver_one(config,json.dumps({'event_id':'sample'})))
            mode['ack']='correct'
            self.assertTrue(alerts.deliver_one(config,json.dumps({'event_id':'sample'})))
        finally:
            server.shutdown();server.server_close();thread.join()


if __name__=='__main__': unittest.main()
