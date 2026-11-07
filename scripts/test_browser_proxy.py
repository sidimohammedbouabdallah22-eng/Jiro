"""Regression coverage for Playwright HTTP tunneling and browser cache framing."""
import http.client
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import threading
from types import SimpleNamespace
import unittest

from browser_proxy import BrowserProxy


class ProxyTests(unittest.TestCase):
    def test_http_connect_head_and_not_modified(self):
        content = b'owned asset'

        class Backend(BaseHTTPRequestHandler):
            def log_message(self, *args):
                pass

            def do_GET(self):
                if self.path == '/cached':
                    self.send_response(304)
                    self.end_headers()
                else:
                    self.send_response(200)
                    self.send_header('Content-Length',str(len(content)))
                    self.end_headers()
                    self.wfile.write(content)

            def do_HEAD(self):
                self.send_response(200)
                self.send_header('Content-Length',str(len(content)))
                self.end_headers()

        backend = ThreadingHTTPServer(('127.0.0.1',0),Backend)
        thread = threading.Thread(target=backend.serve_forever,daemon=True)
        thread.start()
        lab = SimpleNamespace(ports={'proxy':43210},records=[],lock=threading.Lock(),
            lanes={'upload':dict(port=backend.server_port,peer='127.0.0.2')})
        proxy = BrowserProxy(lab)
        self.assertEqual(proxy.server.request_queue_size,128)
        proxy.start()
        try:
            for method,path,status,length,body in [
                ('GET','/asset',200,str(len(content)),content),
                ('HEAD','/asset',200,str(len(content)),b''),
                ('GET','/cached',304,None,b''),
            ]:
                connection = http.client.HTTPConnection('127.0.0.1',proxy.server.server_port,timeout=5)
                connection.set_tunnel('erp.joint.test',43210)
                connection.request(method,path)
                response = connection.getresponse()
                self.assertEqual(response.status,status)
                self.assertEqual(response.getheader('Content-Length'),length)
                self.assertEqual(response.read(),body)
                connection.close()
            proxy.wait_idle()
            self.assertEqual(len(lab.records),3)
            self.assertTrue(all(row['app']=='dolibarr' and row['valid'] for row in lab.records))
            denied = http.client.HTTPConnection('127.0.0.1',proxy.server.server_port,timeout=5)
            denied.request('CONNECT','outside.example:443')
            self.assertEqual(denied.getresponse().status,403)
            denied.close()
        finally:
            proxy.close()
            backend.shutdown()
            backend.server_close()
            thread.join(timeout=5)


if __name__ == '__main__':
    unittest.main()
