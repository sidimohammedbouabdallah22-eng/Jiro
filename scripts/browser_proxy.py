"""Bounded local HTTP proxy for Chromium through actual source-bound lab lanes."""
import hashlib
import http.client
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import threading
import time
from urllib.parse import urlsplit


class BrowserProxy:
    def __init__(self, lab, lane_name='upload'):
        self.lab = lab
        self.profile = 'startup'
        assert lane_name in lab.lanes
        self.lane_name = lane_name
        self.blocked = []
        self.slots = threading.BoundedSemaphore(64)
        self.condition = threading.Condition()
        self.active = 0
        self.saturated = 0
        owner = self

        class Handler(BaseHTTPRequestHandler):
            protocol_version = 'HTTP/1.1'
            timeout = 45

            def log_message(self, *args):
                pass

            def do_CONNECT(self):
                target = urlsplit('http://' + self.path)
                if target.hostname not in ['erp.joint.test','shop.joint.test'] or target.port != lab.ports['proxy']:
                    owner.blocked.append(dict(profile=owner.profile, host=target.hostname))
                    self.send_error(403)
                    return
                self.tunnel_origin = 'http://' + self.path
                self.send_response(200,'Connection established')
                self.end_headers()
                self.close_connection = False

            def forward(self):
                target = urlsplit(self.path)
                if not target.scheme and hasattr(self,'tunnel_origin'):
                    target = urlsplit(self.tunnel_origin + self.path)
                apps = {'erp.joint.test': 'dolibarr', 'shop.joint.test': 'prestashop'}
                if target.scheme != 'http' or target.hostname not in apps or target.port != lab.ports['proxy']:
                    owner.blocked.append(dict(profile=owner.profile, host=target.hostname))
                    self.send_error(403)
                    return
                app = apps[target.hostname]
                lane_name = owner.lane_name
                lane = lab.lanes[lane_name]
                length = int(self.headers.get('Content-Length', '0'))
                if length < 0 or length > 2 << 20 or self.headers.get('Transfer-Encoding'):
                    self.send_error(400)
                    return
                body = self.rfile.read(length)
                if len(body) != length:
                    self.send_error(400)
                    return
                if not owner.slots.acquire(timeout=10):
                    owner.saturated += 1
                    self.send_error(503)
                    return
                with owner.condition:
                    owner.active += 1
                path = target.path + ('?' + target.query if target.query else '')
                hop = {'host','connection','proxy-connection','proxy-authorization','transfer-encoding','content-length'}
                headers = {k:v for k,v in self.headers.items() if k.lower() not in hop}
                headers['Host'] = target.netloc
                headers['Content-Length'] = str(len(body))
                start = time.perf_counter()
                row = dict(app=app,label=owner.profile,role='browser',lane=lane_name,peer=lane['peer'],
                           method=self.command,path=target.path,request_bytes=len(body),status=0,valid=False)
                if target.path == '/api/index.php/documents/upload':
                    row['request_sha256'] = hashlib.sha256(body).hexdigest()
                connection = http.client.HTTPConnection('127.0.0.1', lane['port'], timeout=45)
                try:
                    connection.request(self.command,path,body or None,headers)
                    response = connection.getresponse()
                    data = response.read((8 << 20) + 1)
                    if len(data) > 8 << 20:
                        raise ValueError('response_limit')
                    row.update(status=response.status,response_bytes=len(data),
                               response_sha256=hashlib.sha256(data).hexdigest(),
                               request_id=response.getheader('X-OpenWAF-Request-ID'),
                               valid=200 <= response.status < 400)
                    try:
                        self.send_response(response.status)
                        for key,value in response.getheaders():
                            if key.lower() not in hop:
                                self.send_header(key,value)
                        if response.status not in [204,304] and self.command != 'HEAD':
                            self.send_header('Content-Length',str(len(data)))
                        elif self.command == 'HEAD' and response.getheader('Content-Length') is not None:
                            self.send_header('Content-Length',response.getheader('Content-Length'))
                        self.send_header('Connection','close')
                        self.end_headers()
                        self.wfile.write(data)
                    except (BrokenPipeError,ConnectionResetError,ConnectionAbortedError):
                        row['browser_cancelled_delivery'] = True
                except Exception as error:
                    row['error'] = type(error).__name__
                    try:
                        self.send_error(502)
                    except OSError:
                        pass
                finally:
                    connection.close()
                    row['service_ms'] = (time.perf_counter()-start)*1000
                    with lab.lock:
                        lab.records.append(row)
                    owner.slots.release()
                    with owner.condition:
                        owner.active -= 1
                        owner.condition.notify_all()
                    self.close_connection = True

            do_GET = do_POST = do_PUT = do_DELETE = do_HEAD = forward

        class Server(ThreadingHTTPServer):
            request_queue_size = 128

        self.server = Server(('127.0.0.1',0),Handler)
        self.server.daemon_threads = True
        self.thread = threading.Thread(target=self.server.serve_forever,daemon=True)

    def start(self):
        self.thread.start()
        return 'http://127.0.0.1:'+str(self.server.server_port)

    def close(self):
        self.wait_idle()
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=5)

    def wait_idle(self):
        with self.condition:
            if not self.condition.wait_for(lambda: self.active == 0, timeout=50):
                raise RuntimeError('browser_proxy_did_not_drain')
