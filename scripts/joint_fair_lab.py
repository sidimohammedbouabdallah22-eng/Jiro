"""Real peer-address lanes on top of the unchanged joint business fixture."""
import http.client
import json
import shlex
import socket
import subprocess
import time

from joint_business_lab import Lab,sha


class FairLab(Lab):
    def __init__(self,package,sources,vcpus=1,upstream_trace=False,lane_connections=16):
        super().__init__(package,sources,vcpus=vcpus)
        self.lanes={};self.lane_tunnel=None
        self.upstream_trace=upstream_trace;self.trace_started=False
        assert lane_connections in [16,64]
        self.lane_connections=lane_connections

    def lanes_guest(self,op,data=None):
        command=shlex.join(['sudo','python3',self.remote+'/m4_joint_fair_guest.py',op,'--root',self.root])
        return json.loads(self.run([*self.ssh,command],None if data is None else json.dumps(data)).stdout)

    def start(self):
        super().start()
        listeners=[socket.socket() for _ in range(4)]
        for s in listeners:s.bind(('127.0.0.1',0))
        peers=['127.0.0.2','127.0.0.3','127.0.0.10','127.0.0.11']
        self.lanes={name:dict(port=s.getsockname()[1],peer=peer) for name,s,peer in
                    zip(['upload','storefront','attacker','second-attacker'],listeners,peers)}
        for s in listeners:s.close()
        if self.lane_connections!=16:
            for lane in self.lanes.values():lane['max_children']=self.lane_connections
        self.lanes=self.lanes_guest('setup',self.lanes)
        forwarding=[]
        for lane in self.lanes.values():
            port=lane['port'];forwarding+=['-L',f'127.0.0.1:{port}:127.0.0.1:{port}']
        self.lane_tunnel=self.create_tunnel(forwarding)
        time.sleep(1)
        assert self.lane_tunnel is None or self.lane_tunnel.poll() is None
        self.report['lanes']=self.lanes
        self.report['measurement_note']='source-relay service cgroups include all children in the legacy containers map'
        if self.upstream_trace:
            ports=[self.fixture[name]['ports']['app'] for name in ['dolibarr','prestashop']]
            self.trace_unit='owaf-trace-'+self.tag+'.service'
            self.run([*self.ssh,shlex.join(['sudo','install','-m','600','/dev/null',self.root+'/upstream.private.pcap'])])
            command=['sudo','systemd-run','--collect','--unit='+self.trace_unit,
                     '--property=MemoryMax=64M','--property=RuntimeMaxSec=900',
                     '/usr/bin/tcpdump','-i','lo','-nn','-U','-s','96','-c','100000',
                     '-w',self.root+'/upstream.private.pcap',
                     'tcp and (port '+str(ports[0])+' or port '+str(ports[1])+')']
            self.run([*self.ssh,shlex.join(command)])
            self.trace_started=True
            self.report['diagnostic_trace_only']=True
        self.save()

    def capture(self):
        if self.trace_started:
            self.run([*self.ssh,shlex.join(['sudo','systemctl','stop',self.trace_unit])])
            data=subprocess.run([str(x) for x in [*self.ssh,'sudo cat '+self.root+'/upstream.private.pcap']],capture_output=True,timeout=60)
            assert data.returncode==0 and 24<=len(data.stdout)<=16<<20
            (self.out/'upstream.private.pcap').write_bytes(data.stdout)
            self.report['upstream_trace']=dict(sha256=sha(data.stdout),bytes=len(data.stdout),stopped=True)
            self.trace_started=False
        super().capture()

    def send(self,app,label,method,path,body=None,headers=None,validate=None):
        lane_name=getattr(self.timing,'lane','upload' if app=='dolibarr' else 'storefront')
        lane=self.lanes[lane_name];start=time.perf_counter();due=getattr(self.timing,'due',start)
        row=dict(app=app,label=label,sequence=getattr(self.timing,'sequence',None),lane=lane_name,peer=lane['peer'],
                 role=getattr(self.timing,'role','control'),start_delay_ms=(start-due)*1000,
                 request_bytes=len(body or b''),request_sha256=sha(body or b''),status=0,valid=False)
        c=http.client.HTTPConnection('127.0.0.1',lane['port'],timeout=45)
        try:
            c.request(method,path,body,{'Host':('erp' if app=='dolibarr' else 'shop')+'.joint.test:'+str(self.ports['proxy']),
                      'Content-Type':'application/json','User-Agent':'OpenWAF owned sustained fairness qualification',**(headers or {})})
            r=c.getresponse();data=r.read((2<<20)+1);assert len(data)<=2<<20
            row.update(status=r.status,response_bytes=len(data),response_sha256=sha(data),request_id=r.getheader('X-OpenWAF-Request-ID'))
            if r.status in [429,503]:
                known={b'Application admission share exhausted\n':'application_capacity',
                       b'Client concurrency share exhausted\n':'client_concurrency',
                       b'Client buffer share exhausted\n':'client_buffer',
                       b'Client request body rate exceeded\n':'request_body_rate',
                       b'Application or client request rate exceeded\n':'request_rate'}
                row['refusal_class']=known.get(data,'other')
            row['valid']=bool(validate(r.status,data)) if validate else True
            return r.status,data
        except Exception as error:
            row['error']=type(error).__name__;raise
        finally:
            end=time.perf_counter();row.update(service_ms=(end-start)*1000,scheduled_ms=(end-due)*1000)
            with self.lock:self.records.append(row)
            c.close()

    def close(self):
        if self.attempted:
            if 'capture' not in self.report:
                try:self.report['failure_status']=self.admin('status');self.capture()
                except Exception as error:self.report['failure_capture_error']=type(error).__name__
            try:self.report['lanes_cleanup']=self.lanes_guest('stop')
            except Exception as error:self.report['lanes_cleanup']=dict(stopped=False,error=type(error).__name__);self.report['passed']=False
        if self.lane_tunnel:self.lane_tunnel.terminate();self.lane_tunnel.wait(timeout=20)
        super().close()
