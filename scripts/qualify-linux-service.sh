#!/bin/bash
# Exercise a staged package with a uniquely named disposable systemd service.
set -euo pipefail
if [[ $(id -u) != 0 || $# != 1 ]]; then
    echo 'Usage as root: qualify-linux-service.sh /absolute/package.tar.gz' >&2
    exit 1
fi
package=$(realpath "$1")
stage=$(mktemp -d /var/lib/openwaf-qualification-stage.XXXXXXXX)
unit="openwaf-qualification-${stage##*.}"
qa_user="owafqa${stage##*.}"
qa_user_created=0
state="/var/lib/$unit"
unit_file="/run/systemd/system/$unit.service"
upstream_pid=''
audit_receiver_pid=''
cleanup() {
    code=$?
    if [[ $code != 0 ]]; then
        journalctl -u "$unit.service" --no-pager -n 35 >&2 || true
        if [[ -f $stage/audit-collector.log ]]; then tail -n 20 "$stage/audit-collector.log" >&2; fi
    fi
    systemctl stop "$unit.service" >/dev/null 2>&1 || true
    if [[ -n $upstream_pid ]]; then kill "$upstream_pid" 2>/dev/null || true; wait "$upstream_pid" 2>/dev/null || true; fi
    if [[ -n $audit_receiver_pid ]]; then kill "$audit_receiver_pid" 2>/dev/null || true; wait "$audit_receiver_pid" 2>/dev/null || true; fi
    rm -f -- "$unit_file"
    systemctl daemon-reload
    systemctl reset-failed "$unit.service" >/dev/null 2>&1 || true
    if [[ $qa_user_created == 1 && $qa_user == owafqa* ]]; then
        userdel -- "$qa_user" 2>/dev/null || true
        groupdel -- "$qa_user" 2>/dev/null || true
    fi
    # Resolve each owned test directory before recursive cleanup.
    if [[ $(realpath -m "$state") == "/var/lib/$unit" && $unit == openwaf-qualification-* ]]; then rm -rf -- "$state"; fi
    if [[ $(realpath "$stage") == /var/lib/openwaf-qualification-stage.* ]]; then rm -rf -- "$stage"; fi
    exit "$code"
}
trap cleanup EXIT
chmod 0755 "$stage"
mkdir "$stage/package"
tar -xzf "$package" -C "$stage/package"
DESTDIR="$stage/root" sh "$stage/package/install.sh"
if DESTDIR="$stage/root" sh "$stage/package/install.sh" >"$stage/reinstall.log" 2>&1; then
    echo 'Installer overwrote an existing installation' >&2; exit 1
fi
systemd-sysusers --root="$stage/root" "$stage/root/usr/lib/sysusers.d/openwaf.conf" >/dev/null
if getent passwd "$qa_user" >/dev/null || getent group "$qa_user" >/dev/null; then echo 'Qualification account already exists' >&2; exit 1; fi
systemd-sysusers --inline "u $qa_user - \"OpenWAF disposable qualification\" /nonexistent /usr/sbin/nologin"
qa_user_created=1
mkdir -p "$stage/root/etc/openwaf/tls/current"
openssl rand -hex 32 >"$stage/root/etc/openwaf/admin-token"
chmod 0600 "$stage/root/etc/openwaf/admin-token"
openssl rand -hex 32 >"$stage/root/etc/openwaf/audit-export-token"
chmod 0600 "$stage/root/etc/openwaf/audit-export-token"
printf 'header = "Authorization: Bearer %s"\n' "$(cat "$stage/root/etc/openwaf/admin-token")" >"$stage/auth.curl"
chmod 0600 "$stage/auth.curl"
issue_pair() {
    local path=$1
    mkdir -p "$path"
    openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes \
        -keyout "$path/privkey.pem" -out "$path/fullchain.pem" -days 90 -subj /CN=application.test \
        -addext subjectAltName=DNS:application.test,DNS:portal.test -addext basicConstraints=critical,CA:FALSE \
        -addext extendedKeyUsage=serverAuth -addext keyUsage=digitalSignature >/dev/null 2>&1
}
issue_pair "$stage/root/etc/openwaf/tls/current"
chmod 0640 "$stage/root/etc/openwaf/tls/current/privkey.pem"
chgrp -R "$qa_user" "$stage/root/etc/openwaf/tls"
read -r admin_port proxy_port audit_port < <(python3 - <<'PY'
import socket
with socket.socket() as a, socket.socket() as b,socket.socket() as c:
    a.bind(('127.0.0.1',0)); b.bind(('127.0.0.1',0));c.bind(('127.0.0.1',0))
    print(a.getsockname()[1],b.getsockname()[1],c.getsockname()[1])
PY
)
python3 - "$stage/upstream-port" <<'PY' &
import http.server,json,sys
class Handler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        if self.path.startswith('/identity'):
            self.send_header('Content-Type','application/json'); self.end_headers()
            self.wfile.write(json.dumps(dict(client=self.headers.get('X-Forwarded-For'),real=self.headers.get('X-Real-IP'),scheme=self.headers.get('X-Forwarded-Proto'),spoof=self.headers.get('True-Client-IP'))).encode())
        else:
            self.send_header('Content-Type','text/plain'); self.end_headers(); self.wfile.write(b'qualification backend')
    def log_message(self,*args): pass
server=http.server.HTTPServer(('127.0.0.1',0),Handler)
with open(sys.argv[1],'w') as file: file.write(str(server.server_port))
server.serve_forever()
PY
upstream_pid=$!
for _ in {1..100}; do [[ -s "$stage/upstream-port" ]] && break; sleep 0.05; done
upstream_port=$(cat "$stage/upstream-port")
"$stage/root/usr/lib/openwaf/event-collector" -token-file "$stage/root/etc/openwaf/audit-export-token" -listen "127.0.0.1:$audit_port" -db "$stage/independent-audit.db" >"$stage/audit-collector.log" 2>&1 &
audit_receiver_pid=$!
python3 - "$audit_port" <<'PY'
import socket,sys,time
for attempt in range(600):
    try:
        with socket.create_connection(('127.0.0.1',int(sys.argv[1])),timeout=.1):break
    except OSError:time.sleep(.1)
else:raise RuntimeError('Audit collector did not start')
PY
cat >"$stage/root/etc/openwaf/openwaf.env" <<EOF
OPENWAF_LISTEN=127.0.0.1:$proxy_port
OPENWAF_ADMIN=127.0.0.1:$admin_port
OPENWAF_TRUSTED_PROXIES=
OPENWAF_AUDIT_EXPORT_URL=http://127.0.0.1:$audit_port/v1/events
OPENWAF_TLS_CERT=$stage/root/etc/openwaf/tls/current/fullchain.pem
OPENWAF_TLS_KEY=$stage/root/etc/openwaf/tls/current/privkey.pem
OPENWAF_TLS_HOSTNAMES=application.test
EOF
mkdir -m 0700 "$state"
python3 - "$state/policy.json" "$upstream_port" <<'PY'
import json,sys
policy=dict(schema_version=1,application_id='primary',revision=1,name='Linux qualification',upstream='http://127.0.0.1:'+sys.argv[2],mode='enforcing',paranoia=1,inbound_threshold=5,outbound_threshold=4,request_limit=1048576,response_limit=1048576,inspect_response=False,exclusions=[],custom_rules='',scoped_exceptions=[])
with open(sys.argv[1],'w') as file: json.dump(policy,file)
PY
chown -R "$qa_user:$qa_user" "$state"
sed -e "s|/var/lib/openwaf|$state|g" \
    -e "s|/usr/lib/openwaf/|$stage/root/usr/lib/openwaf/|g" \
    -e "s|/etc/openwaf/|$stage/root/etc/openwaf/|g" \
    -e "s|StateDirectory=openwaf|StateDirectory=$unit|" \
    -e "s|User=openwaf|User=$qa_user|" -e "s|Group=openwaf|Group=$qa_user|" \
    "$stage/root/usr/lib/systemd/system/openwaf.service" >"$unit_file"
sed -i "/^\[Install\]/i LoadCredential=audit-export-token:$stage/root/etc/openwaf/audit-export-token\n" "$unit_file"
sed -i '/^ExecStart=/s|$| -audit-export-token-file=${CREDENTIALS_DIRECTORY}/audit-export-token|' "$unit_file"
systemd-analyze verify "$unit_file"
systemctl daemon-reload
systemctl start "$unit.service"
api() { curl --silent --show-error --fail --config "$stage/auth.curl" "http://127.0.0.1:$admin_port/api/v1/$1"; }
wait_ready() {
    for _ in {1..600}; do
        if api health >"$stage/health.json" 2>/dev/null && python3 -c 'import json,sys; x=json.load(open(sys.argv[1]));sys.exit(not (x["ready"] and x["healthy"]))' "$stage/health.json"; then return; fi
        sleep 0.1
    done
    echo 'Service failed readiness' >&2; return 1
}
wait_ready
pid=$(systemctl show "$unit.service" -p MainPID --value)
[[ $(stat -c %u "/proc/$pid") == "$(id -u "$qa_user")" && $(id -u "$qa_user") != 0 ]]
grep -q 'NoNewPrivs:[[:space:]]*1' "/proc/$pid/status"
if grep -zq OPENWAF_ADMIN_TOKEN "/proc/$pid/environ"; then echo 'Credential leaked into environment' >&2; exit 1; fi
tls_request() { curl --silent --show-error --noproxy '*' --resolve "application.test:$proxy_port:127.0.0.1" --cacert "$1" "https://application.test:$proxy_port${2:-/}"; }
old_cert="$stage/original.pem"
cp "$stage/root/etc/openwaf/tls/current/fullchain.pem" "$old_cert"
[[ $(tls_request "$old_cert") == 'qualification backend' ]]
status=$(curl --silent --noproxy '*' --resolve "application.test:$proxy_port:127.0.0.1" --cacert "$old_cert" -o /dev/null -w '%{http_code}' "https://application.test:$proxy_port/?q=%3Cscript%3Ealert(1)%3C%2Fscript%3E")
[[ $status == 403 ]]
api certificates >"$stage/before.json"
issue_pair "$stage/renewed"
# A half-published pair must preserve the original active certificate.
install -m 0644 "$stage/renewed/fullchain.pem" "$stage/root/etc/openwaf/tls/current/fullchain.pem"
systemctl reload "$unit.service"
for _ in {1..50}; do api certificates >"$stage/failed.json"; if python3 -c 'import json,sys;sys.exit(not json.load(open(sys.argv[1])).get("last_error"))' "$stage/failed.json"; then break; fi; sleep 0.1; done
python3 - "$stage/before.json" "$stage/failed.json" <<'PY'
import json,sys
a,b=(json.load(open(x)) for x in sys.argv[1:])
assert a['sha256']==b['sha256'] and b['last_error'] and not b['healthy']
PY
[[ $(tls_request "$old_cert") == 'qualification backend' ]]
install -m 0640 -g "$qa_user" "$stage/renewed/privkey.pem" "$stage/root/etc/openwaf/tls/current/privkey.pem"
systemctl reload "$unit.service"
wait_ready
api certificates >"$stage/after.json"
python3 - "$stage/before.json" "$stage/after.json" <<'PY'
import json,sys
a,b=(json.load(open(x)) for x in sys.argv[1:])
assert a['sha256']!=b['sha256'] and b['healthy']
PY
[[ $(tls_request "$stage/renewed/fullchain.pem") == 'qualification backend' ]]
api config >"$stage/config.json"
python3 - "$stage/config.json" "$stage/apply.json" <<'PY'
import json,sys
config=json.load(open(sys.argv[1]));config['name']='Qualified Linux policy'
with open(sys.argv[2],'w') as file: json.dump(dict(config=config,reason='isolated service qualification'),file)
PY
curl --silent --show-error --fail --config "$stage/auth.curl" -H 'Content-Type: application/json' --data-binary "@$stage/apply.json" "http://127.0.0.1:$admin_port/api/v1/config/apply" >"$stage/applied.json"
systemctl restart "$unit.service"
wait_ready
api audit >"$stage/audit.json"
python3 - "$stage/audit.json" <<'PY'
import json,sys
items=json.load(open(sys.argv[1]))['items']
assert any(x['operation']=='policy.activate' and x['outcome']=='success' and x['revision']==2 for x in items)
assert any(x['operation']=='certificate.activate' and x['outcome']=='rejected' for x in items)
assert sum(x['operation']=='service.started' for x in items)==2
PY
printf '\nOPENWAF_TRUSTED_PROXIES=127.0.0.1/32\n' >>"$stage/root/etc/openwaf/openwaf.env"
systemctl restart "$unit.service"
wait_ready
curl --silent --show-error --fail --noproxy '*' --resolve "application.test:$proxy_port:127.0.0.1" --cacert "$stage/renewed/fullchain.pem" \
    -H 'X-Forwarded-For: 198.51.100.99, 203.0.113.7' -H 'X-Forwarded-Proto: https' \
    -H 'X-Real-IP: 198.51.100.99' -H 'True-Client-IP: 198.51.100.99' \
    "https://application.test:$proxy_port/identity" >"$stage/identity.json"
python3 - "$stage/identity.json" <<'PY'
import json,sys
x=json.load(open(sys.argv[1])); assert x['client']=='203.0.113.7' and x['real']==x['client'] and x['scheme']=='https' and x['spoof'] is None
PY
status=$(curl --silent --noproxy '*' --resolve "application.test:$proxy_port:127.0.0.1" --cacert "$stage/renewed/fullchain.pem" \
    -H 'X-Forwarded-For: unknown' -o /dev/null -w '%{http_code}' "https://application.test:$proxy_port/")
[[ $status == 400 ]]
status=$(curl --silent --noproxy '*' --resolve "application.test:$proxy_port:127.0.0.1" --cacert "$stage/renewed/fullchain.pem" \
    -H 'X-Forwarded-For: 203.0.113.7' -o /dev/null -w '%{http_code}' "https://application.test:$proxy_port/?q=%3Cscript%3Ealert(1)%3C%2Fscript%3E")
[[ $status == 403 ]]
api events >"$stage/identity-events.json"
api status >"$stage/identity-status.json"
api audit >"$stage/identity-audit.json"
python3 - "$stage/identity-events.json" "$stage/identity-status.json" "$stage/identity-audit.json" <<'PY'
import json,sys
events,status,audit=(json.load(open(path)) for path in sys.argv[1:])
assert any(e['ip']=='203.0.113.7' and e.get('peer_ip')=='127.0.0.1' and e['action']=='blocked' for e in events)
identity=status['client_identity']; assert identity['trusted_networks']==['127.0.0.1/32']
assert any(e['operation']=='service.started' and e.get('resource')==identity['config_sha256'] for e in audit['items'])
PY
api config >"$stage/legacy-policy.json"
python3 - "$stage/legacy-policy.json" "$stage/migrate.json" <<'PY'
import json,sys
c=json.load(open(sys.argv[1]))
keys=['mode','paranoia','inbound_threshold','outbound_threshold','request_limit','response_limit','inspect_response','exclusions','custom_rules','scoped_exceptions']
app=dict(application_id=c['application_id'],name=c['name'],hosts=['application.test'],upstream=c['upstream'],policy={k:c[k] for k in keys})
deployment=dict(schema_version=2,revision=c['revision'],applications=[app])
with open(sys.argv[2],'w') as file: json.dump(dict(config=deployment,reason='Qualify explicit hostname migration'),file)
PY
curl --silent --show-error --fail --config "$stage/auth.curl" -H 'Content-Type: application/json' --data-binary "@$stage/migrate.json" "http://127.0.0.1:$admin_port/api/v1/config/apply" >"$stage/migrated.json"
python3 - "$stage/create-app.json" "$upstream_port" <<'PY'
import json,sys
with open(sys.argv[1],'w') as file: json.dump(dict(revision=3,application_id='portal',name='Qualified portal',hosts=['portal.test'],upstream='http://127.0.0.1:'+sys.argv[2],reason='Qualify isolated application creation'),file)
PY
curl --silent --show-error --fail --config "$stage/auth.curl" -H 'Content-Type: application/json' --data-binary "@$stage/create-app.json" "http://127.0.0.1:$admin_port/api/v1/applications" >"$stage/created.json"
python3 - "$stage/created.json" "$stage/enforce-app.json" <<'PY'
import json,sys
c=json.load(open(sys.argv[1])); p=c['applications'][1]['policy']
assert p['mode']=='detection'
p['mode']='enforcing';p['custom_rules']='SecRule REQUEST_URI "@streq /portal-only" "id:10001,phase:1,deny,status:403,log,msg:\'Portal only\'"'
with open(sys.argv[2],'w') as file: json.dump(dict(config=c,reason='Qualify isolated portal enforcement'),file)
PY
curl --silent --show-error --fail --config "$stage/auth.curl" -H 'Content-Type: application/json' --data-binary "@$stage/enforce-app.json" "http://127.0.0.1:$admin_port/api/v1/config/apply" >"$stage/enforced.json"
for hostname in application.test portal.test; do
    status=$(curl --silent --show-error --noproxy '*' --resolve "$hostname:$proxy_port:127.0.0.1" --cacert "$stage/renewed/fullchain.pem" -o /dev/null -w '%{http_code}' "https://$hostname:$proxy_port/portal-only")
    if [[ $hostname == portal.test ]]; then [[ $status == 403 ]]; else [[ $status == 200 ]]; fi
done
status=$(curl --silent --show-error --noproxy '*' --resolve "application.test:$proxy_port:127.0.0.1" --cacert "$stage/renewed/fullchain.pem" -H 'Host: portal.test' -o /dev/null -w '%{http_code}' "https://application.test:$proxy_port/")
[[ $status == 421 ]]
status=$(curl --silent --show-error --noproxy '*' --resolve "application.test:$proxy_port:127.0.0.1" --cacert "$stage/renewed/fullchain.pem" -H 'Host: unknown.test' -o /dev/null -w '%{http_code}' "https://application.test:$proxy_port/")
[[ $status == 421 ]]
api 'events/search?application=portal' >"$stage/portal-events.json"
python3 - "$stage/portal-events.json" <<'PY'
import json,sys
items=json.load(open(sys.argv[1]))['items']; assert items and all(e['application_id']=='portal' for e in items)
assert any(e['host'].startswith('portal.test') and e['action']=='blocked' for e in items)
PY
api config >"$stage/before-controls.json"
python3 - "$stage/before-controls.json" "$stage/controls.json" <<'PY'
import json,sys
c=json.load(open(sys.argv[1]));c['applications'][0]['traffic_controls']=dict(requests_per_second=1,burst=1,client_requests_per_second=0,client_burst=0,max_concurrent=1,max_client_concurrent=1)
with open(sys.argv[2],'w') as file: json.dump(dict(config=c,reason='Qualify bounded traffic controls'),file)
PY
curl --silent --show-error --fail --config "$stage/auth.curl" -H 'Content-Type: application/json' --data-binary "@$stage/controls.json" "http://127.0.0.1:$admin_port/api/v1/config/apply" >"$stage/controlled.json"
for expected in 200 429; do
    status=$(curl --silent --show-error --noproxy '*' --resolve "application.test:$proxy_port:127.0.0.1" --cacert "$stage/renewed/fullchain.pem" -o /dev/null -w '%{http_code}' "https://application.test:$proxy_port/")
    [[ $status == "$expected" ]]
done
python3 - "$admin_port" "$stage/root/etc/openwaf/admin-token" "$stage/account-password" <<'PY'
import http.cookiejar,json,os,secrets,sys,urllib.request,urllib.error
base='http://127.0.0.1:'+sys.argv[1]+'/api/v1/'
token=open(sys.argv[2]).read().strip();password=secrets.token_urlsafe(32)
with os.fdopen(os.open(sys.argv[3],os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600),'w') as file:file.write(password)
def call(opener,path,data=None,bootstrap=False):
    headers={'Content-Type':'application/json'}
    if bootstrap:headers['Authorization']='Bearer '+token
    request=urllib.request.Request(base+path,data=None if data is None else json.dumps(data).encode(),headers=headers)
    try:
        with opener.open(request) as response:return response.status,json.load(response)
    except urllib.error.HTTPError as error:return error.code,None
root=urllib.request.build_opener()
for role in ['administrator','operator','viewer']:
    code,directory=call(root,'accounts',bootstrap=True);assert code==200
    code,_=call(root,'accounts',dict(revision=directory['revision'],username=role,role=role,disabled=False,password=password,reason='Packaged service account qualification'),True);assert code==200
viewer=urllib.request.build_opener(urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar()))
operator=urllib.request.build_opener(urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar()))
for client,name in [(viewer,'viewer'),(operator,'operator')]:assert call(client,'login',dict(username=name,password=password))[0]==200
assert call(viewer,'config')[0]==200 and call(viewer,'config/validate',{})[0]==403
assert call(viewer,'accounts')[0]==403 and call(operator,'accounts',{})[0]==403
assert call(operator,'certificates/reload',{})[0]==403
code,c=call(operator,'config');assert code==200
c['applications'][1]['name']='Operator qualified portal'
assert call(operator,'config/apply',dict(config=c,reason='Named operator service policy change'))[0]==200
code,directory=call(root,'accounts',bootstrap=True);assert code==200
assert call(root,'accounts',dict(revision=directory['revision'],username='operator',role='operator',disabled=True,password='',reason='Revoke operator session'),True)[0]==200
assert call(operator,'me')[0]==401
code,audit=call(root,'audit',bootstrap=True);assert code==200
assert any(e['operation']=='policy.activate' and e['actor']=='account operator' and e['outcome']=='success' for e in audit['items'])
PY
systemctl restart "$unit.service"
wait_ready
api events >"$stage/pre-recovery-events.json"
systemctl stop "$unit.service"
admin="$stage/root/usr/lib/openwaf/waf-admin"
server="$stage/root/usr/lib/openwaf/waf-server"
"$admin" backup -config "$state/policy.json" -binary "$server" -out "$stage/checkpoint" >"$stage/backup.json"
"$admin" verify -backup "$stage/checkpoint" >"$stage/verify.json"
"$admin" upgrade-check -backup "$stage/checkpoint" -candidate "$server" >"$stage/upgrade.json"
"$admin" rollback -backup "$stage/checkpoint" -out "$stage/rollback" >"$stage/rollback.json"
python3 - "$stage/checkpoint/manifest.json" "$stage/rollback/state/policy.json.audit.jsonl" <<'PY'
import json,sys
manifest=json.load(open(sys.argv[1]))
assert manifest['state']['audit']['records']>0
assert manifest['state']['audit']['export_destination_sha256']
assert manifest['state']['accounts']['count']==3 and manifest['state']['policy']['traffic_controls']
records=[json.loads(line) for line in open(sys.argv[2])]
assert records[-1]['hash']==manifest['state']['audit']['last_hash']
PY
chown -R "$qa_user:$qa_user" "$stage/rollback"
sed -i "s|$state/policy.json|$stage/rollback/state/policy.json|g" "$unit_file"
sed -i "/^ExecStart=/s|$| -event-db=$stage/rollback/state/events.db|" "$unit_file"
# Place the writable restored-state allowance inside the Service section.
sed -i "/^\[Install\]/i ReadWritePaths=$stage/rollback\n" "$unit_file"
systemctl daemon-reload
systemctl start "$unit.service"
wait_ready
api config >"$stage/restored-config.json"
api events >"$stage/restored-events.json"
python3 - "$stage/pre-recovery-events.json" "$stage/restored-events.json" <<'PY'
import json,sys
before={event['id'] for event in json.load(open(sys.argv[1]))}
after={event['id'] for event in json.load(open(sys.argv[2]))}
assert before and before<=after, 'Restored service lost checkpoint security events'
PY
python3 - "$stage/restored-config.json" <<'PY'
import json,sys
x=json.load(open(sys.argv[1])); assert x['revision']==7 and x['schema_version']==2
assert len(x['applications'])==2 and x['applications'][0]['name']=='Qualified Linux policy'
assert x['applications'][0]['traffic_controls']['requests_per_second']==1
PY
[[ $(tls_request "$stage/renewed/fullchain.pem") == 'qualification backend' ]]
python3 - "$admin_port" "$stage/account-password" <<'PY'
import json,sys,urllib.request,urllib.error
base='http://127.0.0.1:'+sys.argv[1]+'/api/v1/login';password=open(sys.argv[2]).read()
for name,expected in [('viewer',200),('operator',401)]:
    request=urllib.request.Request(base,data=json.dumps(dict(username=name,password=password)).encode(),headers={'Content-Type':'application/json'})
    try:
        with urllib.request.urlopen(request) as response:status=response.status
    except urllib.error.HTTPError as error:status=error.code
    assert status==expected
PY
api status >"$stage/audit-delivery.json"
systemctl stop "$unit.service"
python3 - "$stage/rollback/state/policy.json.audit.jsonl" "$stage/independent-audit.db" "$stage/audit-delivery.json" <<'PY'
import json,sqlite3,sys,time
records=[json.loads(line) for line in open(sys.argv[1])]
source=records[0]['hash'][:32]
status=json.load(open(sys.argv[3]));assert status['audit_export']['enabled']
with sqlite3.connect(sys.argv[2]) as db:
    for attempt in range(100):
        delivered={row[0]:json.loads(row[1]) for row in db.execute('SELECT id,data FROM collected_events WHERE source_id=?',(source,))}
        if all(record['id'] in delivered and record==delivered[record['id']] for record in records):break
        time.sleep(.1)
    else:raise AssertionError('Restored audit records were not independently retained')
    assert len(delivered)==len({record['id'] for record in delivered.values()})
PY
echo 'PASS: packaged service, TLS renewal, application/rate controls, local roles/revocation, credential-file audit export, preserved independent audit receipts across checkpoint restore and service cutover.'
