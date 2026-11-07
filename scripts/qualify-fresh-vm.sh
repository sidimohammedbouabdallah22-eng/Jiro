#!/bin/bash
# Install into real service paths on an explicitly disposable, native Linux VM.
set -euo pipefail
if [[ $(id -u) != 0 || $# != 2 || $2 != --disposable-vm ]]; then
    echo 'Usage as root: qualify-fresh-vm.sh /absolute/package.tar.gz --disposable-vm' >&2
    exit 1
fi
if grep -qi microsoft /proc/sys/kernel/osrelease || ! systemd-detect-virt --vm >/dev/null; then
    echo 'Fresh-VM qualification requires a native disposable VM.' >&2; exit 1
fi
for target in /etc/openwaf /var/lib/openwaf /usr/lib/openwaf /usr/lib/systemd/system/openwaf.service; do
    if [[ -e $target || -L $target ]]; then echo "Fresh-install precondition failed at $target" >&2; exit 1; fi
done
if systemctl cat openwaf.service >/dev/null 2>&1 || getent passwd openwaf >/dev/null || getent group openwaf >/dev/null; then
    echo 'Fresh-install precondition failed for service identity.' >&2; exit 1
fi
package=$(realpath "$1")
stage=$(mktemp -d /tmp/openwaf-fresh-vm.XXXXXXXX)
chmod 0700 "$stage"
backend_pid=''
installed=0
cleanup() {
    result=$?
    if [[ $installed == 1 ]]; then
        if [[ $result != 0 ]]; then journalctl -u openwaf.service --no-pager -n 50 >&2 || true; fi
        systemctl stop openwaf.service >/dev/null 2>&1 || true
    fi
    if [[ -n $backend_pid ]]; then kill "$backend_pid" 2>/dev/null || true; wait "$backend_pid" 2>/dev/null || true; fi
    exit "$result"
}
trap cleanup EXIT
mkdir "$stage/package"
tar -xzf "$package" -C "$stage/package"
sh "$stage/package/install.sh"
installed=1
if sh "$stage/package/install.sh" >"$stage/reinstall.log" 2>&1; then echo 'Existing installation was overwritten' >&2; exit 1; fi
python3 - "$stage/ports" <<'PY'
import socket,sys
with socket.socket() as first,socket.socket() as second:
    first.bind(('127.0.0.1',0));second.bind(('127.0.0.1',0))
    open(sys.argv[1],'w').write(str(first.getsockname()[1])+' '+str(second.getsockname()[1])+'\n')
PY
read -r admin_port proxy_port <"$stage/ports"
python3 - "$stage/backend-port" <<'PY' &
import http.server,sys
class Handler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200);self.send_header('Content-Type','text/plain');self.end_headers();self.wfile.write(b'fresh-vm backend')
    def log_message(self,*args):pass
server=http.server.ThreadingHTTPServer(('127.0.0.1',0),Handler)
open(sys.argv[1],'w').write(str(server.server_port))
server.serve_forever()
PY
backend_pid=$!
for _ in {1..100}; do [[ -s "$stage/backend-port" ]] && break; sleep 0.05; done
backend_port=$(cat "$stage/backend-port")
mkdir -p /etc/openwaf/tls/current
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -days 90 -subj /CN=application.test \
    -addext subjectAltName=DNS:application.test -addext basicConstraints=critical,CA:FALSE \
    -addext extendedKeyUsage=serverAuth -addext keyUsage=digitalSignature \
    -keyout /etc/openwaf/tls/current/privkey.pem -out /etc/openwaf/tls/current/fullchain.pem >/dev/null 2>&1
chgrp -R openwaf /etc/openwaf/tls
chmod 0640 /etc/openwaf/tls/current/privkey.pem
cat >/etc/openwaf/openwaf.env <<EOF
OPENWAF_LISTEN=127.0.0.1:$proxy_port
OPENWAF_ADMIN=127.0.0.1:$admin_port
OPENWAF_TRUSTED_PROXIES=
OPENWAF_TLS_CERT=/etc/openwaf/tls/current/fullchain.pem
OPENWAF_TLS_KEY=/etc/openwaf/tls/current/privkey.pem
OPENWAF_TLS_HOSTNAMES=application.test
EOF
install -d -m 0700 -o openwaf -g openwaf /var/lib/openwaf
python3 - "$backend_port" <<'PY'
import json,sys
policy=dict(mode='enforcing',paranoia=1,inbound_threshold=5,outbound_threshold=4,request_limit=1048576,response_limit=1048576,inspect_response=False,exclusions=[],custom_rules='',scoped_exceptions=[])
application=dict(application_id='fresh-vm',name='Fresh VM',hosts=['application.test'],upstream='http://127.0.0.1:'+sys.argv[1],policy=policy)
with open('/var/lib/openwaf/policy.json','w') as file:json.dump(dict(schema_version=2,revision=1,applications=[application]),file)
PY
chown openwaf:openwaf /var/lib/openwaf/policy.json
chmod 0600 /var/lib/openwaf/policy.json
printf 'header = "Authorization: Bearer %s"\n' "$(cat /etc/openwaf/admin-token)" >"$stage/auth.curl"
chmod 0600 "$stage/auth.curl"
api() { curl --silent --show-error --fail --config "$stage/auth.curl" "http://127.0.0.1:$admin_port/api/v1/$1"; }
wait_ready() {
    for _ in {1..600}; do
        if api health >"$stage/health.json" 2>/dev/null && python3 -c 'import json,sys;assert json.load(open(sys.argv[1]))["healthy"]' "$stage/health.json" 2>/dev/null; then return; fi
        sleep 0.1
    done
    echo 'Fresh service did not become healthy' >&2; return 1
}
systemd-analyze verify /usr/lib/systemd/system/openwaf.service
systemctl start openwaf.service
wait_ready
pid=$(systemctl show openwaf.service -p MainPID --value)
[[ $(stat -c %u "/proc/$pid") == "$(id -u openwaf)" && $(id -u openwaf) != 0 ]]
grep -q 'NoNewPrivs:[[:space:]]*1' "/proc/$pid/status"
if grep -zq OPENWAF_ADMIN_TOKEN "/proc/$pid/environ"; then echo 'Administrator credential leaked into environment' >&2; exit 1; fi
request() { curl --silent --show-error --noproxy '*' --resolve "application.test:$proxy_port:127.0.0.1" --cacert /etc/openwaf/tls/current/fullchain.pem "$@"; }
[[ $(request "https://application.test:$proxy_port/") == 'fresh-vm backend' ]]
[[ $(request -o /dev/null -w '%{http_code}' "https://application.test:$proxy_port/?q=%3Cscript%3Ealert(1)%3C%2Fscript%3E") == 403 ]]
systemctl restart openwaf.service
wait_ready
api events >"$stage/events.json"
python3 - "$stage/events.json" <<'PY'
import json,sys
assert any(event['action']=='blocked' and event['application_id']=='fresh-vm' for event in json.load(open(sys.argv[1])))
PY
systemctl stop openwaf.service
/usr/lib/openwaf/waf-admin backup -config /var/lib/openwaf/policy.json -binary /usr/lib/openwaf/waf-server -out "$stage/checkpoint" >"$stage/backup.json"
/usr/lib/openwaf/waf-admin verify -backup "$stage/checkpoint" >"$stage/verify.json"
/usr/lib/openwaf/waf-admin upgrade-check -backup "$stage/checkpoint" -candidate /usr/lib/openwaf/waf-server >"$stage/upgrade.json"
/usr/lib/openwaf/waf-admin rollback -backup "$stage/checkpoint" -out "$stage/rollback" >"$stage/rollback.json"
install -d -m 0700 -o openwaf -g openwaf /var/lib/openwaf/recovered
cp -a "$stage/rollback/state/." /var/lib/openwaf/recovered/
chown -R openwaf:openwaf /var/lib/openwaf/recovered
mkdir -p /etc/systemd/system/openwaf.service.d
cat >/etc/systemd/system/openwaf.service.d/90-qualification-restore.conf <<EOF
[Service]
ExecStart=
ExecStart=/usr/lib/openwaf/waf-server -config=/var/lib/openwaf/recovered/policy.json -event-db=/var/lib/openwaf/recovered/events.db -admin-token-file=\${CREDENTIALS_DIRECTORY}/admin-token -admin=127.0.0.1:$admin_port -listen=127.0.0.1:$proxy_port -tls-cert=/etc/openwaf/tls/current/fullchain.pem -tls-key=/etc/openwaf/tls/current/privkey.pem -tls-hostnames=application.test
EOF
systemctl daemon-reload
systemctl start openwaf.service
wait_ready
[[ $(request "https://application.test:$proxy_port/") == 'fresh-vm backend' ]]
api events >"$stage/restored-events.json"
python3 - "$stage/events.json" "$stage/restored-events.json" <<'PY'
import json,sys
before={event['id'] for event in json.load(open(sys.argv[1]))}
after={event['id'] for event in json.load(open(sys.argv[2]))}
assert before and before<=after, 'Restored service lost checkpoint security events'
PY
printf 'PASS fresh VM installation and restored-service cutover, architecture=%s distribution=%s\n' "$(uname -m)" "$(. /etc/os-release; echo "$ID-$VERSION_ID")"
