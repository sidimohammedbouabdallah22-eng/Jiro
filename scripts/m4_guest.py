"""Isolated real-product qualification fixtures inside an owned disposable VM."""

import argparse
import hashlib
import json
import os
from pathlib import Path
import pwd
import re
import shutil
import subprocess
import sys
import tarfile
import time
import urllib.request


def command(arguments, data=None):
    result = subprocess.run([str(value) for value in arguments], input=data, text=True,
                            capture_output=True, timeout=600)
    if result.returncode:
        raise RuntimeError(f"{arguments[0]} failed: {result.stderr[-2000:]}")
    return result.stdout


def wait_http(url, timeout=240):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            with urllib.request.urlopen(url, timeout=5) as response:
                return response.read()
        except (OSError, ValueError):
            time.sleep(1)
    raise RuntimeError("fixture did not become available")


def relays(fixture):
    network=fixture['tag']+'-internal'
    for name in ['dvwa','wordpress','keycloak']:
        unit=fixture['tag']+'-'+name+'-relay'
        subprocess.run(['systemctl','stop',unit],capture_output=True)
        info=json.loads(command(['docker','inspect',fixture['containers'][name]]))[0]
        address=info['NetworkSettings']['Networks'][network]['IPAddress']
        port=8080 if name=='keycloak' else 80
        command(['systemd-run','--collect','--unit='+unit,'--property=DynamicUser=yes',
            '/usr/bin/socat',f"TCP-LISTEN:{fixture['ports'][name]},bind=127.0.0.1,reuseaddr,fork,max-children=32",f'TCP:{address}:{port}'])


def realm(fixture):
    """Use Keycloak's conditional LoA flows, including mandatory OTP for level 2."""
    def execution(authenticator, priority, config=None):
        value = dict(authenticator=authenticator, requirement="REQUIRED", priority=priority,
                     authenticatorFlow=False, userSetupAllowed=False)
        if config:
            value["authenticatorConfig"] = config
        return value

    flows = [dict(alias="owaf-browser", providerId="basic-flow", topLevel=True, builtIn=False,
                  authenticationExecutions=[dict(flowAlias="owaf-password", authenticatorFlow=True,
                    requirement="CONDITIONAL", priority=10), dict(flowAlias="owaf-otp", authenticatorFlow=True,
                    requirement="CONDITIONAL", priority=20)])]
    for name, level, authenticator in [("owaf-password", "1", "auth-username-password-form"),
                                        ("owaf-otp", "2", "auth-otp-form")]:
        flows.append(dict(alias=name, providerId="basic-flow", topLevel=False, builtIn=False,
            authenticationExecutions=[execution("conditional-level-of-authentication", 10, "loa-"+level),
                                      execution(authenticator, 20)]))
    return dict(realm="openwaf-lab", enabled=True, sslRequired="none", registrationAllowed=False,
        browserFlow="owaf-browser", authenticationFlows=flows,
        authenticatorConfig=[dict(alias="loa-"+level, config={"loa-condition-level":level,"loa-max-age":"0"}) for level in ["1","2"]],
        attributes={"acr.loa.map":json.dumps({"1":1,"2":2})},
        clients=[dict(clientId="openwaf", enabled=True, publicClient=True, standardFlowEnabled=True,
            directAccessGrantsEnabled=False, redirectUris=[fixture["admin_origin"]+"/auth/oidc/callback"],
            webOrigins=[fixture["admin_origin"]], attributes={"pkce.code.challenge.method":"S256","acr.loa.map":json.dumps({"1":1,"2":2})})],
        roles=dict(realm=[dict(name="administrator")]),
        users=[dict(id=fixture["subject"], username="organization-user", enabled=True,realmRoles=["administrator"],
            firstName="Qualification", lastName="User", email="qualification@example.invalid", emailVerified=True,
            credentials=[dict(type="password", value=fixture["password"], temporary=False),
                dict(type="otp", secretData=json.dumps({"value":fixture["otp_secret"]}),
                    credentialData=json.dumps(dict(subType="totp", digits=6, counter=0, period=30, algorithm="HmacSHA1")))])])


def setup(root, fixture, package):
    if root.exists():
        raise RuntimeError("qualification directory already exists")
    if shutil.disk_usage(root.parent).free<5<<30:
        raise RuntimeError('application qualification requires 5 GiB free guest disk')
    if hashlib.sha256(Path(package).read_bytes()).hexdigest()!=fixture['package_sha256']:
        raise RuntimeError('guest package checksum mismatch')
    required=command(['systemctl','show','openwaf.service','-p','Requires','--value']).split()
    owned=[name for name in required if re.fullmatch(r'openwaf-m2-(backend|events|audit)-[a-f0-9]{8}\.service',name)]
    command(['systemctl','stop','openwaf.service',*owned])
    root.mkdir(mode=0o755)
    identity = pwd.getpwnam("openwaf")
    (root/"state").mkdir(mode=0o700)
    os.chown(root/"state",identity.pw_uid,identity.pw_gid)
    (root/"fixture.json").write_text(json.dumps(fixture))
    (root/"fixture.json").chmod(0o600)
    (root/"guest.py").write_bytes(Path(__file__).read_bytes())
    (root/"guest.py").chmod(0o600)
    (root/"realm.json").write_text(json.dumps(realm(fixture)))
    (root/"realm.json").chmod(0o600)
    os.chown(root/"realm.json",1000,1000)
    names = {name:fixture["tag"]+"-"+name for name in ["db","dvwa","wordpress","keycloak"]}
    fixture["containers"] = names
    (root/"fixture.json").write_text(json.dumps(fixture))
    network=fixture["tag"]+"-internal"
    command(["docker","network","create","--internal","--label","openwaf.qualification="+fixture["tag"],network])
    images=fixture["images"]
    def run(name, parameters, arguments=()):
        return command(["docker","run","-d","--name",names[name],"--label","openwaf.qualification="+fixture["tag"],
            "--network",network,"--security-opt","no-new-privileges",*parameters,images[name],*arguments])
    run("db",["--network-alias","db","--memory","512m","-e","MARIADB_ROOT_PASSWORD="+fixture["db_password"]])
    deadline=time.monotonic()+120
    while time.monotonic()<deadline:
        try:
            command(["docker","exec",names["db"],"sh","-c",'mariadb -uroot -p"$MARIADB_ROOT_PASSWORD" -e "SELECT 1"'])
            break
        except RuntimeError:
            time.sleep(1)
    else:
        raise RuntimeError("database startup failed")
    sql="\n".join(f"CREATE DATABASE {name}; CREATE USER '{name}'@'%' IDENTIFIED BY '{fixture['db_password']}'; GRANT ALL ON {name}.* TO '{name}'@'%';" for name in ["dvwa","wordpress"])
    command(["docker","exec","-i",names["db"],"sh","-c",'exec mariadb -uroot -p"$MARIADB_ROOT_PASSWORD"'],sql)
    run("dvwa",["--memory","384m", "-e","DB_SERVER=db",
        "-e","DB_USER=dvwa","-e","DB_PASSWORD="+fixture["db_password"],"-e","DB_DATABASE=dvwa",
        "-e","DEFAULT_SECURITY_LEVEL=low","-e","DISABLE_AUTHENTICATION=false"])
    extra="define('WP_HOME', "+repr(fixture["wordpress_origin"])+"); define('WP_SITEURL', "+repr(fixture["wordpress_origin"])+"); define('WP_ENVIRONMENT_TYPE', 'local');"
    run("wordpress",["--memory","512m",
        "-e","WORDPRESS_DB_HOST=db","-e","WORDPRESS_DB_NAME=wordpress","-e","WORDPRESS_DB_USER=wordpress",
        "-e","WORDPRESS_DB_PASSWORD="+fixture["db_password"],"-e","WORDPRESS_CONFIG_EXTRA="+extra])
    run("keycloak",["--memory","1g",
        "-v",str(root/"realm.json")+":/opt/keycloak/data/import/realm.json:ro",
        "-e","KC_BOOTSTRAP_ADMIN_USERNAME=lab-admin","-e","KC_BOOTSTRAP_ADMIN_PASSWORD="+fixture["password"],
        "-e","JAVA_OPTS_KC_HEAP=-Xms128m -Xmx512m"],
        ["start-dev","--import-realm","--hostname="+fixture["idp_origin"],"--features=step-up-authentication"])
    relays(fixture)
    wait_http(f"http://127.0.0.1:{fixture['ports']['dvwa']}/login.php")
    wait_http(f"http://127.0.0.1:{fixture['ports']['wordpress']}/wp-admin/install.php")
    bootstrap="<?php define('WP_INSTALLING',true); require '/var/www/html/wp-load.php'; require '/var/www/html/wp-admin/includes/upgrade.php'; "
    bootstrap+="if(!is_blog_installed()){wp_install('OpenWAF qualification','site-admin','qualification@example.invalid',false,'',"+repr(fixture["password"])+");} "
    bootstrap+="update_option('permalink_structure','/%postname%/'); flush_rewrite_rules(); $user=get_user_by('login','site-admin'); $result=WP_Application_Passwords::create_new_application_password($user->ID,['name'=>'OpenWAF lab']); echo json_encode(['application_password'=>$result[0]]);"
    result=command(["docker","exec","-i","-u","www-data",names["wordpress"],"php"],bootstrap)
    fixture["wordpress_app_password"]=json.loads(result[result.index('{'):])["application_password"]
    wait_http(fixture["idp_origin"]+"/realms/openwaf-lab/.well-known/openid-configuration")
    binary=root/"waf-server"
    with tarfile.open(package) as archive:
        binary.write_bytes(archive.extractfile("usr/lib/openwaf/waf-server").read())
    binary.chmod(0o755)
    fixture["server_sha256"]=hashlib.sha256(binary.read_bytes()).hexdigest()
    policy=dict(mode="enforcing",paranoia=1,inbound_threshold=5,outbound_threshold=4,request_limit=1048576,
        response_limit=1048576,inspect_response=False,exclusions=[],custom_rules="",scoped_exceptions=[])
    applications=[dict(application_id=name,name=name,hosts=[host],upstream=f"http://127.0.0.1:{fixture['ports'][name]}",policy=policy.copy())
        for name,host in [("dvwa","127.0.0.1"),("wordpress","localhost")]]
    path=root/"state/policy.json"
    path.write_text(json.dumps(dict(schema_version=2,revision=1,applications=applications)))
    os.chown(path,identity.pw_uid,identity.pw_gid)
    path.chmod(0o600)
    config=dict(origin=fixture["admin_origin"],passkey_rp_id="localhost",oidc=dict(issuer=fixture["idp_origin"]+"/realms/openwaf-lab",client_id="openwaf",required_acr="2"))
    path=root/"authentication.json"
    path.write_text(json.dumps(config))
    os.chown(path,0,identity.pw_gid)
    path.chmod(0o640)
    (root/"admin-token").write_text(fixture["token"])
    (root/"admin-token").chmod(0o600)
    unit=fixture["tag"]+".service"
    Path('/etc/systemd/system/'+unit).write_text(f"[Service]\nUser=openwaf\nGroup=openwaf\nLoadCredential=admin-token:{root}/admin-token\nExecStart={binary} -config={root}/state/policy.json -event-db={root}/state/events.db -admin=127.0.0.1:{fixture['ports']['admin']} -listen=127.0.0.1:{fixture['ports']['proxy']} -auth-config={root}/authentication.json -admin-token-file=${{CREDENTIALS_DIRECTORY}}/admin-token\nNoNewPrivileges=yes\nPrivateTmp=yes\nProtectSystem=strict\nReadWritePaths={root}/state\n")
    command(["systemctl","daemon-reload"])
    command(["systemctl","start",unit])
    fixture["containers"]=names
    (root/"fixture.json").write_text(json.dumps(fixture))
    print(json.dumps(fixture))


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('operation',choices=['setup','start','stop'])
    parser.add_argument('--root',type=Path,required=True)
    parser.add_argument('--package')
    args=parser.parse_args()
    if os.getuid()!=0 or not re.fullmatch(r'/var/lib/owaf-m4-[a-f0-9]{8}',str(args.root)) or command(['systemd-detect-virt','--vm']).strip()!='oracle':
        raise RuntimeError('requires an owned disposable VirtualBox guest')
    if args.operation=='setup':
        setup(args.root,json.load(sys.stdin),args.package)
    elif args.operation=='start':
        fixture=json.loads((args.root/'fixture.json').read_text())
        command(['docker','start',*fixture['containers'].values()])
        relays(fixture)
        wait_http(fixture['idp_origin']+'/realms/openwaf-lab/.well-known/openid-configuration')
        command(['systemctl','start',fixture['tag']+'.service'])
        print(json.dumps(dict(started=True)))
    else:
        fixture=json.loads((args.root/'fixture.json').read_text())
        subprocess.run(['systemctl','stop',fixture['tag']+'.service'],capture_output=True)
        for name in ['dvwa','wordpress','keycloak']:
            subprocess.run(['systemctl','stop',fixture['tag']+'-'+name+'-relay'],capture_output=True)
        ids=command(['docker','ps','-q','--filter','label=openwaf.qualification='+fixture['tag']]).split()
        if ids:
            command(['docker','stop',*ids])
        print(json.dumps(dict(stopped=True)))


if __name__=='__main__':
    main()
