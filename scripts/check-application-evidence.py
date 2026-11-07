"""Verify the fresh real-product/provider report and exact packaged executable."""
import argparse
import hashlib
import json
from pathlib import Path
import tarfile


EXPECTED={
 'DVWA benign authenticated lookup':{'status':200},
 'DVWA SQL injection direct exploit and WAF block':{'protected_status':403},
 'DVWA reflected XSS direct exploit and WAF block':{'baseline_executable_markup':True,'protected_status':403},
 'DVWA command injection direct execution and WAF block':{'baseline_marker':True,'protected_status':403},
 'DVWA executable upload baseline and WAF verdict':{'baseline_execution':True,'protected_status':403},
 'DVWA harmless text upload':{'status':200},
 'WordPress authenticated REST publish with rich text':{'status':201},
 'WordPress search and multilingual punctuation':{'status':200},
 'WordPress multipart media upload':{'status':201,'download_sha_verified':True},
 'WordPress REST deletion requires explicit method policy':{'baseline_status':403},
 'WordPress REST update and deletion after scoped method tuning':{'updated':True,'deleted':True},
 'WordPress method tuning preserves other route and payload checks':{'unrelated_delete_blocked':True,'allowed_route_xss_blocked':True},
 'WordPress attack outside an editing workflow':{'status':403},
 'Keycloak password plus OTP, LoA2 and local application grants':{'provider_mfa':True,'acr':'2','local_role':'viewer','application_isolation':True},
 'Keycloak genuine password-only LoA1 rejected for required LoA2':{'weaker_provider_assurance_rejected':True},
 'Local unlink revokes a real Keycloak session':{'session_revoked':True},
 'Real Keycloak signing-key rotation refreshes verification keys':{'changed':True},
 'Real provider token expiry bounds the OpenWAF session':{'real_time_expiry_observed':True,'token_lifespan_seconds':30},
 'Disabling a local account revokes an existing real SSO session':{'subsequent_request_revoked':True},
 'Provider account disable blocks new sign-in; local sessions remain bounded':{'new_sign_in_rejected':True,'existing_session_requires_local_revocation_or_expiry':True},
 'Provider outage rejects code exchange and preserves traffic and local recovery':{'exchange_failed_closed':True,'inspection_available':True,'local_administrator_available':True,'provider_recovery_passed':True},
 'Pilot collector uses a scoped token and rejects bootstrap monitoring':{'scoped_monitoring_passed':True,'bootstrap_rejected':True,'database_contains_no_bearer_secrets':True,'business_pilot_started':False},
}


def check(path,package):
    report=json.loads(path.read_text()); assert report['passed'] and report['provider_settings_restored']
    digest=hashlib.sha256(package.read_bytes()).hexdigest()
    assert digest==Path(str(package)+'.sha256').read_text().split()[0]==report['package_sha256']
    with tarfile.open(package) as archive:
        member=archive.getmember('usr/lib/openwaf/waf-server')
        assert member.isfile() and member.size<=256<<20
        assert hashlib.sha256(archive.extractfile(member).read()).hexdigest()==report['server_sha256']
    cases={case['name']:case for case in report['cases']}
    assert len(cases)==len(report['cases'])==len(EXPECTED) and set(cases)==set(EXPECTED)
    for name,expectations in EXPECTED.items():
        assert cases[name]['passed']
        for key,value in expectations.items(): assert cases[name][key]==value, name+': '+key
    assert cases['DVWA SQL injection direct exploit and WAF block']['baseline_rows']>1
    rotation=cases['Real Keycloak signing-key rotation refreshes verification keys']
    assert rotation['before_kid'] and rotation['after_kid'] and rotation['before_kid']!=rotation['after_kid']
    sources={'tools/application-check/check.cjs','tools/application-check/images.lock.json',
        'scripts/m4_guest.py','scripts/m4_idp.py','scripts/qualify-applications.py','scripts/pilot.py'}
    assert set(report['source_sha256'])==sources
    for name,expected in report['source_sha256'].items():
        assert hashlib.sha256((path.parent/'source'/name).read_bytes()).hexdigest()==expected
    images=json.loads((path.parent/'source/tools/application-check/images.lock.json').read_text())
    assert report['images']=={name:item['image'] for name,item in images.items()}
    return dict(verified=True,cases=len(cases),server_sha256=report['server_sha256'],package_sha256=digest,
        source_snapshots_verified=True,provider_settings_restored=True,business_pilot_started=False,
        scope='Isolated loopback/public-client provider; customer TLS/factor recovery remains open',
        report_sha256=hashlib.sha256(path.read_bytes()).hexdigest(),verifier_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest())


if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('report',type=Path);p.add_argument('--package',type=Path,required=True)
    args=p.parse_args();print(json.dumps(check(args.report,args.package),indent=2))
