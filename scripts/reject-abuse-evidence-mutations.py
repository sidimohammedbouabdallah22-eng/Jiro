"""Prove the CPU-abuse verifier rejects false claims; retain every altered proof."""
import argparse
import copy
import importlib.util
import json
from pathlib import Path


def main():
    if not __debug__:
        raise RuntimeError('verification requires Python assertions; do not use -O')
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('report',type=Path)
    p.add_argument('--package',type=Path,required=True);args=p.parse_args()
    spec=importlib.util.spec_from_file_location('abusecheck',Path(__file__).with_name('check-joint-abuse-evidence.py'))
    checker=importlib.util.module_from_spec(spec);spec.loader.exec_module(checker)
    assert checker.check(args.report,args.package)['passed']
    base=json.loads(args.report.read_text())
    positions={p['name']:i for i,p in enumerate(base['phases'])}
    unicode_index=positions['unicode-one-slot'];oversize_index=positions['bounded-oversize-unicode'];small_index=positions['bounded-small-escaped-unicode']
    def erp(report,index):
        return next(a for a in report['phases'][index]['policy']['applications'] if a['application_id']=='dolibarr')
    mutations={
        'body-limit':lambda r:erp(r,oversize_index)['policy'].__setitem__('request_limit',1048576),
        'body-hash':lambda r:r['phases'][unicode_index].__setitem__('body_sha256','0'*64),
        'storefront-budget':lambda r:r['phases'][unicode_index].__setitem__('storefront_budget_passed',not r['phases'][unicode_index]['storefront_budget_passed']),
        'application-state':lambda r:r['customers_after'].__setitem__('sha256','0'*64),
        'rate-limit':lambda r:erp(r,small_index)['traffic_controls'].__setitem__('requests_per_second',0),
        'resource-window':lambda r:r['phases'][unicode_index]['guest_begin'].__setitem__('monotonic',r['phases'][unicode_index]['guest_begin']['monotonic']+30),
        'receipt-total':lambda r:r['final_status']['storage']['export'].__setitem__('acked_occurrences',0),
        'process-identity':lambda r:r['phases'][unicode_index]['resources']['processes']['gateway'].__setitem__('pid',99999999),
        'source-hash':lambda r:r['sources'].__setitem__('qualify-joint-abuse.py','0'*64),
        'restoration':lambda r:r.__setitem__('policy_restored',False),
    }
    cases=[]
    for name,mutate in mutations.items():
        report=copy.deepcopy(base);mutate(report)
        path=args.report.parent/('rejected-proof-'+name+'.json')
        assert not path.exists(),'refuse to overwrite retained negative proof'
        path.write_text(json.dumps(report))
        try:checker.check(path,args.package)
        except AssertionError:cases.append(dict(name=name,rejected=True))
        else:raise AssertionError('verifier accepted false evidence: '+name)
    result=dict(passed=True,cases=cases,checker_sha256=checker.sha(Path(checker.__file__).read_bytes()),
                scope='deliberately false proof reports; these files are not qualification results')
    (args.report.parent/'verifier-negative-tests.json').write_text(json.dumps(result,indent=2)+'\n')
    print('Valid evidence accepted; ten false CPU-abuse claims rejected')


if __name__=='__main__':main()
