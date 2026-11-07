"""Reject false responsiveness, upload, identity and event-accounting claims."""
import argparse
import copy
import importlib.util
import json
from pathlib import Path


def main():
    if not __debug__:raise RuntimeError('verification requires assertions')
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('report',type=Path);p.add_argument('--package',type=Path,required=True);a=p.parse_args()
    spec=importlib.util.spec_from_file_location('faircheck',Path(__file__).with_name('check-joint-fairness-evidence.py'))
    checker=importlib.util.module_from_spec(spec);spec.loader.exec_module(checker)
    assert checker.check(a.report,a.package)['evidence_verified'];base=json.loads(a.report.read_text())
    mutations={
        'large-body-envelope':lambda r:r['phases'][3]['policy']['applications'][0]['policy'].__setitem__('request_limit',65536),
        'real-peer-identity':lambda r:r['lanes']['attacker'].__setitem__('peer','198.51.100.200'),
        'file-roundtrip':lambda r:r['uploads'][0].__setitem__('passed',False),
        'workflow-latency':lambda r:r['phases'][3].__setitem__('upload_workflow_p95_ms',1),
        'simultaneous-targets':lambda r:r['phases'][3].__setitem__('targets',['prestashop']),
        'relay-cpu':lambda r:r['phases'][3]['resources'].__setitem__('component_cpu_percent',0),
        'committed-files':lambda r:r['files_verified'].__setitem__('files',0),
        'receipt-occurrences':lambda r:r['final_status']['storage']['export'].__setitem__('acked_occurrences',0),
        'business-state':lambda r:r['store_after']['orders'].__setitem__('sha256','0'*64),
        'source-hash':lambda r:r['sources'].__setitem__('qualify-joint-fairness.py','0'*64),
    }
    if 'client_buffer_mib' in base['limits']:
        mutations['client-buffer-limit']=lambda r:r['limits'].__setitem__('client_buffer_mib',8192)
        mutations['client-burst-limit']=lambda r:r['limits'].__setitem__('client_burst',0)
    if base.get('sampler_version',1)==2:
        mutations['sampler-version']=lambda r:r.__setitem__('sampler_version',1)
    cases=[]
    for name,mutate in mutations.items():
        r=copy.deepcopy(base);mutate(r);path=a.report.parent/('rejected-proof-'+name+'.json')
        assert not path.exists(),'retain existing negative evidence'
        path.write_text(json.dumps(r))
        try:checker.check(path,a.package)
        except AssertionError:cases.append(dict(name=name,rejected=True))
        else:raise AssertionError('false claim accepted: '+name)
    result=dict(passed=True,cases=cases,checker_sha256=checker.sha(Path(checker.__file__).read_bytes()))
    (a.report.parent/'verifier-negative-tests.json').write_text(json.dumps(result,indent=2)+'\n');print(str(len(cases))+' false fairness/upload claims rejected')


if __name__=='__main__':main()
