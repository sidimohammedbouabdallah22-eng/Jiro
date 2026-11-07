"""Reject fabricated priority, byte-budget and recovery claims in boundary evidence."""
import argparse
import copy
import importlib.util
import json
from pathlib import Path


def main():
    if not __debug__:
        raise RuntimeError('verification requires assertions')
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('report',type=Path);p.add_argument('--package',type=Path,required=True);a=p.parse_args()
    source=Path(__file__).with_name('check-joint-multisource-evidence.py')
    spec=importlib.util.spec_from_file_location('boundary',source)
    checker=importlib.util.module_from_spec(spec);spec.loader.exec_module(checker)
    assert checker.check(a.report,a.package)['evidence_verified']
    base=json.loads(a.report.read_text())
    mutations={
        'universal-priority':lambda r:r['held_boundary'].__setitem__('admission_guarantee',True),
        'occupied-slots':lambda r:r['held_boundary']['occupied_resources'].__setitem__('active',0),
        'charged-buffers':lambda r:r['held_boundary']['occupied_resources'].__setitem__('reserved_buffer_bytes',0),
        'legitimate-refusal':lambda r:r['held_boundary'].__setitem__('legitimate_upload_status',200),
        'held-body-size':lambda r:r['held_boundary'].__setitem__('body_bytes',900<<10),
        'client-buffer-limit':lambda r:r['limits'].__setitem__('client_buffer_mib',8192),
        'refused-file-absence':lambda r:r['files_verified'].__setitem__('refused_files_absent',0),
        'drained-queue':lambda r:r['final_status']['resources'].__setitem__('pending_admissions',1),
        'receipt-count':lambda r:r['final_status']['storage']['export'].__setitem__('acked_occurrences',0),
        'protected-state':lambda r:r['store_after']['orders'].__setitem__('sha256','0'*64),
    }
    cases=[]
    for name,mutate in mutations.items():
        report=copy.deepcopy(base);mutate(report)
        path=a.report.parent/('rejected-boundary-'+name+'.json')
        assert not path.exists(),'retain existing negative evidence'
        path.write_text(json.dumps(report))
        try:
            checker.check(path,a.package)
        except AssertionError:
            cases.append(dict(name=name,rejected=True))
        else:
            raise AssertionError('false boundary claim accepted: '+name)
    result=dict(passed=True,cases=cases,checker_sha256=checker.sha(source.read_bytes()))
    (a.report.parent/'boundary-negative-tests.json').write_text(json.dumps(result,indent=2)+'\n')
    print(str(len(cases))+' false boundary claims rejected')


if __name__=='__main__':
    main()
