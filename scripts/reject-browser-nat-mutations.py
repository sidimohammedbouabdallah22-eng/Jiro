"""Check that fabricated browser/NAT qualification claims are rejected."""
import argparse
import copy
import importlib.util
import json
from pathlib import Path


def main():
    if not __debug__:
        raise RuntimeError('verification requires assertions')
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('report',type=Path)
    parser.add_argument('--package',type=Path,required=True)
    args = parser.parse_args()
    spec = importlib.util.spec_from_file_location('browser_check',Path(__file__).with_name('check-browser-nat-evidence.py'))
    checker = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(checker)
    assert checker.check(args.report,args.package)['evidence_verified']
    original = json.loads(args.report.read_text())
    mutations = {
        'candidate-result':lambda r:r.__setitem__('candidate_browser_passed',not r['candidate_browser_passed']),
        'browser-outcome':lambda r:r['phases'][1].__setitem__('browser_passed',not r['phases'][1]['browser_passed']),
        'shared-source':lambda r:r['phases'][0].__setitem__('shared_nat',not r['phases'][0]['shared_nat']),
        'peer-address':lambda r:r['lanes']['upload'].__setitem__('peer','198.51.100.200'),
        'client-budget':lambda r:r['phases'][3]['policy']['applications'][0]['traffic_controls'].__setitem__('max_client_buffer_mib',8192),
        'browser-source':lambda r:r.__setitem__('browser_source_sha256','0'*64),
        'asset-evidence':lambda r:r['phases'][0].__setitem__('browser_result_sha256','0'*64),
        'resource-cost':lambda r:r['phases'][3].__setitem__('resources',dict(observed_cpu_percent=0)),
        'committed-file-count':lambda r:r['files_verified'].__setitem__('files',0),
        'receipt-count':lambda r:r['final_status']['storage']['export'].__setitem__('acked_records',-1),
        'business-state':lambda r:r['store_after']['orders'].__setitem__('sha256','0'*64),
        'cpu-restoration':lambda r:r.__setitem__('original_cpu_restored',False),
    }
    if 'gomaxprocs' in original.get('gateway_cpu_control',{}):
        mutations['gateway-parallelism'] = lambda r:r['gateway_cpu_control'].__setitem__(
            'gomaxprocs',2 if r['gateway_cpu_control']['gomaxprocs']==0 else 0)
    if original.get('lab_environment') == 'wsl2':
        mutations.pop('cpu-restoration')
        def spoof_virtualbox(report):
            report['lab_environment']='virtualbox'
            report['vm_powered_off']=True
            report['original_cpu_restored']=True
            report['guest_logical_cpus']=4
        mutations['wsl-virtualbox-claim'] = spoof_virtualbox
        mutations['wsl-allocation'] = lambda r:r['allocation_profile'].__setitem__('allocated_cpus',12)
        mutations['wsl-cleanup'] = lambda r:r.__setitem__('lab_stopped',False)
    if original.get('abuse_endurance'):
        mutations.update({
            'abuse-workers':lambda r:r['phases'][1].__setitem__('workers_per_target',0),
            'abuse-body':lambda r:r['phases'][1].__setitem__('abuse_body_sha256','0'*64),
            'abuse-targets':lambda r:r['phases'][3].__setitem__('targets',['prestashop']),
            'abuse-peer':lambda r:r['phases'][4].__setitem__('attack_lane','attacker'),
            'coverage':lambda r:r['phases'][1].__setitem__('coverage_passed',not r['phases'][1]['coverage_passed']),
            'latency':lambda r:r['phases'][1]['latency'].__setitem__('file_p95_ms',0),
            'abuse-qualification':lambda r:r.__setitem__('abuse_profile_qualified',not r['abuse_profile_qualified']),
            'resource-window':lambda r:r['phases'][1].__setitem__('resource_windows',[]),
            'resource-evidence':lambda r:r['phases'][1].__setitem__('resource_evidence_passed',not r['phases'][1]['resource_evidence_passed']),
            'external-qualification':lambda r:r.__setitem__('external_source_profile_qualified',not r['external_source_profile_qualified']),
        })
        if original.get('nat_limits',{}).get('client_body_kib_per_second'):
            mutations['body-byte-rate'] = lambda r:r['phases'][1]['policy']['applications'][0]['traffic_controls'].__setitem__('client_body_kib_per_second',0)
        if original.get('gateway_cpu_control'):
            mutations['native-cpu-cap'] = lambda r:r['gateway_cpu_control'].__setitem__('cpu_max','100000 100000')
    cases = []
    if 'baseline_qualified' in original:
        mutations['baseline-qualification'] = lambda r:r.__setitem__('baseline_qualified',not r['baseline_qualified'])
    browser_path = args.report.parent/original['phases'][0]['browser_result']
    browser_original = json.loads(browser_path.read_text())
    if browser_original.get('schedule_version') == 2:
        schedule_mutations = {
            'schedule-deadline':lambda b:b['waves'][1].__setitem__('scheduled_start_ms',1),
            'schedule-delay':lambda b:b['waves'][0].__setitem__('start_delay_ms',-1),
            'schedule-order':lambda b:b['waves'][1].__setitem__('wave',0),
            'schedule-duration':lambda b:b.__setitem__('work_elapsed_ms',0),
        }
        for name,mutate in schedule_mutations.items():
            browser = copy.deepcopy(browser_original)
            mutate(browser)
            data_path = args.report.parent/('invalid-browser-'+name+'.json')
            assert not data_path.exists(), 'retain existing negative browser evidence'
            data_path.write_text(json.dumps(browser))
            changed = copy.deepcopy(original)
            changed['phases'][0]['browser_result'] = data_path.name
            changed['phases'][0]['browser_result_sha256'] = checker.sha(data_path.read_bytes())
            path = args.report.parent/('rejected-browser-'+name+'.json')
            assert not path.exists(), 'retain existing negative evidence'
            path.write_text(json.dumps(changed))
            try:
                checker.check(path,args.package)
            except AssertionError:
                cases.append(dict(name=name,rejected=True))
            else:
                raise AssertionError('false browser timing accepted '+name)
    for name, mutate in mutations.items():
        changed = copy.deepcopy(original)
        mutate(changed)
        path = args.report.parent/('rejected-browser-'+name+'.json')
        assert not path.exists(), 'retain existing negative evidence'
        path.write_text(json.dumps(changed))
        try:
            checker.check(path,args.package)
        except AssertionError:
            cases.append(dict(name=name,rejected=True))
        else:
            raise AssertionError('false claim accepted '+name)
    result = dict(passed=True,cases=cases,checker_sha256=checker.sha(Path(checker.__file__).read_bytes()))
    (args.report.parent/'browser-negative-tests.json').write_text(json.dumps(result,indent=2)+'\n')
    print(str(len(cases))+' false browser/NAT claims rejected')


if __name__ == '__main__':
    main()
