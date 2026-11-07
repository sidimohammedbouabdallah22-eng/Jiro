"""Check five-minute windows within the independently verified joint endurance."""
import argparse
import importlib.util
import json
from pathlib import Path

from joint_business_lab import resources, sha


def main():
    if not __debug__:
        raise RuntimeError('evidence verification requires Python assertions; do not use -O')
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('report',type=Path);p.add_argument('--package',type=Path,required=True)
    args=p.parse_args();out=args.report.parent
    spec=importlib.util.spec_from_file_location('jointcheck',Path(__file__).with_name('check-joint-business-evidence.py'))
    checker=importlib.util.module_from_spec(spec);spec.loader.exec_module(checker)
    checker.check(args.report,args.package)
    report=json.loads(args.report.read_text());phase=report['phases'][-1]
    assert phase['name']=='large-joint-endurance' and phase['duration']==1800
    rows=[r for r in json.loads((out/'requests.json').read_text()) if r['label']==phase['name']]
    raw=(out/'resources.jsonl').read_text();begin=phase['guest_begin']['monotonic']
    windows=[]
    for offset in range(0,1800,300):
        selected=[]
        for row in rows:
            rate=phase['erp_rate'] if row['app']=='dolibarr' else phase['shop_rate']
            due=int(row['sequence'].rsplit('-',1)[1])/rate
            if offset<=due<offset+300:selected.append(row)
        assert len(selected)==375 and all(r['status']==200 for r in selected)
        sampled=resources(raw,dict(monotonic=begin+offset),dict(monotonic=begin+offset+300))
        p95={}
        for app in ['dolibarr','prestashop']:
            values=sorted(r['scheduled_latency_ms'] for r in selected if r['app']==app)
            p95[app]=round(values[int((len(values)-1)*.95)],3)
        late=sum(r['start_delay_ms']>100 for r in selected)
        accepted=p95['prestashop']<=2000 and p95['dolibarr']<=10000 and late<=len(selected)*.01 and sampled['observed_cpu_percent']<=85 and sampled['min_available_kib']>=512*1024
        windows.append(dict(begin_offset=offset,end_offset=offset+300,requests=len(selected),p95_ms=p95,
                            late_over_100ms=late,resources=sampled,operating_budget_passed=accepted))
    result=dict(passed=all(w['operating_budget_passed'] for w in windows),windows=windows,
                analyzer_sha256=sha(Path(__file__).read_bytes()),
                resource_helper_sha256=sha(Path(__file__).with_name('joint_business_lab.py').read_bytes()),
                scope='six five-minute lab windows; no production sizing or proof against long-term memory leaks')
    (out/'endurance-windows.json').write_text(json.dumps(result,indent=2)+'\n')
    print(json.dumps(dict(passed=result['passed'],windows=len(windows),requests=len(rows))))
    assert result['passed'],'one endurance window exceeded its operating budget'


if __name__=='__main__':main()
