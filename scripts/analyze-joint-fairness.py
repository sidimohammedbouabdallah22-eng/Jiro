"""Check five-minute windows and admitted/refused latencies in sustained fairness."""
import argparse
from collections import defaultdict
import importlib.util
import json
from pathlib import Path

from joint_business_lab import resources,sha


def p95(values):
    values=sorted(values);return round(values[int((len(values)-1)*.95)],3) if values else None


def main():
    if not __debug__:raise RuntimeError('verification requires assertions')
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('report',type=Path);p.add_argument('--package',type=Path,required=True);a=p.parse_args()
    spec=importlib.util.spec_from_file_location('faircheck',Path(__file__).with_name('check-joint-fairness-evidence.py'))
    checker=importlib.util.module_from_spec(spec);spec.loader.exec_module(checker)
    verified=checker.check(a.report,a.package);assert verified['sustained_profile_qualified']
    out=a.report.parent;r=json.loads(a.report.read_text());rows=json.loads((out/'requests.json').read_text());raw=(out/'resources.jsonl').read_text()
    windows=[]
    for phase in r['phases'][1:]:
        assert phase['seconds']==600
        for offset in [0,300]:
            shop=[row for row in rows if row['label']==phase['name'] and row['role']=='legit-shop' and offset<=int(row['sequence'].rsplit('-',1)[1])<offset+300]
            flows=[f for f in r['uploads'] if f['phase']==phase['name'] and offset<=f['sequence']*20<offset+300]
            uploads=[row for row in rows if row['label']==phase['name'] and row['role']=='legit-upload' and offset<=int(row['sequence'].rsplit('-',1)[1])*20<offset+300]
            assert len(shop)==300 and len(flows)==15
            facts=resources(raw,dict(monotonic=phase['guest_begin']['monotonic']+offset),dict(monotonic=phase['guest_begin']['monotonic']+offset+300),r.get('vcpus',1))
            shop_p95=p95([row['scheduled_ms'] for row in shop]);flow_p95=p95([f['scheduled_ms'] for f in flows])
            late=sum(row['start_delay_ms']>100 for row in shop+uploads)
            passed=all(row['status']==200 for row in shop) and all(f['passed'] for f in flows) and shop_p95<=2000 and flow_p95<=10000 and late<=315*.01 and facts['min_available_kib']>=512*1024
            windows.append(dict(phase=phase['name'],offset=offset,storefront_requests=300,uploads=15,
                                storefront_p95_ms=shop_p95,upload_workflow_p95_ms=flow_p95,late_over_100ms=late,resources=facts,passed=passed))
    groups=defaultdict(list)
    for row in rows:groups[(row['label'],row['role'],row['app'],row['status'])].append(row)
    latencies=[dict(phase=k[0],role=k[1],app=k[2],status=k[3],count=len(v),scheduled_p95_ms=p95([row['scheduled_ms'] for row in v])) for k,v in sorted(groups.items())]
    result=dict(passed=all(w['passed'] for w in windows),windows=windows,latencies=latencies,
                analyzer_sha256=sha(Path(__file__).read_bytes()),helper_sha256=sha(Path(__file__).with_name('joint_business_lab.py').read_bytes()),
                scope='response budgets under measured abuse; saturated CPU is reported, not called headroom or isolation')
    (out/'fairness-windows.json').write_text(json.dumps(result,indent=2)+'\n')
    print(json.dumps(dict(passed=result['passed'],five_minute_windows=len(windows))))
    assert result['passed'],'sustained window exceeded the declared response budget'


if __name__=='__main__':main()
