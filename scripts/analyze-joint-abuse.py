"""Separate admitted-probe latency from fast refusals in verified abuse evidence."""
import argparse
from collections import defaultdict
import hashlib
import json
from pathlib import Path


def main():
    if not __debug__:raise RuntimeError('verification requires Python assertions')
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('report',type=Path);a=p.parse_args()
    out=a.report.parent;report=json.loads(a.report.read_text())
    proof=json.loads((out/('verification.json' if report['passed'] else 'failure-verification.json')).read_text())
    assert proof.get('passed') or proof.get('evidence_verified')
    raw=(out/'requests.json').read_bytes();rows=json.loads(raw)
    groups=defaultdict(list)
    for row in rows:groups[(row['label'],row['app'],row['status'])].append(row)
    result=[]
    for (label,app,status),selected in sorted(groups.items()):
        metrics={}
        for field in ['scheduled_ms','service_ms']:
            values=sorted(r[field] for r in selected)
            metrics[field]={key:round(values[int((len(values)-1)*fraction)],3) for key,fraction in [('p50',.5),('p95',.95),('p99',.99)]}
        result.append(dict(label=label,app=app,status=status,count=len(selected),latency=metrics))
    artifact=dict(qualification_passed=report['passed'],groups=result,
                  requests_sha256=hashlib.sha256(raw).hexdigest(),
                  analyzer_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
                  note='400 ERP probes reached mandatory-field validation; 413/429/503 are refused work; 0 denotes no HTTP response')
    (out/'response-latencies.json').write_text(json.dumps(artifact,indent=2)+'\n')
    print(json.dumps(dict(groups=len(result),requests=len(rows),qualification_passed=report['passed'])))


if __name__=='__main__':main()
