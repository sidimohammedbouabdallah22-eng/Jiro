"""Verify deployed fault proofs against retained samples/outbox/receipt bytes."""
import argparse
import copy
import hashlib
import json
from pathlib import Path
import sqlite3
import tarfile

EXPECTED={
 'baseline':True,'certificate-reload-alert-receiver-offline':False,
 'wrong-alert-acknowledgement':False,'alert-retry-after-watchdog-restart':False,
 'certificate-recovery':True,'security-export-outage':False,
 'security-export-recovery':True,'audit-export-outage':False,
 'audit-export-recovery':True,'event-storage-enospc':False,
 'storage-recovery-and-replayed-attack':True,'missing-samples-real-time':False,
 'sampling-resumed':True,'evidence-read-recovery':True,
}


def sha(data):return hashlib.sha256(data).hexdigest()


def db(data):
    result=sqlite3.connect(':memory:');result.deserialize(data)
    assert result.execute('PRAGMA quick_check').fetchone()[0]=='ok'
    return result


def proof(report,package_sha,server_sha):
    assert report['passed'] and report['vm_powered_off']
    assert report['package_sha256']==package_sha and report['server_sha256']==server_sha
    drill=report['drill'];assert drill['passed']
    assert drill['server_sha256']==server_sha and drill['package_sha256']==package_sha
    assert not drill['business_pilot_started'] and not drill['real_operator_delivery_qualified']
    assert drill['wrong_ack_retried_same_identity'] and drill['receiver_deduplicated']
    assert drill['storage_fault_unacknowledged_attempts']==1
    cases={case['name']:case for case in drill['cases']}
    expected = dict(EXPECTED)
    if report.get('timers_required'):
        expected['timer-sampling-recovery'] = True
        timers = drill['timers']
        assert timers['sampler_stopped'] and timers['watchdog_independent']
        assert timers['samples_after'] > timers['samples_before']
        assert timers['last_sample'] >= timers['started']
        assert timers['firing_observed_at'] - timers['last_sample'] > 180
    assert len(cases)==len(drill['cases'])==len(expected) and set(cases)==set(expected)
    for name,healthy in expected.items():
        case=cases[name];assert case['healthy']==healthy
        if name=='missing-samples-real-time':
            assert case['waited_seconds']>180 and case['reason']=='samples_missing'
            continue
        assert case['health']['ready'] and case['health']['mode']=='enforcing'
        assert case['checks']['canary_application']['ok']
        assert case['checks']['monitoring_credential']['ok']
        assert case['checks']['gateway_health']['ok']==healthy
        if healthy:assert case['pending']==0 and case['watchdog_exit']==0
    assert not cases['certificate-reload-alert-receiver-offline']['health']['checks']['certificate_healthy']
    assert cases['certificate-reload-alert-receiver-offline']['pending']>0
    assert cases['wrong-alert-acknowledgement']['pending']>0
    assert cases['alert-retry-after-watchdog-restart']['pending']==0
    assert not cases['security-export-outage']['health']['checks']['event_delivery_healthy']
    assert not cases['audit-export-outage']['health']['checks']['administration_export_healthy']
    assert cases['event-storage-enospc']['persistence_errors']==1
    assert cases['event-storage-enospc']['isolated_filesystem_bytes']==16<<20
    assert not cases['event-storage-enospc']['health']['checks']['event_persistence_acknowledged']


def check(path,package):
    report=json.loads(path.read_text());out=path.parent
    package_sha=sha(package.read_bytes());assert package_sha==Path(str(package)+'.sha256').read_text().split()[0]
    with tarfile.open(package) as tar:server_sha=sha(tar.extractfile('usr/lib/openwaf/waf-server').read())
    proof(report,package_sha,server_sha)
    for relative,expected in report['sources'].items():assert sha((out/'source'/Path(relative).name).read_bytes())==expected
    archive=out/'fault-evidence.private.tar.gz';assert sha(archive.read_bytes())==report['drill']['capture_sha256']
    with tarfile.open(archive) as tar:
        members=tar.getmembers();assert len({m.name for m in members})==len(members)
        assert sum(m.size for m in members)<2<<30
        assert all((m.isfile() or m.isdir()) and not Path(m.name).is_absolute() and '..' not in Path(m.name).parts for m in members)
        data={m.name:tar.extractfile(m).read() for m in members if m.isfile()}
    for relative,expected in report['sources'].items():
        assert sha(data['scripts/'+Path(relative).name])==expected
    pilot=db(data['probes/evidence.db']);outbox=db(data['alerts/outbox.db']);receiver=db(data['alert-receiver/receipts.db'])
    rows=outbox.execute('SELECT id,payload,acked FROM outbox ORDER BY seq').fetchall()
    assert len(rows)>=10 and all(row[2]==1 for row in rows)
    received=dict(receiver.execute('SELECT id,payload FROM receipts'))
    assert len(received)==len(rows)
    for identity,payload,_ in rows:
        assert received[identity]==payload.encode()
        item=json.loads(payload)
        assert set(item)=={'schema','event_id','deployment','event','reason','checks','observed_at'}
        assert item['event_id']==identity and item['event'] in ['firing','resolved']
    events=[json.loads(row[1]) for row in rows]
    reasons={(e['event'],e['reason']) for e in events}
    for reason in ['sample_failed','samples_missing','evidence_unavailable']:
        assert ('firing',reason) in reasons and ('resolved',reason) in reasons
    active=outbox.execute('SELECT active FROM meta').fetchone()[0];assert json.loads(active) is None
    duplicates=receiver.execute("SELECT id FROM attempts GROUP BY id HAVING count(*)>1 AND sum(mode='wrong-ack')>0 AND sum(mode='normal')>0").fetchall()
    assert duplicates
    samples=pilot.execute('SELECT started,finished,healthy,detail FROM samples ORDER BY started').fetchall()
    assert sum(not row[2] for row in samples)>=6 and samples[-1][2]==1
    assert any(right[0]-left[1]>180 for left,right in zip(samples,samples[1:]))
    if report.get('timers_required'):
        timers = report['drill']['timers']
        firing = next(event for event in events if event['event_id'] == timers['firing_event_id'])
        assert firing['reason'] == 'samples_missing' and firing['event'] == 'firing'
        assert firing['observed_at'] == timers['firing_observed_at']
        automatic = [row for row in samples if timers['started'] <= row[0] < firing['observed_at']]
        assert automatic and all(row[2] for row in automatic)
        assert max(row[1] for row in automatic) == timers['last_sample']
        assert timers['samples_before'] == sum(row[0] < timers['started'] for row in samples)
        assert timers['samples_after'] == timers['samples_before'] + len(automatic)
        assert any(event['event'] == 'resolved' and event['reason'] == 'samples_missing'
                   and event['observed_at'] > firing['observed_at'] for event in events)
    secrets=[data[name].strip() for name in ['probes/monitor-token','probes/webhook-token','alert-receiver/token']]
    for name in ['probes/evidence.db','alerts/outbox.db','alert-receiver/receipts.db']:
        assert all(secret not in data[name] for secret in secrets)
    sender=db(data['state/events.db']);collected=db(data['collector/events.db'])
    source=sender.execute('SELECT source_id FROM export_settings').fetchone()[0]
    source_rows=dict(sender.execute('SELECT id,data FROM events'))
    remote=dict(collected.execute('SELECT id,data FROM collected_events WHERE source_id=?',(source,)))
    assert source_rows==remote and len(source_rows)==report['drill']['delivery_verification']['events']
    assert sender.execute('SELECT count(*) FROM export_outbox').fetchone()[0]==0
    audit=db(data['audit/events.db'])
    records=[json.loads(line) for line in data['state/policy.json.audit.jsonl'].splitlines()]
    for record in records:
        row=audit.execute('SELECT data FROM collected_events WHERE id=?',(record['id'],)).fetchone()
        assert row and json.loads(row[0])==record
    mutations=[lambda r:r.update(passed=False),lambda r:r.update(vm_powered_off=False),
               lambda r:r.update(server_sha256='0'*64),lambda r:r['drill'].update(real_operator_delivery_qualified=True),
               lambda r:r['drill'].update(storage_fault_unacknowledged_attempts=0),
               lambda r:r['drill'].update(receiver_deduplicated=False),lambda r:r['drill'].update(cases=[])]
    if report.get('timers_required'):
        mutations.extend([
            lambda r:r['drill']['timers'].update(watchdog_independent=False),
            lambda r:r['drill']['timers'].update(samples_after=r['drill']['timers']['samples_before']),
            lambda r:r['drill']['timers'].update(firing_observed_at=r['drill']['timers']['last_sample']),
        ])
    for mutate in mutations:
        changed=copy.deepcopy(report);mutate(changed)
        try:proof(changed,package_sha,server_sha)
        except AssertionError:continue
        raise AssertionError('invalid alert evidence accepted')
    for connection in [pilot,outbox,receiver,sender,collected,audit]:connection.close()
    result=dict(passed=True,report=str(path),checker_sha256=sha(Path(__file__).read_bytes()),
                deployed_cases=len(report['drill']['cases']),acknowledged_alert_transitions=len(rows),deduplicated_retry_ids=len(duplicates),
                security_records_delivered=len(source_rows),audit_records_delivered=len(records),
                intentional_unacknowledged_storage_fault_attempts=1,invalid_proofs_rejected=len(mutations),
                shipped_timers_qualified=bool(report.get('timers_required')),
                real_operator_delivery_qualified=False,business_pilot_started=False)
    (out/'verification.json').write_text(json.dumps(result,indent=2)+'\n')
    (out/'source/check-alert-evidence.py').write_bytes(Path(__file__).read_bytes())
    return result


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('report',type=Path);parser.add_argument('--package',type=Path,required=True)
    args=parser.parse_args();print(json.dumps(check(args.report,args.package),indent=2))
