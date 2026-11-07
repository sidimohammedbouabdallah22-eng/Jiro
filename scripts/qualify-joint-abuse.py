"""CPU-abuse screens and a bounded policy on the owned real-business M4 lab."""
import argparse
from collections import Counter
from concurrent.futures import ThreadPoolExecutor
import json
from pathlib import Path
import shlex
import threading
import time
import urllib.parse

from joint_business_lab import Lab, resources, sha


def body_bytes(size, kind):
    """Same-sized valid JSON; Unicode defeats the ASCII-only fast rejection."""
    suffix = {'ascii': '', 'unicode': 'é', 'escaped': 'é', 'attack': '<script>alert(1)</script>'}[kind]
    ensure_ascii = kind == 'escaped'
    overhead = len(json.dumps(dict(payload=suffix), ensure_ascii=ensure_ascii, separators=(',', ':')).encode())
    assert size >= overhead
    body = json.dumps(dict(payload='a'*(size-overhead)+suffix), ensure_ascii=ensure_ascii,
                      separators=(',', ':')).encode()
    assert len(body) == size
    return body


def percentile(rows, field, fraction):
    values = sorted(row[field] for row in rows)
    return round(values[int((len(values)-1)*fraction)], 3) if values else None


def missing_name(code, data):
    if code != 400:
        return False
    try:
        value = json.loads(data)
        return value['error']['code'] == 400 and 'name field missing' in value['error']['message']
    except (ValueError, KeyError, TypeError):
        return False


def policy(lab, slots=8, limit=1 << 20, rate=0):
    config = lab.admin('config')
    erp = next(app for app in config['applications'] if app['application_id'] == 'dolibarr')
    erp['policy']['request_limit'] = limit
    erp['traffic_controls'] = dict(max_concurrent=slots, requests_per_second=rate, burst=rate)
    lab.admin('config/apply', dict(config=config, reason='Owned M4 CPU-abuse profile: explicit admission/body/rate limits'))
    actual = lab.admin('config')
    erp = next(app for app in actual['applications'] if app['application_id'] == 'dolibarr')
    assert erp['policy']['request_limit'] == limit and erp['traffic_controls']['max_concurrent'] == slots
    assert erp['traffic_controls']['requests_per_second'] == rate
    return actual


def customer_state(lab):
    container = lab.fixture['dolibarr']['containers']['app']
    path = '/tmp/openwaf-abuse-state.php'
    lab.run([*lab.ssh, shlex.join(['sudo', 'docker', 'cp', lab.remote+'/m4_joint_abuse_state.php', container+':'+path])])
    output = lab.run([*lab.ssh, shlex.join(['sudo', 'docker', 'exec', '-u', 'www-data', container, 'php', path])]).stdout
    return json.loads(output.split('OPENWAF_ABUSE_STATE:')[1])


def phase(lab, name, seconds, body=None, workers=0, expected=(400,), require=False):
    """Open-loop storefront schedule; four independently paced abuse workers."""
    config = lab.admin('config')
    before = lab.drain()
    begin = lab.guest('mark')
    lab.report['active_phase'] = dict(name=name, policy=config, guest_begin=begin,
                                     seconds=seconds, body_bytes=len(body or b''), workers=workers)
    lab.save()
    first = len(lab.records)
    start = time.perf_counter()
    stop, errors, mutex = threading.Event(), [], threading.Lock()
    product = urllib.parse.urlsplit(lab.fixture['prestashop']['routes']['product'])
    path = product.path + ('?' + product.query if product.query else '')
    key = {'DOLAPIKEY': lab.fixture['dolibarr']['api_key']}

    def shop(index, due):
        lab.timing.due, lab.timing.sequence = due, 'shop-'+str(index)
        try:
            lab.send('prestashop', name, 'GET', path,
                     validate=lambda code, data: (code == 200 and b'OpenWAF Qualification Product' in data)
                     or (code == 503 and b'Application admission share exhausted' in data))
        except Exception as error:
            with mutex:
                errors.append(type(error).__name__)

    def burn(worker):
        index = 0
        stop.wait(worker/max(1, workers))
        while not stop.is_set() and time.perf_counter() < start+seconds:
            due = time.perf_counter()
            lab.timing.due, lab.timing.sequence = due, f'erp-{worker}-{index}'
            def valid(code, data):
                if code == 400:
                    return missing_name(code, data)
                if code == 413:
                    return b'Request body exceeds configured limit' in data
                if code == 429:
                    return b'Application or client request rate exceeded' in data
                if code == 503:
                    return b'Application admission share exhausted' in data
                return False
            try:
                code, _ = lab.send('dolibarr', name, 'POST', '/api/index.php/thirdparties', body, key,
                                   validate=lambda code, data: code in expected and valid(code, data))
            except Exception as error:
                with mutex:
                    errors.append(type(error).__name__)
            index += 1
            # A refused request does not turn this CPU screen into an unbounded flood.
            stop.wait(max(0, 1-(time.perf_counter()-due)))

    burners = [threading.Thread(target=burn, args=(i,), daemon=True) for i in range(workers)]
    for thread in burners:
        thread.start()
    with ThreadPoolExecutor(max_workers=8) as pool:
        jobs = []
        for index in range(seconds):
            due = start+index
            time.sleep(max(0, due-time.perf_counter()))
            jobs.append(pool.submit(shop, index, due))
            if index and index % 30 == 0:
                lab.save()
                print(name+': storefront scheduled '+str(index)+'/'+str(seconds), flush=True)
        time.sleep(max(0, start+seconds-time.perf_counter()))
        workload_end = lab.guest('mark')
        stop.set()
        for thread in burners:
            thread.join(timeout=90)
            assert not thread.is_alive(), 'CPU work did not return; reservations must not be abandoned'
        for job in jobs:
            job.result()
    after = lab.drain()
    end = lab.guest('mark')
    rows = lab.records[first:]
    shop_rows = [row for row in rows if row['app'] == 'prestashop']
    heavy_rows = [row for row in rows if row['app'] == 'dolibarr']
    assert len(shop_rows) == seconds and len({r['sequence'] for r in rows}) == len(rows)
    raw = lab.run([*lab.ssh, 'sudo cat '+lab.root+'/resources.jsonl']).stdout
    sampled = resources(raw, begin, workload_end)
    # This is an abuse-resilience budget, not acceptance of the abusive traffic.
    storefront_ok = all(r['status'] == 200 and r['valid'] for r in shop_rows)
    p95 = percentile(shop_rows, 'scheduled_ms', .95)
    late = sum(row['start_delay_ms'] > 100 for row in shop_rows)
    integrity = not errors and all(r['valid'] for r in rows)
    accepted = integrity and storefront_ok and p95 <= 2000 and late <= len(shop_rows)*.01
    facts = dict(name=name, requested_seconds=seconds, storefront_rate=1,
                 workers=workers, worker_max_attempts_per_second=1,
                 body_bytes=len(body or b''), body_sha256=sha(body or b''),
                 expected_heavy_statuses=list(expected), policy=config,
                 requests=len(rows), storefront_requests=len(shop_rows), heavy_requests=len(heavy_rows),
                 storefront_statuses=dict(Counter(str(r['status']) for r in shop_rows)),
                 heavy_statuses=dict(Counter(str(r['status']) for r in heavy_rows)), errors=errors,
                 invalid_responses=sum(not r['valid'] for r in rows),
                 storefront_p95_ms=p95, storefront_p99_ms=percentile(shop_rows, 'scheduled_ms', .99),
                 heavy_p95_ms=percentile(heavy_rows, 'scheduled_ms', .95),
                 storefront_late_over_100ms=late, integrity_passed=integrity,
                 storefront_budget_passed=accepted, required=require,
                 before=before, after=after, guest_begin=begin, guest_workload_end=workload_end,
                 guest_end=end, resources=sampled)
    lab.report['phases'].append(facts)
    lab.report.pop('active_phase', None)
    lab.save()
    print(name+': integrity='+str(integrity)+', storefront budget='+str(accepted)+', p95='+str(p95)+'ms', flush=True)
    assert integrity, 'unexpected CPU-abuse transport or response failure'
    assert not require or accepted, 'required bounded storefront profile failed'
    return facts


def main():
    if not __debug__:
        raise RuntimeError('qualification requires Python assertions; do not use -O')
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--package', type=Path, required=True)
    p.add_argument('--disposable-vm', action='store_true', required=True)
    p.add_argument('--seconds', type=int, default=90)
    p.add_argument('--bounded-only', action='store_true', help='Skip retained failed wide-admission screens')
    p.add_argument('--failed-screen', type=Path, help='Owned failed Unicode screen required by --bounded-only')
    args = p.parse_args()
    assert __debug__ and 60 <= args.seconds <= 300
    sources = ['qualify-joint-abuse.py', 'joint_business_lab.py', 'm4_joint_abuse_state.php',
               'm4_joint_business_guest.py', 'm4_joint_domains.php', 'm4_joint_files.php', 'm4_business_guest.py',
               'check-joint-abuse-evidence.py', 'reject-abuse-evidence-mutations.py', 'test_joint_abuse.py']
    lab = Lab(args.package, sources)
    lab.report.update(budgets=dict(storefront_rate=1, storefront_p95_ms=2000, late_fraction=.01),
                      profile='bounded-after-failure' if args.bounded_only else 'full',
                      experiment='CPU-abuse screens; bounded policy trades large uploads for storefront responsiveness')
    previous = None
    if args.bounded_only:
        assert args.failed_screen is not None
        failure = args.failed_screen.resolve(strict=True)
        assert failure.parent.parent == lab.repo/'artifacts' and failure.name == 'result.json'
        previous = json.loads(failure.read_text())
        assert not previous['passed'] and previous['server_sha256'] == lab.report['server_sha256']
        assert previous['package_sha256'] == lab.package_sha
        assert previous['phases'][-1]['name'] == 'unicode-eight-slots' and not previous['phases'][-1]['integrity_passed']
        lab.report['prior_failure'] = dict(artifact=failure.parent.name, result_sha256=sha(failure.read_bytes()))
    try:
        lab.start()
        original = lab.admin('config')
        lab.report['original_policy'] = original
        lab.report['customers_before'] = customer_state(lab)
        if previous is not None:
            assert previous['customers_before'] == lab.report['customers_before'], 'failed screen changed customer state'
        # Missing mandatory name rejects before create(), even when inspection accepts the probe.
        lab.send('dolibarr', 'probe-preflight', 'POST', '/api/index.php/thirdparties', body_bytes(1024, 'ascii'),
                 {'DOLAPIKEY': lab.fixture['dolibarr']['api_key']},
                 validate=missing_name)
        assert lab.records[-1]['valid'], 'unexpected application prevalidation response'
        phase(lab, 'storefront-baseline', args.seconds, require=True)
        if not args.bounded_only:
            phase(lab, 'ascii-eight-slots', args.seconds, body_bytes(900 << 10, 'ascii'), 4, (400, 503))
            phase(lab, 'unicode-eight-slots', args.seconds, body_bytes(900 << 10, 'unicode'), 4, (400, 503))
        policy(lab, slots=1)
        phase(lab, 'unicode-one-slot', args.seconds, body_bytes(900 << 10, 'unicode'), 4, (400, 503))
        policy(lab, slots=1, limit=64 << 10, rate=1)
        phase(lab, 'bounded-oversize-unicode', args.seconds, body_bytes(900 << 10, 'unicode'), 4, (413, 429, 503), True)
        phase(lab, 'bounded-small-escaped-unicode', args.seconds, body_bytes(32 << 10, 'escaped'), 4, (400, 429, 503), True)
        time.sleep(1.1)
        for expected in [400, 429]:
            code, _ = lab.send('dolibarr', 'bounded-rate-control', 'POST', '/api/index.php/thirdparties',
                               body_bytes(1024, 'ascii'), {'DOLAPIKEY': lab.fixture['dolibarr']['api_key']},
                               validate=lambda code, data: code == expected)
            assert code == expected
            if expected == 400:
                lab.drain()
        # Temporarily remove the rate for deterministic inspection controls; retain the body/admission cap.
        policy(lab, slots=1, limit=64 << 10)
        time.sleep(1)
        for size, kind, expected in [(32 << 10, 'attack', 403), ((64 << 10)+1, 'unicode', 413)]:
            code, _ = lab.send('dolibarr', 'bounded-controls', 'POST', '/api/index.php/thirdparties',
                               body_bytes(size, kind), {'DOLAPIKEY': lab.fixture['dolibarr']['api_key']},
                               validate=lambda code, data: code == expected)
            assert code == expected
        lab.report['customers_after'] = customer_state(lab)
        assert lab.report['customers_before'] == lab.report['customers_after'], 'probe mutated customer state'
        restore = dict(original, revision=lab.admin('config')['revision'])
        lab.admin('config/apply', dict(config=restore, reason='Restore owned M4 joint policy after CPU-abuse qualification'))
        restored = lab.admin('config')
        assert restored['applications'] == original['applications']
        lab.report['policy_restored'] = True
        lab.report['restored_policy'] = restored
        lab.report['final_status'] = lab.drain()
        assert lab.report['final_status']['summary']['requests'] == len(lab.records)
        assert all(r['valid'] for r in lab.records)
        lab.report['spool_after'] = lab.guest('spool')
        assert lab.report['spool_after']['files'] == lab.report['spool_after']['bytes'] == 0
        lab.capture()
        for name, digest in lab.report['sources'].items():
            assert sha((lab.repo/'scripts'/name).read_bytes()) == digest
        lab.report['passed'] = True
    finally:
        lab.close()
    assert lab.report['passed'] and lab.report['cleanup']['restored'] and lab.report['vm_powered_off']


if __name__ == '__main__':
    main()
