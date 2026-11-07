"""Verify business workflow results against captured SQLite delivery evidence."""
import argparse
from collections import Counter
import hashlib
import json
import re
from pathlib import Path
import sqlite3
import tarfile


def check(path):
    report=json.loads(path.read_text())
    assert report['passed'] and report['functional_passed'] and report['cleanup']['stopped']
    assert report['browser_refusals']==[]
    if 'before_event_pages' in report:
        assert report['before_event_pages']>=max(1,(len(report['before_event_ids'])+498)//499)
        assert report['final_event_pages']>=max(1,(report['final_status']['storage']['stored']+498)//499)
    expected_cases={'dolibarr':11,'prestashop':6}[report['app']]
    if report.get('coverage') in ['business-v2-access','business-v3-native']:
        assert report['app']=='dolibarr'; expected_cases=19 if report['coverage']=='business-v3-native' else 14
        csrf=next(x for x in report['cases'] if x['name']=='application CSRF rejects missing and invalid tokens; valid form commits')
        assert csrf['missing_token_status']==403 and csrf['invalid_token_unchanged'] and csrf['valid_token_committed']
        reader=next(x for x in report['cases'] if x['name']=='reader can read customer but cannot edit or create customers')
        assert all(reader[k] for k in ['read_allowed','unassigned_customer_denied','update_denied_by_application','creation_denied_by_application','unchanged'])
        document=next(x for x in report['cases'] if x['name']=='reader cannot access invoice or its document')
        assert all(document[k] for k in ['invoice_denied_by_application','document_denied_by_application','administrator_access_retained'])
    if report.get('coverage')=='business-v3-native':
        contact=next(x for x in report['cases'] if x['name'].startswith('contact creation persists'))
        assert contact['contact_id']>0 and contact['persisted'] and contact['reader_denied_by_application']
        order=next(x for x in report['cases'] if x['name']=='sales order lines and validation persist correct totals')
        assert order['order_id']>0 and order['total_ht']==250 and order['validated'] and order['reader_denied_by_application']
        native=next(x for x in report['cases'] if x['name'].startswith('native CSV multipart'))
        assert native['simulation_did_not_commit'] and native['committed_once'] and native['unicode_preserved']
        attachment=next(x for x in report['cases'] if x['name']=='native customer multipart attachment round trips exact bytes')
        assert attachment['native_multipart'] and attachment['exact_download'] and attachment['bytes']>65536
        controls=next(x for x in report['cases'] if x['name']=='native multipart controls retain XSS and body size refusal')
        assert controls['paired_xss_status']==403 and controls['oversized_multipart_status']==413
    if report.get('coverage')=='business-v2-cart':
        expected_cases=8
        password=next(x for x in report['cases'] if x['name']=='storefront rejects wrong customer password without authenticating')
        assert password['application_rejected'] and not password['authenticated']
        cart=next(x for x in report['cases'] if x['name']=='cart removal persists and product can be readded before checkout')
        assert cart['removed_persistently'] and cart['readded_quantity']==2
    assert len(report['cases'])==expected_cases and all(x['passed'] for x in report['cases'])
    assert report['installed_version']==report['image']['version']
    assert report['image_metadata']['app']['architecture']=='amd64'
    assert report['environment']['disk_free_before_bytes']>=report['environment']['minimum_disk_free_bytes']
    attempt=report.get('attempt') or int(re.fullmatch(r'results-(\d+)\.json',path.name)[1])
    for name,digest in report['source_sha256'].items():
        source=path.parent/('source-'+str(attempt))/name
        assert hashlib.sha256(source.read_bytes()).hexdigest()==digest
    capture=report['database_archive']; archive=path.parent/capture['file']
    assert archive.parent==path.parent and hashlib.sha256(archive.read_bytes()).hexdigest()==capture['sha256']
    with tarfile.open(archive) as tar:
        assert {m.name for m in tar.getmembers()}=={'events.db','collector.db'} and len(tar.getmembers())==2
        databases={}
        for member in tar.getmembers():
            assert member.isfile() and 0<member.size<=128<<20
            db=sqlite3.connect(':memory:'); db.deserialize(tar.extractfile(member).read())
            assert db.execute('PRAGMA integrity_check').fetchone()[0]=='ok'
            databases[member.name]=db
    try:
        local=dict(databases['events.db'].execute('SELECT id,data FROM events'))
        remote=dict(databases['collector.db'].execute('SELECT id,data FROM collected_events'))
        assert local==remote and local
        events=[json.loads(x) for x in local.values()]
        occurrences=sum(max(1,x.get('occurrences',1)) for x in events)
        assert databases['collector.db'].execute('SELECT records,occurrences FROM collector_totals').fetchone()==(len(local),occurrences)
        assert (len(local),occurrences)==(report['delivery']['records'],report['delivery']['occurrences'])
        before=set(report['before_event_ids']); observed=set(report['attempt_event_ids'])
        assert before.issubset(local) and set(local)-before==observed and not before.intersection(observed)
        current=[x for x in events if x['id'] in observed]
        statuses=Counter()
        cancelled=0
        for x in current:
            n=max(1,x.get('occurrences',1))
            if x['status'] in (403,413,421): statuses[x['status']]+=n
            else:
                assert x['status'] in (200,499) and not x.get('matches')
                assert x['reason'] in ['Client or gateway cancelled response delivery','Client cancelled request']
                cancelled+=n
        expected=({403:9,413:2,421:1} if report.get('coverage')=='business-v3-native' else {403:8,413:1,421:1}) if report['app']=='dolibarr' else {403:2,413:1,421:1}
        assert dict(statuses)==expected, f'known attempt verdict occurrences differ: {dict(statuses)}'
        storage=report['final_status']['storage']; delivery=storage['export']
        assert storage['healthy'] and delivery['healthy'] and not delivery['paused']
        assert storage['stored']==len(local)
        assert storage['committed_occurrences']==delivery['enqueued_occurrences']==delivery['acked_occurrences']==occurrences
        assert storage['committed_records']==delivery['enqueued_records']==delivery['acked_records']==len(local)
        assert all(storage[key]==0 for key in ['pending_writes','queued','queue_dropped','write_failed','ingest_timeouts'])
        assert delivery['pending_records']==0
        assert report['final_status']['summary']['security_occurrences']==sum(expected.values())+cancelled
        assert storage['committed_occurrences']-report['before_status']['storage']['committed_occurrences']==sum(expected.values())+cancelled
        assert cancelled==report['browser_cancellation_occurrences']
        assert report['final_status']['summary']['event_persistence_errors']==0
        if report['app']=='dolibarr':
            tuning=next(x for x in report['cases'] if 'route and method tuning' in x['name'])
            assert tuning['negative_checks']==5 and tuning['exception_routes']==2
            assert any(any(m['id']==911100 for m in x.get('matches',[])) for x in current)
            assert report['policy']['applications'][0]['policy']['exclusions']==[]
        else:
            order=report['delivery']['committed_order']
            assert order['quantity']==2 and order['products_total']==50 and order['unpaid'] and order['bank_wire_state']
    finally:
        for db in databases.values(): db.close()
    return dict(passed=True,report=str(path),records=len(local),occurrences=occurrences,
        attempt_status_occurrences=dict(statuses),browser_cancellation_occurrences=cancelled,capacity_qualified=False)


if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__); p.add_argument('report',type=Path)
    print(json.dumps(check(p.parse_args().report),indent=2))
