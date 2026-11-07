"""Verify the retained idle-reuse failure from TCP metadata, without payload output."""
import argparse
import hashlib
import json
from pathlib import Path
import socket
import struct


def sha(data):
    return hashlib.sha256(data).hexdigest()


def check(report):
    root = report.parent
    r = json.loads(report.read_text())
    assert not r['passed'] and r['diagnostic_trace_only']
    assert r['cleanup']['restored'] and r['vm_powered_off'] and r['upstream_trace']['stopped']
    data = (root / 'upstream.private.pcap').read_bytes()
    assert sha(data) == r['upstream_trace']['sha256']
    assert data[:4] == bytes.fromhex('d4c3b2a1') and struct.unpack_from('<I', data, 20)[0] == 1
    rows = json.loads((root / 'requests.json').read_text())
    failed = [row for row in rows if not row['valid']]
    assert len(failed) == 1 and failed[0]['role'] == 'legit-upload' and failed[0]['status'] == 502
    begin = r['phases'][0]['guest_begin']['time']
    flows = {}
    offset = 24
    while offset < len(data):
        sec, usec, captured, wire = struct.unpack_from('<IIII', data, offset)
        offset += 16
        packet = data[offset:offset + captured]
        offset += captured
        assert len(packet) == captured <= wire
        ip = 14
        assert len(packet) >= ip + 20
        if packet[ip] >> 4 != 4 or packet[ip + 9] != 6:
            continue
        ihl = (packet[ip] & 15) * 4
        tcp = ip + ihl
        assert len(packet) >= tcp + 20
        src = socket.inet_ntoa(packet[ip + 12:ip + 16])
        dst = socket.inet_ntoa(packet[ip + 16:ip + 20])
        sp, dp, seq, ack, length, flags = struct.unpack_from('!HHIIBB', packet, tcp)
        size = struct.unpack_from('!H', packet, ip + 2)[0] - ihl - (length >> 4) * 4
        assert size >= 0
        key = tuple(sorted([(src, sp), (dst, dp)]))
        flows.setdefault(key, []).append(dict(time=sec + usec / 1e6, src=sp, dst=dp, bytes=size, flags=flags))
    assert offset == len(data)
    matches = []
    for key, packets in flows.items():
        # Only the ERP relay, whose exact port is recorded in the owned fixture.
        fixture = json.loads((root / 'fixture.private.json').read_text())
        port = fixture['dolibarr']['ports']['app']
        if not any(endpoint == ('127.0.0.1', port) for endpoint in key):
            continue
        before = [p for p in packets if p['time'] < begin]
        writes = [p for p in packets if p['time'] >= begin and p['dst'] == port and p['bytes']]
        if not before or not writes:
            continue
        first = writes[0]['time']
        replies = [p for p in before if p['src'] == port and p['bytes']]
        closes = [p for p in packets if p['src'] == port and p['flags'] & 5 and p['time'] >= first]
        responses = [p for p in packets if p['src'] == port and p['bytes'] and p['time'] >= first]
        assert replies and closes and not responses
        assert any(p['flags'] & 2 for p in before)
        written = sum(p['bytes'] for p in writes)
        assert 0 < written < failed[0]['request_bytes']
        gap = first - replies[-1]['time']
        assert 5 < gap < 6
        matches.append(dict(idle_gap_seconds=round(gap, 6), partial_request_tcp_bytes=written,
                            close_after_first_write_ms=round((closes[0]['time'] - first) * 1000, 6)))
    assert len(matches) == 1
    return dict(trace_evidence_verified=True, reused_connection_closed_after_partial_write=True,
                response_payload_received=False, automatic_mutation_replay_safe=False,
                backend_timeout_configuration_proven=False, matched_connection=matches[0],
                trace_sha256=sha(data), checker_sha256=sha(Path(__file__).read_bytes()))


if __name__ == '__main__':
    if not __debug__:
        raise RuntimeError('verification requires assertions')
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('report', type=Path)
    args = parser.parse_args()
    result = check(args.report)
    (args.report.parent / 'upstream-trace-verification.json').write_text(json.dumps(result, indent=2) + '\n')
    print(json.dumps(result))
