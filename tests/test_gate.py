import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import vpngate as gate

class Reply:
    status_code = 200
    def __init__(self, data): self.data = data
    def json(self): return self.data

class Session:
    def __init__(self, data): self.data, self.headers = data, None
    def get(self, url, **kw):
        self.headers = kw['headers']
        return Reply(self.data)

class GateTests(unittest.TestCase):
    def setUp(self):
        self.node = dict(host='vpn123.opengw.net', port=443, ip='1.1.1.1', country='Japan', country_code='JP')
        self.ok = dict(success=True, type='sstp', hostname=self.node['host'], port=443,
                       exit=dict(ip='8.8.8.8', location=dict(country='Japan', country_code='JP', city='Tokyo'), asn=dict(org='NTT EAST')))
    def test_string_false_is_not_success(self):
        self.ok['success'] = 'false'
        self.assertFalse(gate.check_one(self.node, Session(self.ok))['success'])
    def test_missing_or_private_exit_is_not_success(self):
        for addr in ('', '127.0.0.1', '192.168.1.1', 'invalid'):
            self.ok['exit']['ip'] = addr
            self.assertFalse(gate.check_one(self.node, Session(self.ok))['success'])
    def test_success_must_match_protocol_and_target(self):
        for key, value in [('type', 'socks5'), ('hostname', 'other.opengw.net'), ('port', 1194)]:
            data = dict(self.ok); data[key] = value
            self.assertFalse(gate.check_one(self.node, Session(data))['success'])
    def test_location_auth_and_public_redaction(self):
        s = Session(self.ok)
        with patch.dict(os.environ, {'CHECK_TOKEN':'private-test-token'}), patch.object(gate, 'WORKER_CHECK_URL', 'https://mine.workers.dev/check?sstp=vpn:vpn@'):
            n = gate.check_one(self.node, s)
            self.assertTrue(n['success'])
            self.assertEqual(n['exit']['city'], 'Tokyo')
            self.assertEqual(s.headers['Authorization'], 'Bearer private-test-token')
            data = gate.build_outputs([n], 1, 1, 'fixture')
            self.assertEqual(data['worker'], 'https://mine.workers.dev/check')
            self.assertNotIn('private-test-token', str(data))
    def test_unknown_stays_unknown(self):
        self.assertEqual(gate.classify_network('vpn12345.opengw.net', '', False), 'unknown')
        n = dict(self.node, success=True, residential='unknown', latency_ms=30)
        d = gate.build_outputs([n], 1, 1, 'fixture')
        with patch.object(gate, 'EDGE_HOSTS', ['my-edge.workers.dev:443']):
            line = gate.build_nodes_text(d)
        self.assertIn('未知-01', line)
        self.assertNotIn('机房', line)
        self.assertEqual(d['stats']['unknown'], 1)
    def test_empty_publish_preserves_previous(self):
        with tempfile.TemporaryDirectory() as tmp, patch.object(gate, 'PUBLIC_DIR', tmp):
            p = Path(tmp) / 'nodes.txt'; p.write_text('previous', encoding='utf-8')
            with self.assertRaises(ValueError): gate.write_outputs({'available': []})
            self.assertEqual(p.read_text(), 'previous')
    def test_configuration_requires_owned_url_and_tls_entry(self):
        with patch.dict(os.environ, {'CHECK_TOKEN':'test'}), patch.object(gate, 'EDGE_HOSTS', ['mine.workers.dev:443']):
            for url in ('', 'https://mine.workers.dev', 'http://mine/check?sstp=vpn:vpn@'):
                with patch.object(gate, 'WORKER_CHECK_URL', url), self.assertRaises(ValueError): gate.validate_configuration()
            with patch.object(gate, 'WORKER_CHECK_URL', 'https://mine.workers.dev/check?sstp=vpn:vpn@'):
                gate.validate_configuration()
                with patch.object(gate, 'EDGE_HOSTS', ['mine:7890']), self.assertRaises(ValueError): gate.validate_configuration()
    def test_candidates_are_deduplicated(self):
        self.assertEqual(len(gate.dedupe([self.node, dict(self.node)])), 1)

if __name__ == '__main__': unittest.main()
