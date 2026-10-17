import json
import tempfile
import unittest
from pathlib import Path

from uu_vps_proxy.profiles import Error, atomic_json, proxy_from_url, validate


class ProfilesTests(unittest.TestCase):
    def test_authenticated_ipv6_url_and_percent_encoded_password(self):
        outbound = proxy_from_url('socks5h://sample:p%40ss@[::1]:1080')
        self.assertEqual(outbound['server'], '::1')
        self.assertEqual(outbound['password'], 'p@ss')
        self.assertEqual(outbound['version'], '5')

    def test_https_proxy_preserves_verified_server_name(self):
        outbound = proxy_from_url('https://proxy.example:443')
        self.assertEqual(outbound['tls'], {'enabled': True, 'server_name': 'proxy.example'})

    def test_rejects_bad_urls_without_echoing_credentials(self):
        for url in ('file:///secret', 'http://sample:secret@host', 'http://host:80/path', 'socks://host:1080'):
            with self.subTest(url=url), self.assertRaises(Error) as raised:
                proxy_from_url(url)
            self.assertNotIn('secret', str(raised.exception))

    def test_rejects_direct_fallback_and_insecure_tls(self):
        variants = [dict(type='direct', server='example', server_port=80),
                    dict(type='http', server='example', server_port=80, detour='direct'),
                    dict(type='http', server='example', server_port=443, tls={'insecure': True})]
        for outbound in variants:
            with self.subTest(outbound=outbound), self.assertRaises(Error):
                validate({'outbound': outbound})

    def test_atomic_credentials_file_is_private(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'config/proxy.json'
            data = {'outbound': proxy_from_url('http://sample:p%40ss@127.0.0.1:1080')}
            atomic_json(path, data)
            self.assertEqual(path.stat().st_mode & 0o777, 0o600)
            self.assertEqual(path.parent.stat().st_mode & 0o777, 0o700)
            self.assertEqual(json.loads(path.read_text()), data)
