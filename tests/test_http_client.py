"""URL scheme checks apply before network I/O and to every redirect."""
from pathlib import Path
import runpy
import unittest
from unittest.mock import patch
from urllib.request import Request

helpers = runpy.run_path(str(Path(__file__).resolve().parents[1] /
                            "api-mock/scripts/http_client.py"))
open_http = helpers["open_http"]
RestrictedRedirect = helpers["RestrictedRedirect"]


class HttpClientTests(unittest.TestCase):
    def test_rejects_non_https_downloads_before_opening(self):
        for url in ('file:///etc/passwd', 'data:text/plain,test',
                    'ftp://example.com/file', 'http://example.com/file',
                    'https://user:password@example.com/file'):
            with self.subTest(url=url), self.assertRaises(ValueError):
                open_http(url, timeout=1)

    def test_https_redirect_cannot_downgrade_or_read_local_files(self):
        handler = RestrictedRedirect(("https",))
        request = Request('https://example.com/file')
        for url in ('http://example.com/file', 'file:///etc/passwd',
                    'https://user:password@example.com/file'):
            with self.subTest(url=url), self.assertRaises(ValueError):
                handler.redirect_request(request,
                                         None, 302, 'Found', {}, url)
        redirected = handler.redirect_request(Request('https://example.com/file'),
            None, 302, 'Found', {}, 'https://cdn.example.com/file')
        self.assertEqual(redirected.full_url, 'https://cdn.example.com/file')

    def test_mock_can_explicitly_use_http(self):
        with patch.dict(open_http.__globals__, build_opener=lambda *_: self):
            result = open_http(Request('http://127.0.0.1:18080/api/healthcheck'),
                               timeout=10, schemes=('http', 'https'))
        self.assertEqual(result, 'mock response')

    def open(self, request, timeout):
        self.assertEqual(timeout, 10)
        return 'mock response'
