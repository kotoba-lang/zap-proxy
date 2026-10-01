import json
import os
import unittest
from unittest.mock import patch

from plugin import tools


class OriginTest(unittest.TestCase):
    def test_canonicalizes_default_ports_and_ipv6(self):
        self.assertEqual(tools._origin("HTTPS://Example.COM/path"), "https://example.com:443")
        self.assertEqual(tools._origin("http://[::1]/"), "http://[::1]:80")

    def test_rejects_credentials_and_non_http_schemes(self):
        for value in ("https://user@example.com", "file:///tmp/x", "", "https://host:bad"):
            with self.subTest(value=value), self.assertRaises(ValueError):
                tools._origin(value)


class GateTest(unittest.TestCase):
    def test_passive_allows_registered_origin_but_active_needs_second_gate(self):
        with patch.dict(os.environ, {"ZAP_PROXY_TARGETS": "http://localhost:8765"}, clear=True):
            self.assertIsNone(tools._gate(None, "http://localhost:8765/path", active=False))
            self.assertIn("without allow_active", tools._gate(None, "http://localhost:8765", active=True))

    def test_active_and_third_party_gate(self):
        with patch.dict(
            os.environ,
            {"ZAP_PROXY_TARGETS": "http://localhost:8765:active"},
            clear=True,
        ):
            self.assertIsNone(tools._gate(None, "http://localhost:8765", active=True))
            self.assertIn("not in zap_proxy_targets", tools._gate(None, "https://example.com", active=False))

    def test_invalid_target_is_refused(self):
        with patch.dict(os.environ, {"ZAP_PROXY_TARGETS": "http://localhost"}, clear=True):
            self.assertIn("Invalid target URL", tools._gate(None, "file:///etc/passwd", active=False))


class RequestTest(unittest.TestCase):
    def test_edn_request_escapes_untrusted_target(self):
        request = tools._edn_request('http://localhost/a" :active? true ;', False, 10)
        self.assertIn('\\"', request)
        self.assertEqual(request.count(":active?"), 2)
        self.assertIn(":active? false", request)

    def test_rules_use_checkout_relative_repo(self):
        result = json.loads(tools.zap_scan_rules())
        self.assertIn(":zap-proxy.rule/id", result["registry_edn"])


if __name__ == "__main__":
    unittest.main()
