import unittest
import socket
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "src"))
from proxy import FilteringForwardProxy, is_host_allowed

class TestFilteringProxy(unittest.TestCase):
    def test_domain_whitelist_matcher(self):
        whitelist = ["pypi.org", "*.pythonhosted.org", "registry.npmjs.org", "*.npmjs.org"]

        # Allowed exact and wildcard
        self.assertTrue(is_host_allowed("pypi.org", whitelist))
        self.assertTrue(is_host_allowed("pypi.org:443", whitelist))
        self.assertTrue(is_host_allowed("files.pythonhosted.org", whitelist))
        self.assertTrue(is_host_allowed("files.pythonhosted.org:443", whitelist))
        self.assertTrue(is_host_allowed("registry.npmjs.org", whitelist))
        self.assertTrue(is_host_allowed("sub.registry.npmjs.org", whitelist))

        # Disallowed / Attacker domains
        self.assertFalse(is_host_allowed("evil.com", whitelist))
        self.assertFalse(is_host_allowed("malicious-telemetry.io", whitelist))
        self.assertFalse(is_host_allowed("notpypi.org", whitelist))
        self.assertFalse(is_host_allowed("pypi.org.attacker.com", whitelist))

    def test_proxy_blocks_unauthorized_connect(self):
        whitelist = ["pypi.org", "*.pythonhosted.org"]
        with FilteringForwardProxy(whitelist=whitelist, host="127.0.0.1", port=0) as proxy:
            # Connect to proxy
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.connect(("127.0.0.1", proxy.port))
            # Request tunnel to evil.com
            req = b"CONNECT evil.com:443 HTTP/1.1\r\nHost: evil.com:443\r\n\r\n"
            s.sendall(req)
            resp = s.recv(4096)
            s.close()

            self.assertIn(b"403 Forbidden", resp)
            self.assertIn(b"[AgentShield] Domain not whitelisted", resp)

    def test_proxy_blocks_unauthorized_http_get(self):
        whitelist = ["pypi.org", "*.pythonhosted.org"]
        with FilteringForwardProxy(whitelist=whitelist, host="127.0.0.1", port=0) as proxy:
            # Connect to proxy
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.connect(("127.0.0.1", proxy.port))
            # Request GET to evil.com
            req = b"GET http://evil.com/leak HTTP/1.1\r\nHost: evil.com\r\n\r\n"
            s.sendall(req)
            resp = s.recv(4096)
            s.close()

            self.assertIn(b"403 Forbidden", resp)

if __name__ == "__main__":
    unittest.main()
