import unittest

from scripts.safe_fetch import validate_url


class SafeFetchTests(unittest.TestCase):
    def test_accepts_exact_allowlisted_https_host(self):
        parsed = validate_url("https://challenge.example:8443/api", {"challenge.example"})
        self.assertEqual(parsed.hostname, "challenge.example")

    def test_rejects_unlisted_host(self):
        with self.assertRaisesRegex(ValueError, "allowlist"):
            validate_url("https://other.example/path", {"challenge.example"})

    def test_rejects_credentials_in_url(self):
        with self.assertRaisesRegex(ValueError, "credentials"):
            validate_url("https://user:pass@challenge.example/path", {"challenge.example"})

    def test_rejects_non_http_scheme(self):
        with self.assertRaisesRegex(ValueError, "scheme"):
            validate_url("file:///etc/passwd", {"challenge.example"})

    def test_rejects_metadata_ip_when_not_explicitly_authorized(self):
        with self.assertRaisesRegex(ValueError, "allowlist"):
            validate_url("http://169.254.169.254/latest/meta-data/", {"challenge.example"})


if __name__ == "__main__":
    unittest.main()
