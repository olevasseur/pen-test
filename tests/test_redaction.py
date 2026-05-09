import unittest

from pentest_harness.core.redaction import redact, sanitize_for_security_map


class RedactionTests(unittest.TestCase):
    def test_redacts_sensitive_keys_and_tokens(self):
        value = redact({"Authorization": "Bearer abcdefghijklmnop", "nested": {"cookie": "session=secret"}, "ok": "hello"})
        self.assertEqual(value["Authorization"], "[REDACTED]")
        self.assertEqual(value["nested"]["cookie"], "[REDACTED]")
        self.assertEqual(value["ok"], "hello")

    def test_security_map_rejects_forbidden_content(self):
        with self.assertRaises(ValueError):
            sanitize_for_security_map("Authorization: Bearer abcdefghijklmnop")


if __name__ == "__main__":
    unittest.main()
