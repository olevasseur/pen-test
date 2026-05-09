import tempfile
import unittest
from pathlib import Path

from pentest_harness.core.roe import parse_rules_of_engagement
from pentest_harness.core.security_map import SecurityMapUpdate, documented_routes, load_security_map, propose_security_map_update, write_security_map_update


class RoeSecurityMapTests(unittest.TestCase):
    def test_parses_cheddar_urls_and_forbidden_legacy(self):
        markdown = """
| Staging | `https://staging-api-aws.cheddar.biz` |
| Production | `https://api.cheddar.biz` |
- Do not use `https://staging-api.cheddar.biz` for AWS staging tests.
"""
        roe = parse_rules_of_engagement(markdown)
        self.assertIn("https://staging-api-aws.cheddar.biz", roe.allowed_staging_urls)
        self.assertIn("https://api.cheddar.biz", roe.allowed_production_urls)
        self.assertIn("https://staging-api.cheddar.biz", roe.forbidden_urls)

    def test_security_map_update_requires_sanitized_content(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            sec = root / ".security"
            sec.mkdir()
            (sec / "rules-of-engagement.md").write_text("rules", encoding="utf-8")
            (sec / "attack-surface.md").write_text("# Attack Surface\n", encoding="utf-8")
            security_map = load_security_map(root)
            update = propose_security_map_update(security_map, "attack-surface.md", "# Drift\n\n- none")
            write_security_map_update(security_map, update)
            self.assertIn("pentest-harness:start", (sec / "attack-surface.md").read_text(encoding="utf-8"))
            with self.assertRaises(ValueError):
                propose_security_map_update(security_map, "attack-surface.md", "Cookie: session=secret")

    def test_documented_routes_uses_cheddar_handler_auth_money_columns(self):
        markdown = """
| Method | Path | File | Handler | Auth | Money | Notes |
|---|---|---|---|---|---|---|
| `POST` | `/v1/deposit` | `api/src/rest/payment/crypto/deposit.ts:24` | `deposit` | API key | Direct | Creates deposit. |
"""
        routes = documented_routes(markdown)
        self.assertEqual(routes[0].auth, "API key")
        self.assertEqual(routes[0].money, "Direct")

    def test_write_security_map_update_writes_sanitized_return_value(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            sec = root / ".security"
            sec.mkdir()
            (sec / "rules-of-engagement.md").write_text("rules", encoding="utf-8")
            (sec / "attack-surface.md").write_text("# Attack Surface\n", encoding="utf-8")
            security_map = load_security_map(root)
            update = SecurityMapUpdate(
                relative_path="attack-surface.md",
                proposed_content="Identifier 123e4567-e89b-12d3-a456-426614174000 and hex abcdefabcdefabcdefabcdefabcdefab\n",
                diff="",
            )
            target = write_security_map_update(security_map, update)
            written = target.read_text(encoding="utf-8")
            self.assertNotIn("123e4567-e89b-12d3-a456-426614174000", written)
            self.assertNotIn("abcdefabcdefabcdefabcdefabcdefab", written)
            self.assertIn("[uuid:", written)
            self.assertIn("[hex:", written)


if __name__ == "__main__":
    unittest.main()
