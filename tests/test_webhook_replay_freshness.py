from datetime import UTC, datetime, timedelta
import json
from pathlib import Path
import tempfile
import unittest

from pentest_harness.modules.webhook_replay_freshness import (
    WebhookReplayFreshnessModule,
    classify_webhook_freshness,
    validate_replay_fixture,
)


class WebhookReplayFreshnessTests(unittest.TestCase):
    def setUp(self):
        self.now = datetime(2026, 1, 1, 12, 0, 0, tzinfo=UTC)

    def test_timestamp_within_tolerance_is_fresh(self):
        result = classify_webhook_freshness(
            case_id="fresh",
            timestamp=self.now - timedelta(seconds=10),
            now=self.now,
            tolerance_seconds=300,
            delivery_id="synthetic-delivery-001",
        )
        self.assertEqual(result.status, "accepted")
        self.assertEqual(result.classification, "fresh")
        self.assertFalse(result.duplicate_detected)

    def test_timestamp_older_than_tolerance_is_stale(self):
        result = classify_webhook_freshness(
            case_id="stale",
            timestamp=self.now - timedelta(seconds=301),
            now=self.now,
            tolerance_seconds=300,
        )
        self.assertEqual(result.status, "rejected")
        self.assertEqual(result.classification, "stale_timestamp")

    def test_timestamp_too_far_in_future_is_invalid(self):
        result = classify_webhook_freshness(
            case_id="future",
            timestamp=self.now + timedelta(seconds=301),
            now=self.now,
            tolerance_seconds=300,
        )
        self.assertEqual(result.status, "rejected")
        self.assertEqual(result.classification, "future_timestamp")

    def test_missing_timestamp_is_invalid(self):
        result = classify_webhook_freshness(
            case_id="missing",
            timestamp=None,
            now=self.now,
            tolerance_seconds=300,
        )
        self.assertEqual(result.status, "rejected")
        self.assertEqual(result.classification, "missing_timestamp")

    def test_malformed_timestamp_is_invalid(self):
        result = classify_webhook_freshness(
            case_id="malformed",
            timestamp="not-a-timestamp",
            now=self.now,
            tolerance_seconds=300,
        )
        self.assertEqual(result.status, "rejected")
        self.assertEqual(result.classification, "malformed_timestamp")

    def test_duplicate_delivery_id_is_replay(self):
        result = classify_webhook_freshness(
            case_id="duplicate",
            timestamp=self.now.isoformat(),
            now=self.now,
            tolerance_seconds=300,
            delivery_id="synthetic-delivery-001",
            prior_delivery_ids={"synthetic-delivery-001"},
        )
        self.assertEqual(result.status, "rejected")
        self.assertEqual(result.classification, "duplicate_delivery_id")
        self.assertTrue(result.duplicate_detected)

    def test_new_delivery_id_is_not_duplicate(self):
        result = classify_webhook_freshness(
            case_id="new-delivery",
            timestamp=str(int(self.now.timestamp())),
            now=self.now,
            tolerance_seconds=300,
            delivery_id="synthetic-delivery-002",
            prior_delivery_ids={"synthetic-delivery-001"},
        )
        self.assertEqual(result.status, "accepted")
        self.assertEqual(result.classification, "fresh")
        self.assertFalse(result.duplicate_detected)

    def test_module_metadata_disables_production(self):
        metadata = WebhookReplayFreshnessModule.metadata
        self.assertEqual(metadata.id, "webhook-replay-freshness")
        self.assertFalse(metadata.production_allowed)
        self.assertFalse(metadata.requires_credentials)
        self.assertTrue(metadata.exploit_capable)

    def test_synthetic_fixtures_do_not_contain_private_target_details(self):
        module_path = Path(__file__).parents[1] / "src" / "pentest_harness" / "modules" / "webhook_replay_freshness.py"
        haystack = module_path.read_text(encoding="utf-8").lower()
        forbidden_terms = (
            "cheddar" + ".biz",
            "staging" + "-" + "api",
            "coin" + "flow",
            "svi" + "x",
            "authori" + "zation:",
            "cook" + "ie:",
            "private" + " key",
            "mnemo" + "nic",
        )
        for term in forbidden_terms:
            self.assertNotIn(term, haystack)

    def test_fixture_schema_validation_accepts_complete_synthetic_fixture(self):
        fixture = validate_replay_fixture(_valid_fixture())
        self.assertEqual(fixture.provider, "quicknode")
        self.assertEqual(fixture.surface, "btc_streams")
        self.assertEqual(fixture.endpoint_path, "/quicknode/btc/streams")
        self.assertEqual(fixture.freshness_tolerance_seconds, 300)

    def test_fixture_validation_rejects_missing_endpoint_path(self):
        fixture = _valid_fixture()
        fixture.pop("endpoint_path")
        with self.assertRaisesRegex(ValueError, "endpoint_path"):
            validate_replay_fixture(fixture)

    def test_fixture_validation_rejects_wrong_provider(self):
        fixture = _valid_fixture()
        fixture["provider"] = "other"
        with self.assertRaisesRegex(ValueError, "provider must be quicknode"):
            validate_replay_fixture(fixture)

    def test_fixture_validation_rejects_wrong_surface(self):
        fixture = _valid_fixture()
        fixture["surface"] = "other"
        with self.assertRaisesRegex(ValueError, "surface must be btc_streams"):
            validate_replay_fixture(fixture)

    def test_fixture_validation_rejects_non_staging_target_environment(self):
        fixture = _valid_fixture(target_environment="production")
        with self.assertRaisesRegex(ValueError, "must be staging"):
            validate_replay_fixture(fixture)

    def test_fixture_validation_rejects_money_impact(self):
        fixture = _valid_fixture()
        fixture["fixture_safety"]["no_money_impact"] = False
        with self.assertRaisesRegex(ValueError, "no_money_impact"):
            validate_replay_fixture(fixture)

    def test_fixture_validation_rejects_non_synthetic_payload(self):
        fixture = _valid_fixture()
        fixture["fixture_safety"]["synthetic_payload"] = False
        with self.assertRaisesRegex(ValueError, "synthetic_payload"):
            validate_replay_fixture(fixture)

    def test_fixture_validation_rejects_inline_signing_secret(self):
        fixture = _valid_fixture()
        fixture["signing"]["reference"] = "super-secret-inline-value"
        with self.assertRaisesRegex(ValueError, "inline sensitive material"):
            validate_replay_fixture(fixture)

    def test_fixture_validation_rejects_invalid_env_signing_references(self):
        invalid_references = (
            "env:",
            "env:foo",
            "env:quicknode_secret",
            "env:abc.def",
            "env:abc-def",
            "env:sk_live_123",
            "env:eyJhbGciOi...",
            "literal-secret",
            "qn_secret_value",
            "anything-not-env",
        )
        for reference in invalid_references:
            with self.subTest(reference=reference):
                fixture = _valid_fixture()
                fixture["signing"]["reference"] = reference
                with self.assertRaises(ValueError):
                    validate_replay_fixture(fixture)

    def test_fixture_validation_accepts_strict_env_signing_references(self):
        for reference in ("env:QUICKNODE_WEBHOOK_SECRET", "env:STAGING_QN_BTC_SIGNING_SECRET"):
            with self.subTest(reference=reference):
                fixture = _valid_fixture()
                fixture["signing"]["reference"] = reference
                parsed = validate_replay_fixture(fixture)
                self.assertEqual(parsed.signing.reference, reference)

    def test_dry_run_plan_includes_required_cases(self):
        module = WebhookReplayFreshnessModule()
        with tempfile.TemporaryDirectory() as tmp:
            fixture_path = Path(tmp) / "fixture.json"
            fixture_path.write_text(json.dumps(_valid_fixture()), encoding="utf-8")
            plan = module.build_dry_run_plan(project="cheddar", target_environment="staging", fixture_file=str(fixture_path))
        self.assertEqual(plan.planned_cases, ("fresh_control", "stale_timestamp", "replay_identical_request"))
        self.assertTrue(plan.no_http_sent)
        self.assertFalse(plan.live_execution_enabled)


def _valid_fixture(target_environment: str = "staging") -> dict:
    return {
        "provider": "quicknode",
        "surface": "btc_streams",
        "endpoint_path": "/quicknode/btc/streams",
        "target_environment": target_environment,
        "signature_headers": {
            "signature": "x-qn-signature",
            "nonce": "x-qn-nonce",
            "timestamp": "x-qn-timestamp",
        },
        "timestamp_format": "unix_seconds_or_documented_format",
        "freshness_tolerance_seconds": 300,
        "signing": {
            "mode": "external_reference",
            "reference": "env:QUICKNODE_STAGING_WEBHOOK_SECRET",
        },
        "fixture_safety": {
            "synthetic_payload": True,
            "no_money_impact": True,
            "no_customer_data": True,
            "staging_only": True,
        },
        "payload_template": {
            "description": "synthetic BTC-shaped event with unmatched output address",
        },
    }


if __name__ == "__main__":
    unittest.main()
