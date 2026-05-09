from datetime import UTC, datetime, timedelta
from pathlib import Path
import unittest

from pentest_harness.modules.webhook_replay_freshness import WebhookReplayFreshnessModule, classify_webhook_freshness


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

    def test_synthetic_fixtures_do_not_contain_private_target_details(self):
        module_path = Path(__file__).parents[1] / "src" / "pentest_harness" / "modules" / "webhook_replay_freshness.py"
        haystack = module_path.read_text(encoding="utf-8").lower()
        forbidden_terms = (
            "cheddar" + ".biz",
            "staging" + "-" + "api",
            "coin" + "flow",
            "quick" + "node",
            "svi" + "x",
            "authori" + "zation:",
            "cook" + "ie:",
            "private" + " key",
            "mnemo" + "nic",
            "customer",
        )
        for term in forbidden_terms:
            self.assertNotIn(term, haystack)


if __name__ == "__main__":
    unittest.main()
