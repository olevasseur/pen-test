from datetime import UTC, datetime, timedelta
from contextlib import contextmanager
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from pentest_harness.modules.webhook_replay_freshness import (
    WebhookHttpResponse,
    WebhookReplayFreshnessModule,
    classify_webhook_freshness,
    classify_live_results,
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

    def test_live_staging_execution_with_fake_sender_executes_exactly_three_cases(self):
        captured = []

        def fake_sender(prepared):
            captured.append(prepared)
            return WebhookHttpResponse(status_code=401 if prepared.case_id == "stale_timestamp" else 200)

        with tempfile.TemporaryDirectory() as runtime_tmp, tempfile.TemporaryDirectory() as fixture_tmp, tempfile.TemporaryDirectory() as target_tmp:
            fixture_path = Path(fixture_tmp) / "fixture.json"
            fixture_path.write_text(json.dumps(_valid_live_fixture()), encoding="utf-8")
            with _runtime_context(runtime_tmp), patch.dict("os.environ", {"QUICKNODE_STAGING_WEBHOOK_SECRET": "unit-test-signing-value"}):
                result = WebhookReplayFreshnessModule().execute_live_staging(
                    project="cheddar",
                    target_environment="staging",
                    target_repo=target_tmp,
                    fixture_file=str(fixture_path),
                    authorization_ticket="TEST-123",
                    sender=fake_sender,
                    now=self.now,
                )
                self.assertTrue(result.evidence_path.exists())
        self.assertEqual([request.case_id for request in captured], ["fresh_control", "stale_timestamp", "replay_identical_request"])
        self.assertEqual([case.case_id for case in result.cases], ["fresh_control", "stale_timestamp", "replay_identical_request"])

    def test_replay_reuses_identical_signed_request_material_from_fresh_control(self):
        captured = []

        def fake_sender(prepared):
            captured.append(prepared)
            return WebhookHttpResponse(status_code=200)

        with tempfile.TemporaryDirectory() as runtime_tmp, tempfile.TemporaryDirectory() as fixture_tmp, tempfile.TemporaryDirectory() as target_tmp:
            fixture_path = Path(fixture_tmp) / "fixture.json"
            fixture_path.write_text(json.dumps(_valid_live_fixture()), encoding="utf-8")
            with _runtime_context(runtime_tmp), patch.dict("os.environ", {"QUICKNODE_STAGING_WEBHOOK_SECRET": "unit-test-signing-value"}):
                WebhookReplayFreshnessModule().execute_live_staging(
                    project="cheddar",
                    target_environment="staging",
                    target_repo=target_tmp,
                    fixture_file=str(fixture_path),
                    authorization_ticket="TEST-123",
                    sender=fake_sender,
                    now=self.now,
                )
        self.assertEqual(captured[0].headers, captured[2].headers)
        self.assertEqual(captured[0].body, captured[2].body)
        self.assertEqual(captured[0].timestamp, captured[2].timestamp)
        self.assertEqual(captured[0].nonce, captured[2].nonce)

    def test_stale_timestamp_is_older_than_freshness_tolerance(self):
        captured = []

        def fake_sender(prepared):
            captured.append(prepared)
            return WebhookHttpResponse(status_code=401)

        with tempfile.TemporaryDirectory() as runtime_tmp, tempfile.TemporaryDirectory() as fixture_tmp, tempfile.TemporaryDirectory() as target_tmp:
            fixture_path = Path(fixture_tmp) / "fixture.json"
            fixture_path.write_text(json.dumps(_valid_live_fixture()), encoding="utf-8")
            with _runtime_context(runtime_tmp), patch.dict("os.environ", {"QUICKNODE_STAGING_WEBHOOK_SECRET": "unit-test-signing-value"}):
                WebhookReplayFreshnessModule().execute_live_staging(
                    project="cheddar",
                    target_environment="staging",
                    target_repo=target_tmp,
                    fixture_file=str(fixture_path),
                    authorization_ticket="TEST-123",
                    sender=fake_sender,
                    now=self.now,
                )
        fresh, stale = captured[0], captured[1]
        self.assertGreater(fresh.timestamp - stale.timestamp, 300)

    def test_live_result_flags_possible_stale_and_replay_acceptance(self):
        cases = (
            _case("fresh_control", "fresh", 200, "boundary_accepted"),
            _case("stale_timestamp", "stale", 200, "boundary_accepted"),
            _case("replay_identical_request", "replay", 200, "boundary_accepted"),
        )
        stale_possible, replay_possible, inconclusive = classify_live_results(cases)
        self.assertTrue(stale_possible)
        self.assertTrue(replay_possible)
        self.assertFalse(inconclusive)

    def test_fresh_rejected_makes_live_result_inconclusive(self):
        cases = (
            _case("fresh_control", "fresh", 401, "boundary_rejected"),
            _case("stale_timestamp", "stale", 401, "boundary_rejected"),
            _case("replay_identical_request", "replay", 401, "boundary_rejected"),
        )
        stale_possible, replay_possible, inconclusive = classify_live_results(cases)
        self.assertFalse(stale_possible)
        self.assertFalse(replay_possible)
        self.assertTrue(inconclusive)

    def test_missing_env_var_for_signing_reference_fails_closed(self):
        with tempfile.TemporaryDirectory() as runtime_tmp, tempfile.TemporaryDirectory() as fixture_tmp, tempfile.TemporaryDirectory() as target_tmp:
            fixture_path = Path(fixture_tmp) / "fixture.json"
            fixture_path.write_text(json.dumps(_valid_live_fixture()), encoding="utf-8")
            with _runtime_context(runtime_tmp), patch.dict("os.environ", {}, clear=True):
                with self.assertRaisesRegex(ValueError, "environment variable is not set"):
                    WebhookReplayFreshnessModule().execute_live_staging(
                        project="cheddar",
                        target_environment="staging",
                        target_repo=target_tmp,
                        fixture_file=str(fixture_path),
                        authorization_ticket="TEST-123",
                        sender=lambda _request: WebhookHttpResponse(status_code=200),
                        now=self.now,
                    )

    def test_fixture_file_inside_pen_test_repo_is_rejected(self):
        fixture_path = Path(__file__).parents[1] / "tmp-webhook-fixture.test.json"
        fixture_path.write_text(json.dumps(_valid_live_fixture()), encoding="utf-8")
        try:
            with tempfile.TemporaryDirectory() as target_tmp, patch.dict("os.environ", {"QUICKNODE_STAGING_WEBHOOK_SECRET": "unit-test-signing-value"}):
                with self.assertRaisesRegex(ValueError, "outside the pen-test repo"):
                    WebhookReplayFreshnessModule().execute_live_staging(
                        project="cheddar",
                        target_environment="staging",
                        target_repo=target_tmp,
                        fixture_file=str(fixture_path),
                        authorization_ticket="TEST-123",
                        sender=lambda _request: WebhookHttpResponse(status_code=200),
                        now=self.now,
                    )
        finally:
            fixture_path.unlink(missing_ok=True)

    def test_fixture_file_inside_target_repo_is_rejected(self):
        with tempfile.TemporaryDirectory() as target_tmp, patch.dict("os.environ", {"QUICKNODE_STAGING_WEBHOOK_SECRET": "unit-test-signing-value"}):
            fixture_path = Path(target_tmp) / "fixture.json"
            fixture_path.write_text(json.dumps(_valid_live_fixture()), encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "outside the target repo"):
                WebhookReplayFreshnessModule().execute_live_staging(
                    project="cheddar",
                    target_environment="staging",
                    target_repo=target_tmp,
                    fixture_file=str(fixture_path),
                    authorization_ticket="TEST-123",
                    sender=lambda _request: WebhookHttpResponse(status_code=200),
                    now=self.now,
                )

    def test_evidence_report_omits_secret_signature_and_payload_body(self):
        captured = []

        def fake_sender(prepared):
            captured.append(prepared)
            return WebhookHttpResponse(status_code=200)

        with tempfile.TemporaryDirectory() as runtime_tmp, tempfile.TemporaryDirectory() as fixture_tmp, tempfile.TemporaryDirectory() as target_tmp:
            fixture_path = Path(fixture_tmp) / "fixture.json"
            fixture_path.write_text(json.dumps(_valid_live_fixture()), encoding="utf-8")
            with _runtime_context(runtime_tmp), patch.dict("os.environ", {"QUICKNODE_STAGING_WEBHOOK_SECRET": "unit-test-signing-value"}):
                result = WebhookReplayFreshnessModule().execute_live_staging(
                    project="cheddar",
                    target_environment="staging",
                    target_repo=target_tmp,
                    fixture_file=str(fixture_path),
                    authorization_ticket="TEST-123",
                    sender=fake_sender,
                    now=self.now,
                )
            evidence = result.evidence_path.read_text(encoding="utf-8")
        self.assertNotIn("unit-test-signing-value", evidence)
        self.assertNotIn(captured[0].headers["x-qn-signature"], evidence)
        self.assertNotIn("tb1qsyntheticunmatchedaddress", evidence)


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


def _valid_live_fixture() -> dict:
    fixture = _valid_fixture()
    fixture["base_url"] = "https://staging.example.test"
    fixture["signing"]["algorithm"] = "quicknode_hmac_sha256_hex_v1"
    fixture["signing"]["signed_content_template"] = "nonce_timestamp_json_body"
    fixture["payload_template"]["body"] = [
        {
            "txid": "synthetic-unmatched-btc-tx",
            "vout": [
                {
                    "address": "tb1qsyntheticunmatchedaddress",
                    "value": 1,
                }
            ],
        }
    ]
    return fixture


def _case(case_id: str, timestamp_category: str, status_code: int, classification: str):
    from pentest_harness.modules.webhook_replay_freshness import LiveCaseResult

    return LiveCaseResult(
        case_id=case_id,
        timestamp_category=timestamp_category,
        status_code=status_code,
        response_classification=classification,
        http_sent=True,
    )


@contextmanager
def _runtime_context(runtime_tmp: str):
    from pentest_harness.core import artifacts

    with patch.object(artifacts, "RUNTIME_ROOT", Path(runtime_tmp)):
        yield


if __name__ == "__main__":
    unittest.main()
