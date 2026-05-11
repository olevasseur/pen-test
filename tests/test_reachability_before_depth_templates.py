import json
import unittest
from pathlib import Path


REPO = Path(__file__).parents[1]
DESIGN = REPO / "docs" / "design" / "reachability-before-depth.md"
TEMPLATE_DIR = REPO / "templates" / "money-moving-race"


class ReachabilityBeforeDepthTemplateTests(unittest.TestCase):
    def test_reachability_gate_files_exist(self):
        self.assertTrue(DESIGN.is_file())
        self.assertTrue((TEMPLATE_DIR / "reachability-snapshot.md").is_file())
        self.assertTrue((TEMPLATE_DIR / "decision-gate.md").is_file())
        self.assertTrue((TEMPLATE_DIR / "evidence.schema.json").is_file())

    def test_required_checklist_items_are_present(self):
        text = _combined_text()
        for phrase in [
            "worker/task count",
            "consumer count per relevant queue",
            "prefetch/concurrency settings",
            "queue retry/redelivery behavior",
            "whether duplicate messages can exist",
            "whether the attacker can externally produce duplicate events",
            "active, paused, dry-run, testnet, or provider-bound",
            "whether staging can safely observe",
            "whether current topology serializes the race",
            "what topology change would make the race reachable",
        ]:
            self.assertIn(phrase, text)

    def test_decision_categories_are_present(self):
        text = _combined_text()
        for phrase in [
            "Continue deep exploit proof",
            "Stop and write latent finding",
            "Do staging-readiness first",
            "Needs explicit approval",
        ]:
            self.assertIn(phrase, text)

    def test_staging_is_allowed_but_gated_not_forbidden(self):
        text = _combined_text().lower()
        self.assertIn("staging is allowed, but gated", text)
        self.assertIn("paused side-effect worker", text)
        self.assertIn("dry-run mode", text)
        self.assertIn("testnet-only behavior", text)

    def test_template_says_not_to_default_to_application_fixes(self):
        text = _combined_text().lower()
        self.assertIn("not an application remediation guide", text)
        self.assertIn("must not default to implementing application fixes", text)
        self.assertIn("application fix attempted", text)

    def test_template_distinguishes_local_external_and_topology(self):
        text = _combined_text().lower()
        self.assertIn("local proof", text)
        self.assertIn("external reachability", text)
        self.assertIn("deployed topology", text)
        self.assertIn("serializes the race", text)

class MoneyMovingRaceEvidenceSchemaTests(unittest.TestCase):
    def test_template_schema_contains_scaffold_result_fields(self):
        schema = json.loads((TEMPLATE_DIR / "evidence.schema.json").read_text(encoding="utf-8"))
        required = schema["required"]
        for field in [
            "campaign_id",
            "project",
            "target_name",
            "classification",
            "live_http_sent",
            "staging_hit",
            "production_hit",
            "live_provider_calls",
            "real_funds_used",
            "local_proof_confirmed",
            "external_reachability",
            "deployment_topology_reachability",
            "duplicate_queue_jobs_observed",
            "duplicate_external_side_effect_observed",
            "duplicate_durable_records_observed",
            "staging_safety_controls_confirmed",
            "staging_probe_run",
            "decision_gate",
            "caveats",
        ]:
            self.assertIn(field, required)

    def test_template_schema_decision_values_match_scaffold_gate(self):
        schema = json.loads((TEMPLATE_DIR / "evidence.schema.json").read_text(encoding="utf-8"))
        decisions = schema["properties"]["decision_gate"]["enum"]
        self.assertEqual(
            decisions,
            [
                "unset",
                "continue_deep_exploit_proof",
                "stop_and_write_latent_finding",
                "do_staging_readiness_first",
                "needs_explicit_approval",
            ],
        )


def _combined_text() -> str:
    paths = [
        DESIGN,
        TEMPLATE_DIR / "reachability-snapshot.md",
        TEMPLATE_DIR / "decision-gate.md",
    ]
    return "\n".join(path.read_text(encoding="utf-8") for path in paths)


if __name__ == "__main__":
    unittest.main()
