import json
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from io import StringIO
from pathlib import Path

from pentest_harness.cli import main


REQUIRED_FILES = [
    "notes.md",
    "reachability-snapshot.md",
    "decision-gate.md",
    "threat-model.md",
    "code-map.md",
    "state-machine.md",
    "race-hypotheses.md",
    "local-proof-plan.md",
    "local-proof-results.md",
    "staging-readiness.md",
    "staging-safety-gates.md",
    "staging-probe-plan.md",
    "evidence-sanitization-plan.md",
    "pen-test-reinforcement.md",
    "commands.md",
    "findings.md",
    "evidence/result.schema.json",
    "evidence/result.json",
]


class MoneyMovingRaceScaffoldTests(unittest.TestCase):
    def test_cli_command_exists_and_creates_timestamped_directory(self):
        with tempfile.TemporaryDirectory() as tmp:
            code, stdout, stderr = _run_main(_scaffold_args(tmp))
            path = _path_from_stdout(stdout)
        self.assertEqual(code, 0)
        self.assertEqual(stderr, "")
        self.assertIn("Campaign scaffold created:", stdout)
        self.assertRegex(path.name, r"^settlement-duplicate-execution-\d{8}T\d{6}Z$")

    def test_all_required_files_are_created(self):
        with tempfile.TemporaryDirectory() as tmp:
            code, stdout, _stderr = _run_main(_scaffold_args(tmp))
            path = _path_from_stdout(stdout)
            created = [name for name in REQUIRED_FILES if (path / name).is_file()]
        self.assertEqual(code, 0)
        self.assertEqual(created, REQUIRED_FILES)

    def test_result_json_has_sanitized_defaults(self):
        with tempfile.TemporaryDirectory() as tmp:
            _code, stdout, _stderr = _run_main(_scaffold_args(tmp))
            path = _path_from_stdout(stdout)
            result = json.loads((path / "evidence" / "result.json").read_text(encoding="utf-8"))
        self.assertEqual(result["project"], "cheddar")
        self.assertEqual(result["target_name"], "settlement-duplicate-execution")
        self.assertEqual(result["classification"], "inconclusive")
        self.assertFalse(result["live_http_sent"])
        self.assertFalse(result["staging_hit"])
        self.assertFalse(result["production_hit"])
        self.assertFalse(result["live_provider_calls"])
        self.assertFalse(result["real_funds_used"])
        self.assertFalse(result["local_proof_confirmed"])
        self.assertEqual(result["external_reachability"], "inconclusive")
        self.assertEqual(result["deployment_topology_reachability"], "unknown")
        self.assertEqual(result["decision_gate"], "unset")
        self.assertEqual(result["caveats"], [])

    def test_result_schema_exists_and_validates_default_fields_shape(self):
        with tempfile.TemporaryDirectory() as tmp:
            _code, stdout, _stderr = _run_main(_scaffold_args(tmp))
            path = _path_from_stdout(stdout)
            schema = json.loads((path / "evidence" / "result.schema.json").read_text(encoding="utf-8"))
            result = json.loads((path / "evidence" / "result.json").read_text(encoding="utf-8"))
        self.assertEqual(schema["additionalProperties"], False)
        self.assertEqual(set(schema["required"]), set(result))
        self.assertIn("unset", schema["properties"]["decision_gate"]["enum"])

    def test_reachability_snapshot_contains_required_topology_checklist(self):
        with tempfile.TemporaryDirectory() as tmp:
            _code, stdout, _stderr = _run_main(_scaffold_args(tmp))
            text = (_path_from_stdout(stdout) / "reachability-snapshot.md").read_text(encoding="utf-8")
        for phrase in [
            "worker/task count",
            "consumer count per relevant queue",
            "prefetch/concurrency settings",
            "retry/redelivery behavior",
            "duplicate-message reachability",
            "attacker-controlled trigger",
            "side-effect worker safety",
            "whether staging can observe safely",
            "whether topology serializes the race",
            "what topology change would make the race reachable",
        ]:
            self.assertIn(phrase, text)

    def test_decision_gate_contains_four_outcomes(self):
        with tempfile.TemporaryDirectory() as tmp:
            _code, stdout, _stderr = _run_main(_scaffold_args(tmp))
            text = (_path_from_stdout(stdout) / "decision-gate.md").read_text(encoding="utf-8")
        for phrase in [
            "Continue deep exploit proof",
            "Stop and write latent finding",
            "Do staging-readiness first",
            "Needs explicit approval",
        ]:
            self.assertIn(phrase, text)

    def test_generated_templates_state_staging_and_fixing_rules(self):
        with tempfile.TemporaryDirectory() as tmp:
            _code, stdout, _stderr = _run_main(_scaffold_args(tmp))
            path = _path_from_stdout(stdout)
            combined = "\n".join((path / name).read_text(encoding="utf-8") for name in ["notes.md", "staging-readiness.md", "staging-safety-gates.md"])
        lowered = combined.lower()
        self.assertIn("staging is allowed for authorized systems, but gated", lowered)
        self.assertIn("do not default to fixing the application", lowered)
        self.assertIn("provider-bound paths require explicit safety controls", lowered)
        self.assertIn("separate local proof, external reachability, deployed topology, and staging/live validation", lowered)

    def test_generated_files_do_not_ask_for_raw_secrets(self):
        with tempfile.TemporaryDirectory() as tmp:
            _code, stdout, _stderr = _run_main(_scaffold_args(tmp))
            path = _path_from_stdout(stdout)
            combined = "\n".join(file.read_text(encoding="utf-8") for file in path.rglob("*") if file.is_file())
        lowered = combined.lower()
        self.assertNotIn("paste your secret", lowered)
        self.assertNotIn("paste secret values", lowered)
        self.assertIn("do not paste raw secrets", lowered)

    def test_custom_project_target_name_and_output_root_are_supported(self):
        with tempfile.TemporaryDirectory() as tmp:
            args = [
                "campaign",
                "scaffold",
                "money-moving-race",
                "--project",
                "custom-project",
                "--target-name",
                "custom-target",
                "--output-root",
                tmp,
            ]
            code, stdout, stderr = _run_main(args)
            path = _path_from_stdout(stdout)
            result = json.loads((path / "evidence" / "result.json").read_text(encoding="utf-8"))
        self.assertEqual(code, 0)
        self.assertEqual(stderr, "")
        self.assertTrue(str(path).startswith(tmp))
        self.assertRegex(path.name, r"^custom-target-\d{8}T\d{6}Z$")
        self.assertEqual(result["project"], "custom-project")
        self.assertEqual(result["target_name"], "custom-target")


def _scaffold_args(output_root: str) -> list[str]:
    return [
        "campaign",
        "scaffold",
        "money-moving-race",
        "--project",
        "cheddar",
        "--target-name",
        "settlement-duplicate-execution",
        "--output-root",
        output_root,
    ]


def _path_from_stdout(stdout: str) -> Path:
    for line in stdout.splitlines():
        if line.startswith("path: "):
            return Path(line.removeprefix("path: "))
    raise AssertionError(f"No path line in output: {stdout}")


def _run_main(argv: list[str]) -> tuple[int, str, str]:
    stdout = StringIO()
    stderr = StringIO()
    with redirect_stdout(stdout), redirect_stderr(stderr):
        code = main(argv)
    return code, stdout.getvalue(), stderr.getvalue()


if __name__ == "__main__":
    unittest.main()
