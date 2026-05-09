import json
import tempfile
import unittest
from contextlib import contextmanager, redirect_stderr, redirect_stdout
from io import StringIO
from pathlib import Path
from unittest.mock import patch

from pentest_harness.cli import main
from pentest_harness.core import artifacts
from pentest_harness.core.ledger import LedgerEntry, append_ledger
from pentest_harness.core.scans import ScanModuleState, ScanState, utc_now, write_scan_state
from pentest_harness.core.suggestions import SuggestionContext, suggestions_to_json, suggest_next_actions
from pentest_harness.core.security_map import load_security_map


class SuggestionTests(unittest.TestCase):
    def test_suggest_works_with_no_runtime_ledger(self):
        with tempfile.TemporaryDirectory() as repo_tmp, tempfile.TemporaryDirectory() as runtime_tmp:
            repo = _make_security_repo(repo_tmp)
            with _suggest_context(runtime_tmp):
                code, stdout, _stderr = _run_main(["suggest", "cheddar", "--target-repo", str(repo)])
        self.assertEqual(code, 0)
        self.assertIn("Suggestions for cheddar", stdout)

    def test_suggest_recommends_baseline_when_route_inventory_has_not_run(self):
        with tempfile.TemporaryDirectory() as repo_tmp, tempfile.TemporaryDirectory() as runtime_tmp:
            repo = _make_security_repo(repo_tmp)
            with _suggest_context(runtime_tmp):
                _code, stdout, _stderr = _run_main(["suggest", "cheddar", "--target-repo", str(repo)])
        self.assertIn("Run baseline route inventory", stdout)

    def test_suggest_detects_missing_webhook_negative_coverage(self):
        with tempfile.TemporaryDirectory() as repo_tmp, tempfile.TemporaryDirectory() as runtime_tmp:
            repo = _make_security_repo(repo_tmp)
            with _suggest_context(runtime_tmp):
                append_ledger("cheddar", _entry("route-inventory", "passed"))
                _code, stdout, _stderr = _run_main(["suggest", "cheddar", "--target-repo", str(repo)])
        self.assertIn("Run webhook negative-auth coverage", stdout)

    def test_suggest_reports_replay_freshness_skeleton_pending(self):
        with tempfile.TemporaryDirectory() as repo_tmp, tempfile.TemporaryDirectory() as runtime_tmp:
            repo = _make_security_repo(repo_tmp)
            with _suggest_context(runtime_tmp):
                _code, stdout, _stderr = _run_main(["suggest", "cheddar", "--target-repo", str(repo)])
        self.assertIn("Webhook replay/freshness target coverage pending", stdout)

    def test_suggest_recommends_replay_freshness_module_when_registry_lacks_one(self):
        with tempfile.TemporaryDirectory() as repo_tmp:
            repo = _make_security_repo(repo_tmp)
            security_map = load_security_map(repo)
            context = SuggestionContext(
                project="demo",
                security_map=security_map,
                ledger_entries=(),
                latest_scan_state=None,
                route_inventory_artifacts=(),
                module_ids=("route-inventory",),
                production_capable_module_count=1,
            )
            suggestions = suggest_next_actions(context)
        self.assertIn("add-webhook-replay-freshness-module", {suggestion.id for suggestion in suggestions})

    def test_suggest_detects_checkout_flow_coverage_gap(self):
        with tempfile.TemporaryDirectory() as repo_tmp, tempfile.TemporaryDirectory() as runtime_tmp:
            repo = _make_security_repo(repo_tmp)
            with _suggest_context(runtime_tmp):
                append_ledger("cheddar", _entry("route-inventory", "passed"))
                append_ledger("cheddar", _entry("webhook-negative", "passed"))
                _code, stdout, _stderr = _run_main(["suggest", "cheddar", "--target-repo", str(repo)])
        self.assertIn("Run checkout exposure summary", stdout)

    def test_completed_scan_evidence_counts_as_coverage(self):
        with tempfile.TemporaryDirectory() as repo_tmp, tempfile.TemporaryDirectory() as runtime_tmp:
            repo = _make_security_repo(repo_tmp)
            with _suggest_context(runtime_tmp):
                state = ScanState(
                    scan_id="scan-completed",
                    project="cheddar",
                    plan_id="baseline",
                    target="staging",
                    target_repo=str(repo),
                    requested_evidence_level="non_mutating_probe",
                    started_at=utc_now(),
                )
                state.completed.append(ScanModuleState(module_id="route-inventory", status="completed"))
                state.completed.append(ScanModuleState(module_id="webhook-negative", status="completed"))
                state.completed.append(ScanModuleState(module_id="checkout-exposure-summary", status="completed"))
                write_scan_state(state)
                _code, stdout, _stderr = _run_main(["suggest", "cheddar", "--target-repo", str(repo)])
        self.assertNotIn("Run baseline route inventory", stdout)
        self.assertNotIn("Run webhook negative-auth coverage", stdout)
        self.assertNotIn("Run checkout exposure summary", stdout)

    def test_suggest_reports_failed_scan_modules(self):
        with tempfile.TemporaryDirectory() as repo_tmp, tempfile.TemporaryDirectory() as runtime_tmp:
            repo = _make_security_repo(repo_tmp)
            with _suggest_context(runtime_tmp):
                state = ScanState(
                    scan_id="scan-failed",
                    project="cheddar",
                    plan_id="baseline",
                    target="staging",
                    target_repo=str(repo),
                    requested_evidence_level="observe_only",
                    started_at=utc_now(),
                )
                state.failed.append(ScanModuleState(module_id="security-map-drift", status="failed", error="failed"))
                write_scan_state(state)
                _code, stdout, _stderr = _run_main(["suggest", "cheddar", "--target-repo", str(repo)])
        self.assertIn("Review or rerun failed scan modules", stdout)
        self.assertIn("security-map-drift", stdout)

    def test_json_output_is_valid(self):
        with tempfile.TemporaryDirectory() as repo_tmp, tempfile.TemporaryDirectory() as runtime_tmp:
            repo = _make_security_repo(repo_tmp)
            with _suggest_context(runtime_tmp):
                code, stdout, _stderr = _run_main(["suggest", "cheddar", "--target-repo", str(repo), "--format", "json"])
        self.assertEqual(code, 0)
        parsed = json.loads(stdout)
        self.assertEqual(parsed["project"], "cheddar")
        self.assertIsInstance(parsed["suggestions"], list)
        self.assertIn("id", parsed["suggestions"][0])

    def test_suggest_does_not_write_security_map(self):
        with tempfile.TemporaryDirectory() as repo_tmp, tempfile.TemporaryDirectory() as runtime_tmp:
            repo = _make_security_repo(repo_tmp)
            attack_surface = repo / ".security" / "attack-surface.md"
            before = attack_surface.read_text(encoding="utf-8")
            with _suggest_context(runtime_tmp):
                code, _stdout, _stderr = _run_main(["suggest", "cheddar", "--target-repo", str(repo)])
            after = attack_surface.read_text(encoding="utf-8")
        self.assertEqual(code, 0)
        self.assertEqual(before, after)

    def test_suggest_does_not_create_runtime_artifacts(self):
        with tempfile.TemporaryDirectory() as repo_tmp, tempfile.TemporaryDirectory() as runtime_tmp:
            repo = _make_security_repo(repo_tmp)
            runtime_root = Path(runtime_tmp)
            before = sorted(path.relative_to(runtime_root) for path in runtime_root.rglob("*"))
            with _suggest_context(runtime_tmp):
                code, _stdout, _stderr = _run_main(["suggest", "cheddar", "--target-repo", str(repo)])
            after = sorted(path.relative_to(runtime_root) for path in runtime_root.rglob("*"))
        self.assertEqual(code, 0)
        self.assertEqual(before, after)

    def test_empty_security_folder_still_produces_safe_output(self):
        with tempfile.TemporaryDirectory() as repo_tmp, tempfile.TemporaryDirectory() as runtime_tmp:
            repo = Path(repo_tmp)
            (repo / ".security").mkdir()
            with _suggest_context(runtime_tmp):
                code, stdout, _stderr = _run_main(["suggest", "cheddar", "--target-repo", str(repo)])
        self.assertEqual(code, 0)
        self.assertIn("Production testing framework has no enabled modules", stdout)

    def test_missing_security_folder_returns_nonzero(self):
        with tempfile.TemporaryDirectory() as repo_tmp, tempfile.TemporaryDirectory() as runtime_tmp:
            with _suggest_context(runtime_tmp):
                code, _stdout, stderr = _run_main(["suggest", "cheddar", "--target-repo", repo_tmp])
        self.assertEqual(code, 2)
        self.assertIn("does not contain .security", stderr)

    def test_malformed_scan_state_is_ignored(self):
        with tempfile.TemporaryDirectory() as repo_tmp, tempfile.TemporaryDirectory() as runtime_tmp:
            repo = _make_security_repo(repo_tmp)
            bad_state = Path(runtime_tmp) / "cheddar" / "scans" / "bad"
            bad_state.mkdir(parents=True)
            (bad_state / "scan-state.json").write_text("{not-json", encoding="utf-8")
            with _suggest_context(runtime_tmp):
                code, stdout, _stderr = _run_main(["suggest", "cheddar", "--target-repo", str(repo)])
        self.assertEqual(code, 0)
        self.assertIn("Suggestions for cheddar", stdout)

    def test_malformed_latest_scan_falls_back_to_valid_scan(self):
        with tempfile.TemporaryDirectory() as repo_tmp, tempfile.TemporaryDirectory() as runtime_tmp:
            repo = _make_security_repo(repo_tmp)
            with _suggest_context(runtime_tmp):
                valid = ScanState(
                    scan_id="valid",
                    project="cheddar",
                    plan_id="baseline",
                    target="staging",
                    target_repo=str(repo),
                    requested_evidence_level="observe_only",
                    started_at=utc_now(),
                )
                valid.failed.append(ScanModuleState(module_id="webhook-negative", status="failed", error="failed"))
                write_scan_state(valid)
                bad_state = Path(runtime_tmp) / "cheddar" / "scans" / "zz-bad"
                bad_state.mkdir(parents=True)
                (bad_state / "scan-state.json").write_text("{not-json", encoding="utf-8")
                _code, stdout, _stderr = _run_main(["suggest", "cheddar", "--target-repo", str(repo)])
        self.assertIn("Review or rerun failed scan modules", stdout)

    def test_malformed_ledger_lines_are_ignored(self):
        with tempfile.TemporaryDirectory() as repo_tmp, tempfile.TemporaryDirectory() as runtime_tmp:
            repo = _make_security_repo(repo_tmp)
            ledger = Path(runtime_tmp) / "cheddar" / "ledger.jsonl"
            ledger.parent.mkdir(parents=True)
            ledger.write_text("{not-json\n", encoding="utf-8")
            with _suggest_context(runtime_tmp):
                code, stdout, _stderr = _run_main(["suggest", "cheddar", "--target-repo", str(repo)])
        self.assertEqual(code, 0)
        self.assertIn("Run baseline route inventory", stdout)

    def test_json_output_with_no_suggestions_has_stable_shape(self):
        with tempfile.TemporaryDirectory() as repo_tmp:
            repo = _make_security_repo(repo_tmp)
            security_map = load_security_map(repo)
            context = SuggestionContext(
                project="demo",
                security_map=security_map,
                ledger_entries=(
                    {"module_id": "route-inventory", "outcome": "passed"},
                    {"module_id": "webhook-negative", "outcome": "passed"},
                    {"module_id": "checkout-exposure-summary", "outcome": "passed"},
                    {"module_id": "security-map-drift", "outcome": "passed", "security_map_drift_detected": False},
                    {"module_id": "webhook-replay-freshness", "outcome": "passed", "evidence_level": "non_mutating_probe"},
                ),
                latest_scan_state=None,
                route_inventory_artifacts=(),
                module_ids=("webhook-replay",),
                production_capable_module_count=1,
            )
            payload = json.loads(suggestions_to_json("demo", suggest_next_actions(context)))
        self.assertEqual(payload["project"], "demo")
        self.assertEqual(payload["suggestions"], [])

    def test_text_output_does_not_claim_vulnerability(self):
        with tempfile.TemporaryDirectory() as repo_tmp, tempfile.TemporaryDirectory() as runtime_tmp:
            repo = _make_security_repo(repo_tmp)
            with _suggest_context(runtime_tmp):
                _code, stdout, _stderr = _run_main(["suggest", "cheddar", "--target-repo", str(repo)])
        self.assertNotIn("vulnerable", stdout.lower())
        self.assertNotIn("exploit", stdout.lower())


def _entry(module_id: str, outcome: str) -> LedgerEntry:
    return LedgerEntry(
        run_id=f"run-{module_id}",
        module_id=module_id,
        target_profile="cheddar",
        target_environment="staging",
        base_url="https://staging.example.test",
        safety_level="static_only",
        evidence_level="observe_only",
        production_authorization_ticket=None,
        timestamp=utc_now(),
        outcome=outcome,
        summary=f"{module_id} {outcome}",
        finding_ids=[],
        artifact_references=[],
        linked_security_docs={},
        security_map_drift_detected=False,
        security_map_update_proposed=False,
        security_map_update_written=False,
    )


def _make_security_repo(root_tmp: str) -> Path:
    repo = Path(root_tmp)
    security = repo / ".security"
    (security / "invariants").mkdir(parents=True)
    (security / "flows").mkdir()
    (security / "webhooks").mkdir()
    (security / "findings").mkdir()
    (security / "rules-of-engagement.md").write_text("# Rules\n", encoding="utf-8")
    (security / "attack-surface.md").write_text(
        "# Attack Surface\n\n| Method | Path | File | Handler | Auth | Money |\n|---|---|---|---|---|---|\n| `GET` | `/example` | `app.py:1` | `handler` | Public | None |\n",
        encoding="utf-8",
    )
    (security / "methodology.md").write_text("Webhook replay and freshness checks.\n", encoding="utf-8")
    (security / "trust-boundaries.md").write_text("# Trust\n", encoding="utf-8")
    (security / "findings" / "TEMPLATE.md").write_text("# Finding\n", encoding="utf-8")
    (security / "invariants" / "webhook-trust.md").write_text("Webhook replay freshness nonce stale event controls.\n", encoding="utf-8")
    (security / "flows" / "checkout.md").write_text("Checkout flow.\n", encoding="utf-8")
    (security / "webhooks" / "provider.md").write_text("Webhook replay guidance.\n", encoding="utf-8")
    return repo


@contextmanager
def _suggest_context(runtime_tmp: str):
    with patch.object(artifacts, "RUNTIME_ROOT", Path(runtime_tmp)):
        yield


def _run_main(argv):
    stdout = StringIO()
    stderr = StringIO()
    with redirect_stdout(stdout), redirect_stderr(stderr):
        code = main(argv)
    return code, stdout.getvalue(), stderr.getvalue()


if __name__ == "__main__":
    unittest.main()
