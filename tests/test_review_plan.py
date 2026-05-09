import json
import tempfile
import unittest
from contextlib import contextmanager, redirect_stderr, redirect_stdout
from io import StringIO
from pathlib import Path
from unittest.mock import patch

from pentest_harness.cli import main


class ReviewPlanTests(unittest.TestCase):
    def test_review_plan_works_with_missing_security_folder(self):
        with tempfile.TemporaryDirectory() as repo_tmp, tempfile.TemporaryDirectory() as runtime_tmp:
            with _runtime_context(runtime_tmp):
                code, stdout, stderr = _run_main(["review-plan", "cheddar", "--target-repo", repo_tmp])
        self.assertEqual(code, 0)
        self.assertEqual(stderr, "")
        self.assertIn("No pending review plans.", stdout)

    def test_review_plan_works_with_empty_security_folder(self):
        with tempfile.TemporaryDirectory() as repo_tmp, tempfile.TemporaryDirectory() as runtime_tmp:
            repo = Path(repo_tmp)
            (repo / ".security").mkdir()
            with _runtime_context(runtime_tmp):
                code, stdout, _stderr = _run_main(["review-plan", "cheddar", "--target-repo", str(repo)])
        self.assertEqual(code, 0)
        self.assertIn("No pending review plans.", stdout)

    def test_webhook_replay_freshness_plan_appears_for_matching_invariant(self):
        with tempfile.TemporaryDirectory() as repo_tmp, tempfile.TemporaryDirectory() as runtime_tmp:
            repo = _make_security_repo(repo_tmp)
            with _runtime_context(runtime_tmp):
                code, stdout, _stderr = _run_main(["review-plan", "cheddar", "--target-repo", str(repo)])
        self.assertEqual(code, 0)
        self.assertIn("Webhook replay/freshness target coverage", stdout)
        self.assertIn("Status: pending", stdout)

    def test_review_plan_does_not_write_security_map(self):
        with tempfile.TemporaryDirectory() as repo_tmp, tempfile.TemporaryDirectory() as runtime_tmp:
            repo = _make_security_repo(repo_tmp)
            before = _snapshot(repo / ".security")
            with _runtime_context(runtime_tmp):
                code, _stdout, _stderr = _run_main(["review-plan", "cheddar", "--target-repo", str(repo)])
            after = _snapshot(repo / ".security")
        self.assertEqual(code, 0)
        self.assertEqual(before, after)

    def test_review_plan_does_not_create_runtime_artifacts(self):
        with tempfile.TemporaryDirectory() as repo_tmp, tempfile.TemporaryDirectory() as runtime_tmp:
            repo = _make_security_repo(repo_tmp)
            runtime_root = Path(runtime_tmp)
            before = sorted(path.relative_to(runtime_root) for path in runtime_root.rglob("*"))
            with _runtime_context(runtime_tmp):
                code, _stdout, _stderr = _run_main(["review-plan", "cheddar", "--target-repo", str(repo)])
            after = sorted(path.relative_to(runtime_root) for path in runtime_root.rglob("*"))
        self.assertEqual(code, 0)
        self.assertEqual(before, after)

    def test_json_output_is_valid_and_stable(self):
        with tempfile.TemporaryDirectory() as repo_tmp, tempfile.TemporaryDirectory() as runtime_tmp:
            repo = _make_security_repo(repo_tmp)
            with _runtime_context(runtime_tmp):
                code, stdout, _stderr = _run_main(["review-plan", "cheddar", "--target-repo", str(repo), "--format", "json"])
        self.assertEqual(code, 0)
        parsed = json.loads(stdout)
        self.assertEqual(parsed["project"], "cheddar")
        self.assertIsInstance(parsed["review_plans"], list)
        plan = parsed["review_plans"][0]
        self.assertEqual(plan["id"], "webhook-replay-freshness")
        self.assertEqual(plan["status"], "pending")
        self.assertIn("linked_suggestion_id", plan)
        self.assertIn("linked_security_docs", plan)
        self.assertIn("read_only_prerequisites", plan)
        self.assertIn("safe_next_implementation_slice", plan)
        self.assertIn("not_allowed_yet", plan)
        self.assertFalse(plan["requires_live_probe"])
        self.assertFalse(plan["production_allowed"])

    def test_text_output_does_not_imply_vulnerability(self):
        with tempfile.TemporaryDirectory() as repo_tmp, tempfile.TemporaryDirectory() as runtime_tmp:
            repo = _make_security_repo(repo_tmp)
            with _runtime_context(runtime_tmp):
                _code, stdout, _stderr = _run_main(["review-plan", "cheddar", "--target-repo", str(repo)])
        lowered = stdout.lower()
        self.assertNotIn("vulnerable", lowered)
        self.assertNotIn("finding confirmed", lowered)

    def test_text_output_says_review_checklist_not_probe_result(self):
        with tempfile.TemporaryDirectory() as repo_tmp, tempfile.TemporaryDirectory() as runtime_tmp:
            repo = _make_security_repo(repo_tmp)
            with _runtime_context(runtime_tmp):
                _code, stdout, _stderr = _run_main(["review-plan", "cheddar", "--target-repo", str(repo)])
        self.assertIn("This is a review checklist, not a probe result.", stdout)

    def test_output_includes_not_allowed_yet_safety_items(self):
        with tempfile.TemporaryDirectory() as repo_tmp, tempfile.TemporaryDirectory() as runtime_tmp:
            repo = _make_security_repo(repo_tmp)
            with _runtime_context(runtime_tmp):
                _code, stdout, _stderr = _run_main(["review-plan", "cheddar", "--target-repo", str(repo)])
        self.assertIn("Not allowed yet:", stdout)
        self.assertIn("Do not replay real production webhook payloads.", stdout)
        self.assertIn("Do not test production.", stdout)


def _make_security_repo(root_tmp: str) -> Path:
    repo = Path(root_tmp)
    security = repo / ".security"
    (security / "invariants").mkdir(parents=True)
    (security / "webhooks").mkdir()
    (security / "rules-of-engagement.md").write_text("# Rules\n", encoding="utf-8")
    (security / "methodology.md").write_text("Webhook replay and freshness review guidance.\n", encoding="utf-8")
    (security / "invariants" / "webhook-trust.md").write_text("Webhook stale replay freshness expectations.\n", encoding="utf-8")
    (security / "webhooks" / "provider.md").write_text("Webhook timestamp and duplicate delivery review notes.\n", encoding="utf-8")
    return repo


def _snapshot(root: Path) -> dict[str, str]:
    return {str(path.relative_to(root)): path.read_text(encoding="utf-8") for path in sorted(root.rglob("*.md"))}


@contextmanager
def _runtime_context(runtime_tmp: str):
    from pentest_harness.core import artifacts

    with patch.object(artifacts, "RUNTIME_ROOT", Path(runtime_tmp)):
        yield


def _run_main(argv: list[str]) -> tuple[int, str, str]:
    stdout = StringIO()
    stderr = StringIO()
    with redirect_stdout(stdout), redirect_stderr(stderr):
        code = main(argv)
    return code, stdout.getvalue(), stderr.getvalue()


if __name__ == "__main__":
    unittest.main()
