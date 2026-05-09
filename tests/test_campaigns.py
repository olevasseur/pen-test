import json
import tempfile
import unittest
from contextlib import contextmanager, redirect_stderr, redirect_stdout
from io import StringIO
from pathlib import Path
from unittest.mock import patch

from pentest_harness.cli import main


class CampaignTests(unittest.TestCase):
    def test_campaign_create_command_exists(self):
        with tempfile.TemporaryDirectory() as runtime_tmp, tempfile.TemporaryDirectory() as target_tmp:
            with _runtime_context(runtime_tmp):
                code, stdout, stderr = _run_main(_campaign_args(target_tmp))
        self.assertEqual(code, 0)
        self.assertEqual(stderr, "")
        self.assertIn("Campaign created:", stdout)

    def test_campaign_create_writes_under_runtime_root(self):
        with tempfile.TemporaryDirectory() as runtime_tmp, tempfile.TemporaryDirectory() as target_tmp:
            with _runtime_context(runtime_tmp):
                code, stdout, _stderr = _run_main(_campaign_args(target_tmp))
            campaign_path = _path_from_stdout(stdout)
            self.assertEqual(code, 0)
            self.assertTrue(campaign_path.is_dir())
            self.assertTrue(str(campaign_path).startswith(str(Path(runtime_tmp) / "cheddar" / "campaigns")))

    def test_campaign_json_has_stable_fields(self):
        with tempfile.TemporaryDirectory() as runtime_tmp, tempfile.TemporaryDirectory() as target_tmp:
            with _runtime_context(runtime_tmp):
                _code, stdout, _stderr = _run_main(_campaign_args(target_tmp))
            campaign_path = _path_from_stdout(stdout)
            payload = json.loads((campaign_path / "campaign.json").read_text(encoding="utf-8"))
        self.assertEqual(payload["project"], "cheddar")
        self.assertEqual(payload["target"], "staging")
        self.assertEqual(payload["focus"], "webhook-replay-freshness")
        self.assertEqual(payload["status"], "created")
        self.assertIn("campaign_id", payload)
        self.assertIn("created_at", payload)
        self.assertIn("target_repo", payload)
        self.assertEqual([task["file"] for task in payload["tasks"]], _expected_task_files())

    def test_expected_child_agent_task_files_are_created(self):
        with tempfile.TemporaryDirectory() as runtime_tmp, tempfile.TemporaryDirectory() as target_tmp:
            with _runtime_context(runtime_tmp):
                _code, stdout, _stderr = _run_main(_campaign_args(target_tmp))
            campaign_path = _path_from_stdout(stdout)
            for filename in ["campaign.json", *_expected_task_files()]:
                self.assertTrue((campaign_path / filename).is_file(), filename)

    def test_generated_tasks_are_attack_oriented(self):
        with tempfile.TemporaryDirectory() as runtime_tmp, tempfile.TemporaryDirectory() as target_tmp:
            with _runtime_context(runtime_tmp):
                _code, stdout, _stderr = _run_main(_campaign_args(target_tmp))
            campaign_path = _path_from_stdout(stdout)
            text = "\n".join((campaign_path / filename).read_text(encoding="utf-8") for filename in _expected_task_files())
        lowered = text.lower()
        self.assertIn("exploit hypotheses", lowered)
        self.assertIn("prove exploitability", lowered)
        self.assertIn("attack attempts", lowered)
        self.assertIn("stale timestamp accepted", lowered)
        self.assertIn("duplicate delivery id accepted", lowered)

    def test_campaign_create_does_not_modify_target_repo(self):
        with tempfile.TemporaryDirectory() as runtime_tmp, tempfile.TemporaryDirectory() as target_tmp:
            target = Path(target_tmp)
            (target / ".security").mkdir()
            (target / ".security" / "README.md").write_text("before\n", encoding="utf-8")
            before = _snapshot(target)
            with _runtime_context(runtime_tmp):
                code, _stdout, _stderr = _run_main(_campaign_args(target_tmp))
            after = _snapshot(target)
        self.assertEqual(code, 0)
        self.assertEqual(before, after)

    def test_campaign_create_does_not_create_files_in_repo(self):
        repo = Path(__file__).parents[1]
        with tempfile.TemporaryDirectory() as runtime_tmp, tempfile.TemporaryDirectory() as target_tmp:
            before = _repo_runtime_snapshot(repo)
            with _runtime_context(runtime_tmp):
                code, _stdout, _stderr = _run_main(_campaign_args(target_tmp))
            after = _repo_runtime_snapshot(repo)
        self.assertEqual(code, 0)
        self.assertEqual(before, after)

    def test_unknown_project_fails_clearly(self):
        with tempfile.TemporaryDirectory() as runtime_tmp, tempfile.TemporaryDirectory() as target_tmp:
            with _runtime_context(runtime_tmp):
                code, _stdout, stderr = _run_main(
                    [
                        "campaign",
                        "create",
                        "unknown",
                        "--target",
                        "staging",
                        "--target-repo",
                        target_tmp,
                        "--focus",
                        "webhook-replay-freshness",
                    ]
                )
        self.assertEqual(code, 2)
        self.assertIn("Unknown project unknown", stderr)

    def test_unknown_focus_fails_clearly(self):
        with tempfile.TemporaryDirectory() as runtime_tmp, tempfile.TemporaryDirectory() as target_tmp:
            with _runtime_context(runtime_tmp):
                code, _stdout, stderr = _run_main(
                    [
                        "campaign",
                        "create",
                        "cheddar",
                        "--target",
                        "staging",
                        "--target-repo",
                        target_tmp,
                        "--focus",
                        "unknown-focus",
                    ]
                )
        self.assertEqual(code, 2)
        self.assertIn("Unknown campaign focus unknown-focus", stderr)


def _campaign_args(target_repo: str) -> list[str]:
    return [
        "campaign",
        "create",
        "cheddar",
        "--target",
        "staging",
        "--target-repo",
        target_repo,
        "--focus",
        "webhook-replay-freshness",
    ]


def _expected_task_files() -> list[str]:
    return ["recon.md", "exploit-hypotheses.md", "exploit-design.md", "module-implementation.md", "evidence-review.md"]


def _path_from_stdout(stdout: str) -> Path:
    for line in stdout.splitlines():
        if line.startswith("path: "):
            return Path(line.removeprefix("path: "))
    raise AssertionError(f"No path line in output: {stdout}")


def _snapshot(root: Path) -> dict[str, str]:
    return {str(path.relative_to(root)): path.read_text(encoding="utf-8") for path in sorted(root.rglob("*")) if path.is_file()}


def _repo_runtime_snapshot(repo: Path) -> list[str]:
    names: list[str] = []
    for path in repo.rglob("*"):
        if ".git" in path.parts:
            continue
        if path.is_file() and path.name in {"ledger.jsonl", "scan-state.json", "heartbeat.json", ".env"}:
            names.append(str(path.relative_to(repo)))
        if path.is_dir() and path.name in {"campaigns", "__pycache__"}:
            names.append(str(path.relative_to(repo)))
    return sorted(names)


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
